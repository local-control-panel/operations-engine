//! Transactional orchestration for `db.migrateMariadbLine`.
//!
//! Docker and SQL mechanics live behind `Driver`; this module owns the safety
//! ordering and is testable with deterministic failure injection. The source
//! is frozen read-only before its dump, nothing is imported into a target that
//! already holds tables, the target must reproduce the source's tables (with
//! row counts), accounts and routines before anything is switched, and every
//! failure after the freeze attempts a rollback before the transaction is
//! recorded as failed. No volume is ever removed.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mariadb_migrate::{MigrateRequest, MigrateResult, OPERATION},
    mutation::preflight,
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};

pub struct Context<'a, D> {
    pub engine_state: &'a ManagedRoot,
    pub driver: &'a mut D,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceInfo {
    pub version: String,
    pub volume: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Baseline {
    /// Driver-owned, secret-free description of what the target must contain.
    pub validation_token: String,
    pub databases: u64,
    pub tables: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedDump {
    pub backup_id: String,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedTarget {
    pub volume: String,
    pub version: String,
}

pub trait Driver {
    type Error: std::fmt::Debug;

    /// Checks the stack can switch by alias, the source runs, and makes the
    /// source read-only so nothing is written after the dump starts.
    fn freeze_source(
        &mut self,
        request: &MigrateRequest,
        cancellation: &CancellationToken,
    ) -> Result<SourceInfo, Self::Error>;
    fn export_dump(
        &mut self,
        request: &MigrateRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Self::Error>;
    /// Taken after the dump, from the frozen source.
    fn capture_baseline(
        &mut self,
        request: &MigrateRequest,
        cancellation: &CancellationToken,
    ) -> Result<Baseline, Self::Error>;
    /// Starts the target, refuses one that already holds tables, loads the dump.
    fn import_target(
        &mut self,
        request: &MigrateRequest,
        dump: &ExportedDump,
        cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Self::Error>;
    fn validate_target(
        &mut self,
        request: &MigrateRequest,
        baseline: &Baseline,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error>;
    /// Stops the source and gives the target the source's service name.
    fn cutover(
        &mut self,
        request: &MigrateRequest,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error>;
    /// Makes the source writable and running again, takes the alias back and
    /// stops the target. Idempotent; removes nothing.
    fn rollback_source(&mut self, request: &MigrateRequest) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    EmptyDump,
    PhaseFailed {
        phase: &'static str,
        rollback_attempted: bool,
        rollback_succeeded: bool,
    },
    State(state::StateError),
    PostCommit {
        result: Box<MigrateResult>,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another MariaDB migration for this stack is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original MariaDB migration is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "MariaDB migration was cancelled".into(),
            ),
            Self::EmptyDump => (
                ErrorCode::SubprocessFailed,
                "MariaDB did not produce a non-empty exported dump".into(),
            ),
            Self::PhaseFailed {
                phase,
                rollback_attempted,
                rollback_succeeded,
            } => (
                if *rollback_attempted && !*rollback_succeeded {
                    ErrorCode::Internal
                } else {
                    ErrorCode::SubprocessFailed
                },
                format!(
                    "MariaDB migration failed during {phase}; rollback {}",
                    if !rollback_attempted {
                        "was not required"
                    } else if *rollback_succeeded {
                        "restored the source service"
                    } else {
                        "also failed"
                    }
                ),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::State(_) | Self::PostCommit { .. } | Self::Preflight(_) => (
                ErrorCode::Internal,
                "internal MariaDB migration error".into(),
            ),
        }
    }
}

pub fn execute<D: Driver>(
    context: &mut Context<'_, D>,
    request: &MigrateRequest,
    cancellation: &CancellationToken,
) -> Result<MigrateResult, Error> {
    let scope = open_state(context.engine_state, request.stack_name.as_str()).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path(request.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancellation.clone());
    let failed = |state: &crate::transaction::state::TransactionState, error: Error| {
        fail(&scope, &state_path, &audit_path, state.clone(), error)
    };

    if pre_commit.check().is_err() {
        return Err(failed(&state, Error::Cancelled));
    }
    // From the first freeze attempt on, every failure rolls back.
    let rolled_back = |driver: &mut D, phase_name: &'static str| {
        let rollback = driver.rollback_source(request).is_ok();
        phase(phase_name, true, rollback)
    };
    let source = match context.driver.freeze_source(request, cancellation) {
        Ok(source) => source,
        Err(_) => {
            let error = rolled_back(context.driver, "source freeze");
            return Err(failed(&state, error));
        }
    };
    let dump = match context.driver.export_dump(request, cancellation) {
        Ok(dump) => dump,
        Err(_) => {
            let error = rolled_back(context.driver, "dump export");
            return Err(failed(&state, error));
        }
    };
    if dump.byte_len == 0 {
        context.driver.rollback_source(request).ok();
        return Err(failed(&state, Error::EmptyDump));
    }
    let baseline = match context.driver.capture_baseline(request, cancellation) {
        Ok(baseline) => baseline,
        Err(_) => {
            let error = rolled_back(context.driver, "baseline");
            return Err(failed(&state, error));
        }
    };
    if pre_commit.check().is_err() {
        context.driver.rollback_source(request).ok();
        return Err(failed(&state, Error::Cancelled));
    }
    let target = match context.driver.import_target(request, &dump, cancellation) {
        Ok(target) => target,
        Err(_) => {
            let error = rolled_back(context.driver, "target import");
            return Err(failed(&state, error));
        }
    };
    if context
        .driver
        .validate_target(request, &baseline, &target, cancellation)
        .is_err()
    {
        let error = rolled_back(context.driver, "target validation");
        return Err(failed(&state, error));
    }
    if context
        .driver
        .cutover(request, &target, cancellation)
        .is_err()
        || pre_commit.check().is_err()
    {
        let error = rolled_back(context.driver, "cutover");
        return Err(failed(&state, error));
    }

    let result = MigrateResult {
        source_service: request.source_service.into(),
        target_service: request.target_service.into(),
        source_version: source.version,
        target_version: target.version,
        backup_id: dump.backup_id,
        retained_source_volume: source.volume,
        target_volume: target.volume,
        databases: baseline.databases,
        tables: baseline.tables,
        completed_at_unix_secs: now(),
    };
    let _committed = pre_commit.commit();
    drop(lock);
    state
        .mark_committed(serde_json::to_value(&result).expect("migration result serializes"))
        .expect("transaction is in progress");
    if state::save(&scope, &state_path, &state).is_err() {
        return Err(Error::PostCommit {
            result: Box::new(result),
        });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    Ok(result)
}

fn phase(name: &'static str, attempted: bool, succeeded: bool) -> Error {
    Error::PhaseFailed {
        phase: name,
        rollback_attempted: attempted,
        rollback_succeeded: succeeded,
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<MigrateResult, Error> {
    let loaded = state::load(scope, &state_path(id)).map_err(Error::State)?;
    if loaded.operation != OPERATION {
        return Err(Error::Replayed {
            code: ErrorCode::Conflict,
            message: "idempotency key belongs to another operation".into(),
        });
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => serde_json::from_value(
            loaded
                .outcome
                .expect("committed outcome")
                .result
                .expect("result"),
        )
        .map_err(|error| Error::Io(std::io::Error::other(error))),
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.expect("failed outcome");
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

pub(crate) fn open_state(root: &ManagedRoot, stack: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("mariadb-migrate/{stack}"))
        .expect("validated stack name produces a safe state path");
    root.create_dir_all(&path)?;
    let scope = root.open_managed_dir(&path)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(child).expect("static path"))?;
    }
    Ok(scope)
}

fn state_path(id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).expect("UUID path")
}

fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("static path")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        fail: Option<&'static str>,
        empty_dump: bool,
        rollback_fails: bool,
        calls: Vec<&'static str>,
    }

    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<(), ()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    impl Driver for Fake {
        type Error = ();
        fn freeze_source(
            &mut self,
            _: &MigrateRequest,
            _: &CancellationToken,
        ) -> Result<SourceInfo, ()> {
            self.step("freeze")?;
            Ok(SourceInfo {
                version: "11.4.13".into(),
                volume: "wcp_mariadb_data".into(),
            })
        }
        fn export_dump(
            &mut self,
            _: &MigrateRequest,
            _: &CancellationToken,
        ) -> Result<ExportedDump, ()> {
            self.step("dump")?;
            Ok(ExportedDump {
                backup_id: "dump-1".into(),
                byte_len: if self.empty_dump { 0 } else { 42 },
            })
        }
        fn capture_baseline(
            &mut self,
            _: &MigrateRequest,
            _: &CancellationToken,
        ) -> Result<Baseline, ()> {
            self.step("baseline")?;
            Ok(Baseline {
                validation_token: "tables+accounts".into(),
                databases: 2,
                tables: 5,
            })
        }
        fn import_target(
            &mut self,
            _: &MigrateRequest,
            _: &ExportedDump,
            _: &CancellationToken,
        ) -> Result<ImportedTarget, ()> {
            self.step("import")?;
            Ok(ImportedTarget {
                volume: "wcp_mariadb_13_data".into(),
                version: "13.0.2".into(),
            })
        }
        fn validate_target(
            &mut self,
            _: &MigrateRequest,
            _: &Baseline,
            _: &ImportedTarget,
            _: &CancellationToken,
        ) -> Result<(), ()> {
            self.step("validate")
        }
        fn cutover(
            &mut self,
            _: &MigrateRequest,
            _: &ImportedTarget,
            _: &CancellationToken,
        ) -> Result<(), ()> {
            self.step("cutover")
        }
        fn rollback_source(&mut self, _: &MigrateRequest) -> Result<(), ()> {
            self.calls.push("rollback");
            if self.rollback_fails { Err(()) } else { Ok(()) }
        }
    }

    fn request() -> MigrateRequest {
        MigrateRequest::parse(
            r#"{"stackName":"wp-stack","sourceService":"mariadb-11","targetService":"mariadb-13","rootPassword":"secret"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("migrate-1"),
        )
        .unwrap()
    }

    fn root() -> (tempfile::TempDir, ManagedRoot) {
        let dir = tempfile::tempdir().unwrap();
        let trusted = crate::site::TrustedRoot::parse(dir.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        (dir, root)
    }

    fn run(driver: &mut Fake, state: &ManagedRoot) -> Result<MigrateResult, Error> {
        execute(
            &mut Context {
                engine_state: state,
                driver,
            },
            &request(),
            &CancellationToken::default(),
        )
    }

    #[test]
    fn the_source_is_frozen_before_the_dump_and_nothing_commits_before_cutover() {
        let (dir, state) = root();
        let mut driver = Fake::default();
        let result = run(&mut driver, &state).unwrap();
        assert_eq!(
            driver.calls,
            [
                "freeze", "dump", "baseline", "import", "validate", "cutover"
            ]
        );
        assert_eq!(result.retained_source_volume, "wcp_mariadb_data");
        assert_eq!(result.target_volume, "wcp_mariadb_13_data");
        assert_eq!((result.databases, result.tables), (2, 5));
        let transaction = std::fs::read_to_string(dir.path().join(
            "mariadb-migrate/wp-stack/transactions/123e4567-e89b-12d3-a456-426614174000.json",
        ))
        .unwrap();
        let audit = std::fs::read_to_string(
            dir.path()
                .join("mariadb-migrate/wp-stack/audit/events.jsonl"),
        )
        .unwrap();
        assert!(!transaction.contains("secret"));
        assert!(!audit.contains("secret"));
    }

    #[test]
    fn every_failure_after_the_freeze_restores_the_source() {
        for failing in [
            "freeze", "dump", "baseline", "import", "validate", "cutover",
        ] {
            let (_dir, state) = root();
            let mut driver = Fake {
                fail: Some(failing),
                ..Fake::default()
            };
            let error = run(&mut driver, &state).unwrap_err();
            assert!(
                driver.calls.ends_with(&["rollback"]),
                "{failing}: {:?}",
                driver.calls
            );
            assert!(matches!(
                error,
                Error::PhaseFailed {
                    rollback_attempted: true,
                    rollback_succeeded: true,
                    ..
                }
            ));
        }
    }

    #[test]
    fn an_empty_dump_never_reaches_the_target() {
        let (_dir, state) = root();
        let mut driver = Fake {
            empty_dump: true,
            ..Fake::default()
        };
        assert!(matches!(
            run(&mut driver, &state).unwrap_err(),
            Error::EmptyDump
        ));
        assert_eq!(driver.calls, ["freeze", "dump", "rollback"]);
    }

    #[test]
    fn a_failed_rollback_is_escalated_to_internal() {
        let (_dir, state) = root();
        let mut driver = Fake {
            fail: Some("validate"),
            rollback_fails: true,
            ..Fake::default()
        };
        let error = run(&mut driver, &state).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::Internal);
        assert!(error.protocol().1.contains("also failed"));
    }

    #[test]
    fn a_repeated_idempotency_key_replays_the_committed_result() {
        let (_dir, state) = root();
        let mut driver = Fake::default();
        let first = run(&mut driver, &state).unwrap();
        let mut again = Fake::default();
        let second = run(&mut again, &state).unwrap();
        assert!(again.calls.is_empty(), "replay must not touch Docker");
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
    }
}
