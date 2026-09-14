//! Transactional orchestration for `meilisearch.upgrade`.
//!
//! Docker, HTTP and filesystem mechanics live behind `Driver`; this module
//! owns the safety ordering and is testable with deterministic failure
//! injection. In particular, no import begins until a non-empty exported dump
//! exists, and every failure after source shutdown attempts rollback before the
//! transaction is recorded as failed.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    meilisearch_upgrade::{OPERATION, TARGET_VERSION, UpgradeRequest, UpgradeResult},
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
pub struct Baseline {
    pub source_version: String,
    /// Driver-owned, secret-free comparison token for index counts/settings
    /// and caller-declared representative search results.
    pub validation_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedDump {
    pub backup_id: String,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedTarget {
    pub volume: String,
}

pub trait Driver {
    type Error: std::fmt::Debug;

    fn capture_baseline(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<Baseline, Self::Error>;
    fn create_and_export_dump(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Self::Error>;
    fn stop_source(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error>;
    fn import_target(
        &mut self,
        request: &UpgradeRequest,
        dump: &ExportedDump,
        cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Self::Error>;
    fn validate_target(
        &mut self,
        request: &UpgradeRequest,
        baseline: &Baseline,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error>;
    fn cutover(
        &mut self,
        request: &UpgradeRequest,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error>;
    fn rollback_source(&mut self, request: &UpgradeRequest) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    SourceVersionMismatch,
    EmptyDump,
    PhaseFailed {
        phase: &'static str,
        rollback_attempted: bool,
        rollback_succeeded: bool,
    },
    State(state::StateError),
    PostCommit {
        result: UpgradeResult,
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
                "another Meilisearch upgrade for this stack is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original Meilisearch upgrade is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "Meilisearch upgrade was cancelled".into(),
            ),
            Self::SourceVersionMismatch => (
                ErrorCode::Conflict,
                "the live Meilisearch version does not match the guarded source version".into(),
            ),
            Self::EmptyDump => (
                ErrorCode::SubprocessFailed,
                "Meilisearch did not produce a non-empty exported dump".into(),
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
                    "Meilisearch upgrade failed during {phase}; rollback {}",
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
                "internal Meilisearch upgrade error".into(),
            ),
        }
    }
}

pub fn execute<D: Driver>(
    context: &mut Context<'_, D>,
    request: &UpgradeRequest,
    cancellation: &CancellationToken,
) -> Result<UpgradeResult, Error> {
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

    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    let baseline = context
        .driver
        .capture_baseline(request, cancellation)
        .map_err(|_| phase("baseline", false, false))
        .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;
    if baseline.source_version != request.expected_source_version {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::SourceVersionMismatch,
        ));
    }
    let dump = context
        .driver
        .create_and_export_dump(request, cancellation)
        .map_err(|_| phase("dump export", false, false))
        .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;
    if dump.byte_len == 0 {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::EmptyDump,
        ));
    }
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    if context.driver.stop_source(request, cancellation).is_err() {
        let rollback = context.driver.rollback_source(request).is_ok();
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            phase("source shutdown", true, rollback),
        ));
    }

    let target = match context.driver.import_target(request, &dump, cancellation) {
        Ok(target) => target,
        Err(_) => {
            let rollback = context.driver.rollback_source(request).is_ok();
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                phase("target import", true, rollback),
            ));
        }
    };
    if context
        .driver
        .validate_target(request, &baseline, &target, cancellation)
        .is_err()
    {
        let rollback = context.driver.rollback_source(request).is_ok();
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            phase("target validation", true, rollback),
        ));
    }
    if context
        .driver
        .cutover(request, &target, cancellation)
        .is_err()
        || pre_commit.check().is_err()
    {
        let rollback = context.driver.rollback_source(request).is_ok();
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            phase("cutover", true, rollback),
        ));
    }

    let _committed = pre_commit.commit();
    drop(lock);
    let result = UpgradeResult {
        source_version: baseline.source_version,
        target_version: TARGET_VERSION.into(),
        backup_id: dump.backup_id,
        target_volume: target.volume,
        completed_at_unix_secs: now(),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("upgrade result serializes"))
        .expect("transaction is in progress");
    if state::save(&scope, &state_path, &state).is_err() {
        return Err(Error::PostCommit { result });
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<UpgradeResult, Error> {
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

fn open_state(root: &ManagedRoot, stack: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("meilisearch/{stack}"))
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
    use crate::meilisearch_upgrade::TARGET_IMAGE;

    #[derive(Default)]
    struct Fake {
        fail: Option<&'static str>,
        empty_dump: bool,
        rollback_fails: bool,
        calls: Vec<&'static str>,
    }

    impl Driver for Fake {
        type Error = ();
        fn capture_baseline(
            &mut self,
            _: &UpgradeRequest,
            _: &CancellationToken,
        ) -> Result<Baseline, ()> {
            self.calls.push("baseline");
            if self.fail == Some("baseline") {
                return Err(());
            }
            Ok(Baseline {
                source_version: "1.53.1".into(),
                validation_token: "counts+searches".into(),
            })
        }
        fn create_and_export_dump(
            &mut self,
            _: &UpgradeRequest,
            _: &CancellationToken,
        ) -> Result<ExportedDump, ()> {
            self.calls.push("dump");
            if self.fail == Some("dump") {
                return Err(());
            }
            Ok(ExportedDump {
                backup_id: "dump-1".into(),
                byte_len: if self.empty_dump { 0 } else { 42 },
            })
        }
        fn stop_source(&mut self, _: &UpgradeRequest, _: &CancellationToken) -> Result<(), ()> {
            self.calls.push("stop");
            if self.fail == Some("stop") {
                Err(())
            } else {
                Ok(())
            }
        }
        fn import_target(
            &mut self,
            _: &UpgradeRequest,
            _: &ExportedDump,
            _: &CancellationToken,
        ) -> Result<ImportedTarget, ()> {
            self.calls.push("import");
            if self.fail == Some("import") {
                Err(())
            } else {
                Ok(ImportedTarget {
                    volume: "wcp_meilisearch_1_53_2".into(),
                })
            }
        }
        fn validate_target(
            &mut self,
            _: &UpgradeRequest,
            _: &Baseline,
            _: &ImportedTarget,
            _: &CancellationToken,
        ) -> Result<(), ()> {
            self.calls.push("validate");
            if self.fail == Some("validate") {
                Err(())
            } else {
                Ok(())
            }
        }
        fn cutover(
            &mut self,
            _: &UpgradeRequest,
            _: &ImportedTarget,
            _: &CancellationToken,
        ) -> Result<(), ()> {
            self.calls.push("cutover");
            if self.fail == Some("cutover") {
                Err(())
            } else {
                Ok(())
            }
        }
        fn rollback_source(&mut self, _: &UpgradeRequest) -> Result<(), ()> {
            self.calls.push("rollback");
            if self.rollback_fails { Err(()) } else { Ok(()) }
        }
    }

    fn request() -> UpgradeRequest {
        UpgradeRequest::parse(
            &format!(r#"{{"stackName":"wp-stack","service":"meili-1","expectedSourceVersion":"1.53.1","targetImage":"{TARGET_IMAGE}","masterKey":"secret","searchProbes":[]}}"#),
            "123e4567-e89b-12d3-a456-426614174000",
            Some("upgrade-1"),
        ).unwrap()
    }

    fn root() -> (tempfile::TempDir, ManagedRoot) {
        let dir = tempfile::tempdir().unwrap();
        let trusted = crate::site::TrustedRoot::parse(dir.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        (dir, root)
    }

    #[test]
    fn successful_order_commits_only_after_validation_and_cutover() {
        let (_dir, state) = root();
        let mut driver = Fake::default();
        let result = execute(
            &mut Context {
                engine_state: &state,
                driver: &mut driver,
            },
            &request(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.target_version, TARGET_VERSION);
        assert_eq!(
            driver.calls,
            ["baseline", "dump", "stop", "import", "validate", "cutover"]
        );
        let transaction =
            std::fs::read_to_string(_dir.path().join(
                "meilisearch/wp-stack/transactions/123e4567-e89b-12d3-a456-426614174000.json",
            ))
            .unwrap();
        let audit =
            std::fs::read_to_string(_dir.path().join("meilisearch/wp-stack/audit/events.jsonl"))
                .unwrap();
        assert!(!transaction.contains("secret"));
        assert!(!audit.contains("secret"));
    }

    #[test]
    fn failed_import_or_validation_restores_the_source() {
        for failing in ["stop", "import", "validate", "cutover"] {
            let (_dir, state) = root();
            let mut driver = Fake {
                fail: Some(failing),
                empty_dump: false,
                rollback_fails: false,
                calls: vec![],
            };
            let error = execute(
                &mut Context {
                    engine_state: &state,
                    driver: &mut driver,
                },
                &request(),
                &CancellationToken::default(),
            )
            .unwrap_err();
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
    fn no_source_shutdown_occurs_without_a_successful_nonempty_dump() {
        for (fail, empty) in [(Some("dump"), false), (None, true)] {
            let (_dir, state) = root();
            let mut driver = Fake {
                fail,
                empty_dump: empty,
                rollback_fails: false,
                calls: vec![],
            };
            execute(
                &mut Context {
                    engine_state: &state,
                    driver: &mut driver,
                },
                &request(),
                &CancellationToken::default(),
            )
            .unwrap_err();
            assert_eq!(driver.calls, ["baseline", "dump"]);
        }
    }

    #[test]
    fn rollback_failure_is_escalated_to_internal() {
        let (_dir, state) = root();
        let mut driver = Fake {
            fail: Some("validate"),
            empty_dump: false,
            rollback_fails: true,
            calls: vec![],
        };
        let error = execute(
            &mut Context {
                engine_state: &state,
                driver: &mut driver,
            },
            &request(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::Internal);
        assert!(matches!(
            error,
            Error::PhaseFailed {
                rollback_attempted: true,
                rollback_succeeded: false,
                ..
            }
        ));
    }
}
