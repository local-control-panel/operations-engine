//! Server-owned PHP site creation. The journal precedes every boundary;
//! incomplete attempts are explicitly compensated, never silently replayed.
use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{Domain, RuntimeId, SiteRelativePath},
    site_migrate_runtime::{Backend as RuntimeBackend, Identity, StepError},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const OPERATION: &str = "site.create";
pub const RECOVER_OPERATION: &str = "site.recoverCreate";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub domain: String,
    pub runtime_id: String,
    #[serde(default)]
    pub relative_root: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub worker_mode: bool,
    #[serde(default = "default_workers")]
    pub worker_count: i64,
}
fn default_workers() -> i64 {
    4
}
impl Plan {
    pub fn validate(&self) -> Result<(Domain, RuntimeId), StepError> {
        let domain = Domain::parse(&self.domain).map_err(|_| invalid())?;
        let runtime = RuntimeId::parse(&self.runtime_id).map_err(|_| invalid())?;
        if domain.as_str() == "sites" {
            return Err(invalid());
        }
        // Reuse the underlying operations' complete path/profile/identity validation.
        crate::site_root::PrepareRequest::parse(
            &self.domain,
            self.relative_root.as_deref(),
            10000,
            10000,
            None,
            &fresh().to_string(),
            None,
        )
        .map_err(|_| invalid())?;
        crate::stack_service::EnsureRequest::parse(
            &self.runtime_id,
            self.profile.as_deref(),
            &fresh().to_string(),
            None,
        )
        .map_err(|_| invalid())?;
        if !(1..=64).contains(&self.worker_count) {
            return Err(invalid());
        }
        Ok((domain, runtime))
    }
}
fn invalid() -> StepError {
    StepError::new(ErrorCode::InvalidInput, "invalid site creation plan")
}
fn internal() -> StepError {
    StepError::new(
        ErrorCode::Internal,
        "site creation journal is unavailable; inspect operation status before retrying",
    )
}
fn conflict() -> StepError {
    StepError::new(
        ErrorCode::Conflict,
        "site creation is active or requires explicit recovery",
    )
}
fn fresh() -> RequestId {
    RequestId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
}
fn rel(s: &str) -> SiteRelativePath {
    SiteRelativePath::parse(s).unwrap()
}
fn transaction(id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{id}.json"))
}
fn journal_path(id: RequestId) -> SiteRelativePath {
    rel(&format!("pending/{id}.json"))
}
fn scope(state: &ManagedRoot, domain: &Domain) -> Result<ManagedRoot, StepError> {
    let path = rel(&format!("site-create/{domain}"));
    state.create_dir_all(&path).map_err(|_| internal())?;
    let scope = state.open_managed_dir(&path).map_err(|_| internal())?;
    for name in ["transactions", "locks", "audit", "pending", "plans"] {
        scope.create_dir_all(&rel(name)).map_err(|_| internal())?;
    }
    Ok(scope)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    request_id: RequestId,
    plan: Plan,
    root: String,
    identity: bool,
    root_attempted: bool,
    service: bool,
    exec: bool,
    route: bool,
    completed: Option<CreateResult>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    pub domain: String,
    pub runtime_id: String,
    pub root: String,
    pub port: u16,
}

pub trait Backend: RuntimeBackend {
    /// Refuse existing roots, routes (including disabled/parked), identities,
    /// services and execution configs. Never adopts another attempt's data.
    fn check_available(&self, plan: &Plan) -> Result<String, StepError>;
    fn allocate_new(&self, plan: &Plan, root: &str, key: &str) -> Result<Identity, StepError>;
    fn prepare_new_root(
        &self,
        plan: &Plan,
        identity: &Identity,
        key: &str,
    ) -> Result<(), StepError>;
    fn ensure_pool(&self, plan: &Plan) -> Result<(), StepError>;
    fn create_route(&self, plan: &Plan, content: &str) -> Result<(), StepError>;
    fn remove_created_route(&self, plan: &Plan, expected: &str) -> Result<(), StepError>;
    fn remove_empty_root(&self, plan: &Plan, request_id: RequestId) -> Result<(), StepError>;
    fn remove_created_exec(&self, plan: &Plan, _id: RequestId) -> Result<(), StepError> {
        let (domain, runtime) = plan.validate()?;
        self.remove_exec_config(&runtime, &domain)
    }
    fn remove_created_service(&self, plan: &Plan, _id: RequestId) -> Result<(), StepError> {
        let (domain, runtime) = plan.validate()?;
        self.remove_service(&runtime, &domain)
    }
    fn release_created_identity(&self, plan: &Plan, request_id: RequestId)
    -> Result<(), StepError>;
}
pub fn ingress_config(plan: &Plan) -> String {
    let domain = &plan.domain;
    let runtime_id = &plan.runtime_id;
    format!(
        "{domain} {{\n    import /etc/wcp/ingress.d/bans/*.caddy\n    reverse_proxy runtime-{runtime_id}:80 {{\n        header_up X-Request-ID {{http.request.uuid}}\n        header_up X-WCP-Runtime-ID {runtime_id}\n        header_down X-Request-ID {{http.request.uuid}}\n    }}\n    log_append request_id {{http.request.uuid}}\n    log_append domain {domain}\n    log_append runtime_id {runtime_id}\n}}\n"
    )
}
fn save(scope: &ManagedRoot, journal: &Journal) -> Result<(), StepError> {
    scope
        .write_atomic(
            &journal_path(journal.request_id),
            &serde_json::to_vec(journal).map_err(|_| internal())?,
        )
        .map_err(|_| internal())
}
fn undo(backend: &impl Backend, journal: &Journal) -> Result<(), StepError> {
    journal.plan.validate()?;
    // Stop at the first failure: a route/service that still needs an identity
    // must never be followed by deleting that identity or its content root.
    if journal.route {
        backend.remove_created_route(&journal.plan, &ingress_config(&journal.plan))?;
    }
    if journal.exec {
        backend.remove_created_exec(&journal.plan, journal.request_id)?;
    }
    if journal.service {
        backend.remove_created_service(&journal.plan, journal.request_id)?;
    }
    if journal.root_attempted {
        backend.remove_empty_root(&journal.plan, journal.request_id)?;
    }
    if journal.identity {
        backend.release_created_identity(&journal.plan, journal.request_id)?;
    }
    Ok(())
}

pub fn execute(
    state: &ManagedRoot,
    backend: &impl Backend,
    plan: &Plan,
    request_id: RequestId,
    key: &IdempotencyKey,
) -> Result<CreateResult, StepError> {
    let (domain, runtime) = plan.validate()?;
    let scope = scope(state, &domain)?;
    let admitted =
        preflight::run(&scope, request_id, Some(key), OPERATION).map_err(|e| match e {
            preflight::Error::Lock(_) => conflict(),
            _ => internal(),
        })?;
    let admitted = match admitted {
        preflight::Outcome::Replay(id) => {
            let stored: Plan = serde_json::from_str(
                &scope
                    .read_to_string(&rel(&format!("plans/{id}.json")))
                    .map_err(|_| internal())?,
            )
            .map_err(|_| internal())?;
            if stored != *plan {
                return Err(StepError::new(
                    ErrorCode::Conflict,
                    "the idempotency key belongs to a different creation plan",
                ));
            }
            let record = state::load(&scope, &transaction(id)).map_err(|_| internal())?;
            return match record.status {
                TransactionStatus::InProgress => Err(conflict()),
                TransactionStatus::Failed => Err(StepError::new(
                    record
                        .outcome
                        .as_ref()
                        .and_then(|o| o.error_code)
                        .unwrap_or(ErrorCode::Internal),
                    "site creation failed; inspect the recorded outcome",
                )),
                TransactionStatus::Committed => serde_json::from_value(
                    record.outcome.and_then(|o| o.result).ok_or_else(internal)?,
                )
                .map_err(|_| internal()),
            };
        }
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted {
        lock: _lock,
        mut state,
    } = admitted;
    scope
        .write_atomic(
            &rel(&format!("plans/{request_id}.json")),
            &serde_json::to_vec(plan).map_err(|_| internal())?,
        )
        .map_err(|_| internal())?;
    // A crash after recording the terminal outcome can leave a journal.
    // Its transaction proves compensation/verification already finished;
    // remove only that metadata before considering another explicit intent.
    let pending = scope
        .open_managed_dir(&rel("pending"))
        .map_err(|_| internal())?;
    for name in pending.file_names().map_err(|_| internal())? {
        let old = name
            .strip_suffix(".json")
            .and_then(|s| RequestId::parse(s).ok())
            .ok_or_else(internal)?;
        let record = state::load(&scope, &transaction(old)).map_err(|_| internal())?;
        if record.request_id != old || record.operation != OPERATION {
            return Err(internal());
        }
        if record.status == TransactionStatus::InProgress {
            state
                .mark_failed(ErrorCode::Conflict, "an earlier creation requires recovery")
                .map_err(|_| internal())?;
            state::save(&scope, &transaction(request_id), &state).map_err(|_| internal())?;
            return Err(conflict());
        }
        scope
            .remove_file(&journal_path(old))
            .map_err(|_| internal())?;
    }
    let root = match backend.check_available(plan) {
        Ok(root) => root,
        Err(e) => {
            state
                .mark_failed(e.code, &e.message)
                .map_err(|_| internal())?;
            state::save(&scope, &transaction(request_id), &state).map_err(|_| internal())?;
            return Err(e);
        }
    };
    let mut journal = Journal {
        request_id,
        plan: plan.clone(),
        root: root.clone(),
        identity: false,
        root_attempted: false,
        service: false,
        exec: false,
        route: false,
        completed: None,
    };
    save(&scope, &journal)?;
    let run = || -> Result<CreateResult, StepError> {
        journal.identity = true;
        save(&scope, &journal)?;
        let identity = backend.allocate_new(plan, &root, &format!("{request_id}:identity"))?;
        crate::failpoint::hit("site-create-after-identity");
        journal.root_attempted = true;
        save(&scope, &journal)?;
        backend.prepare_new_root(plan, &identity, &format!("{request_id}:root"))?;
        crate::failpoint::hit("site-create-after-root");
        backend.ensure_pool(plan)?;
        journal.service = true;
        save(&scope, &journal)?;
        backend.write_service(&runtime, &domain, &identity)?;
        crate::failpoint::hit("site-create-after-service");
        journal.exec = true;
        save(&scope, &journal)?;
        backend.activate_exec_config(
            &runtime,
            &domain,
            &crate::site_migrate_runtime::pool_reverse_proxy_caddyfile(&domain, identity.port),
        )?;
        crate::failpoint::hit("site-create-after-exec");
        backend.probe(&format!("runtime-{runtime}"), &domain, &root, None)?;
        journal.route = true;
        save(&scope, &journal)?;
        backend.create_route(plan, &ingress_config(plan))?;
        crate::failpoint::hit("site-create-after-route");
        backend.probe("ingress", &domain, &root, None)?;
        let result = CreateResult {
            domain: plan.domain.clone(),
            runtime_id: plan.runtime_id.clone(),
            root: root.clone(),
            port: identity.port,
        };
        journal.completed = Some(result.clone());
        save(&scope, &journal)?;
        crate::failpoint::hit("site-create-after-verify");
        Ok(result)
    };
    let mut run = run;
    match run() {
        Ok(result) => {
            state
                .mark_committed(serde_json::to_value(&result).map_err(|_| internal())?)
                .map_err(|_| internal())?;
            state::save(&scope, &transaction(request_id), &state).map_err(|_| internal())?;
            let _ = audit::append(
                &scope,
                &rel("audit/events.jsonl"),
                &AuditRecord::result(request_id, true, None),
            );
            let _ = scope.remove_file(&journal_path(request_id));
            Ok(result)
        }
        Err(error) => {
            if undo(backend, &journal).is_err() {
                return Err(StepError::new(
                    ErrorCode::Internal,
                    "site creation failed and requires explicit recovery; retained content was not deleted",
                ));
            }
            state
                .mark_failed(error.code, &error.message)
                .map_err(|_| internal())?;
            state::save(&scope, &transaction(request_id), &state).map_err(|_| internal())?;
            let _ = audit::append(
                &scope,
                &rel("audit/events.jsonl"),
                &AuditRecord::result(request_id, false, Some(error.code)),
            );
            scope
                .remove_file(&journal_path(request_id))
                .map_err(|_| internal())?;
            Err(error)
        }
    }
}

pub fn available(scope: &ManagedRoot, record: &state::TransactionState) -> bool {
    record.operation == OPERATION
        && record.status == TransactionStatus::InProgress
        && scope
            .open_regular_read(&journal_path(record.request_id))
            .ok()
            .and_then(|file| {
                const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
                if file.metadata().ok()?.len() > MAX_JOURNAL_BYTES {
                    return None;
                }
                let mut bytes = Vec::new();
                file.take(MAX_JOURNAL_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .ok()?;
                if bytes.len() > MAX_JOURNAL_BYTES as usize {
                    return None;
                }
                serde_json::from_slice::<Journal>(&bytes).ok()
            })
            .is_some_and(|j| j.request_id == record.request_id && j.plan.validate().is_ok())
}

pub fn recover(
    state: &ManagedRoot,
    backend: &impl Backend,
    domain: &str,
    id: RequestId,
) -> Result<crate::operation_status::OperationStatus, StepError> {
    let domain = Domain::parse(domain).map_err(|_| invalid())?;
    let scope = state
        .open_managed_dir(&rel(&format!("site-create/{domain}")))
        .map_err(|_| internal())?;
    let _lock = lock::acquire(&scope, &preflight::lock_path(), id).map_err(|_| conflict())?;
    let mut record = state::load(&scope, &transaction(id)).map_err(|_| internal())?;
    if record.request_id != id || record.operation != OPERATION {
        return Err(invalid());
    }
    if record.status != TransactionStatus::InProgress && scope.exists(&journal_path(id)) {
        let journal: Journal = serde_json::from_str(
            &scope
                .read_to_string(&journal_path(id))
                .map_err(|_| internal())?,
        )
        .map_err(|_| internal())?;
        if journal.request_id != id || journal.plan.domain != domain.as_str() {
            return Err(invalid());
        }
        scope
            .remove_file(&journal_path(id))
            .map_err(|_| internal())?;
    }
    if record.status == TransactionStatus::InProgress {
        let journal: Journal = serde_json::from_str(
            &scope
                .read_to_string(&journal_path(id))
                .map_err(|_| internal())?,
        )
        .map_err(|_| internal())?;
        if journal.request_id != id || journal.plan.domain != domain.as_str() {
            return Err(invalid());
        }
        journal.plan.validate()?;
        if let Some(result) = &journal.completed {
            // Verification happened before the durable commit checkpoint. Do
            // not undo a completed create because its response was lost.
            record
                .mark_committed(serde_json::to_value(result).map_err(|_| internal())?)
                .map_err(|_| internal())?;
        } else {
            undo(backend, &journal)?;
            record
                .mark_failed(
                    ErrorCode::Cancelled,
                    "interrupted creation was compensated; no published site remains",
                )
                .map_err(|_| internal())?;
        }
        audit::append(
            &scope,
            &rel("audit/events.jsonl"),
            &AuditRecord::mutation_start(id, None, RECOVER_OPERATION),
        )
        .map_err(|_| internal())?;
        state::save(&scope, &transaction(id), &record).map_err(|_| internal())?;
        scope
            .remove_file(&journal_path(id))
            .map_err(|_| internal())?;
    }
    Ok(crate::operation_status::OperationStatus {
        transaction: record,
        active: false,
        recovery_action: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ingress::ConfigHash,
        site::TrustedRoot,
        site_migrate_runtime::{HealthCheck, Route, RouteKind},
    };
    use std::cell::RefCell;
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        fail: RefCell<Option<String>>,
        fail_cleanup: RefCell<bool>,
    }
    impl Fake {
        fn step(&self, name: &str) -> Result<(), StepError> {
            self.calls.borrow_mut().push(name.into());
            if self.fail.borrow().as_deref() == Some(name) {
                Err(StepError::new(
                    ErrorCode::SubprocessFailed,
                    "forced step failure",
                ))
            } else {
                Ok(())
            }
        }
        fn cleanup(&self, name: &str) -> Result<(), StepError> {
            self.calls.borrow_mut().push(name.into());
            if *self.fail_cleanup.borrow() {
                Err(conflict())
            } else {
                Ok(())
            }
        }
    }
    fn identity() -> Identity {
        Identity {
            os_user: "wcp-site-0000000000000001".into(),
            uid: 10000,
            gid: 10000,
            port: 9000,
            root: "/var/www/example.test/public".into(),
            worker_mode: false,
            worker_count: 4,
        }
    }
    impl RuntimeBackend for Fake {
        fn read_route(&self, _: &Domain) -> Result<Route, StepError> {
            unreachable!()
        }
        fn read_identity(&self, _: &RuntimeId, _: &Domain) -> Result<Option<Identity>, StepError> {
            Ok(None)
        }
        fn allocate_identity(
            &self,
            _: &RuntimeId,
            _: &Domain,
            _: &Identity,
        ) -> Result<Identity, StepError> {
            unreachable!()
        }
        fn write_service(&self, _: &RuntimeId, _: &Domain, _: &Identity) -> Result<(), StepError> {
            self.step("service")
        }
        fn activate_exec_config(
            &self,
            _: &RuntimeId,
            _: &Domain,
            _: &str,
        ) -> Result<(), StepError> {
            self.step("exec")
        }
        fn probe(
            &self,
            service: &str,
            _: &Domain,
            _: &str,
            _: Option<&HealthCheck>,
        ) -> Result<(), StepError> {
            self.step(if service == "ingress" {
                "verify"
            } else {
                "probe"
            })
        }
        fn activate_route(
            &self,
            _: &Domain,
            _: RouteKind,
            _: &str,
            _: &ConfigHash,
        ) -> Result<(), StepError> {
            unreachable!()
        }
        fn remove_exec_config(&self, _: &RuntimeId, _: &Domain) -> Result<(), StepError> {
            self.cleanup("remove-exec")
        }
        fn remove_service(&self, _: &RuntimeId, _: &Domain) -> Result<(), StepError> {
            self.cleanup("remove-service")
        }
        fn release_identity(&self, _: &RuntimeId, _: &Domain) -> Result<(), StepError> {
            unreachable!()
        }
        fn stop_idle_pool(&self, _: &RuntimeId) -> Result<(), StepError> {
            unreachable!()
        }
    }
    impl Backend for Fake {
        fn check_available(&self, _: &Plan) -> Result<String, StepError> {
            self.step("available")?;
            Ok(identity().root)
        }
        fn allocate_new(&self, _: &Plan, _: &str, _: &str) -> Result<Identity, StepError> {
            self.step("identity")?;
            Ok(identity())
        }
        fn prepare_new_root(&self, _: &Plan, _: &Identity, _: &str) -> Result<(), StepError> {
            self.step("root")
        }
        fn ensure_pool(&self, _: &Plan) -> Result<(), StepError> {
            self.step("pool")
        }
        fn create_route(&self, _: &Plan, _: &str) -> Result<(), StepError> {
            self.step("route")
        }
        fn remove_created_route(&self, _: &Plan, _: &str) -> Result<(), StepError> {
            self.cleanup("remove-route")
        }
        fn remove_empty_root(&self, _: &Plan, _: RequestId) -> Result<(), StepError> {
            self.cleanup("remove-root")
        }
        fn release_created_identity(&self, _: &Plan, _: RequestId) -> Result<(), StepError> {
            self.cleanup("release-identity")
        }
    }
    fn plan() -> Plan {
        Plan {
            domain: "example.test".into(),
            runtime_id: "fp1-php83".into(),
            relative_root: Some("public".into()),
            profile: None,
            worker_mode: false,
            worker_count: 4,
        }
    }
    fn fixture() -> (tempfile::TempDir, ManagedRoot, RequestId, IdempotencyKey) {
        let dir = tempfile::tempdir().unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(dir.path()).unwrap()).unwrap();
        (
            dir,
            root,
            fresh(),
            IdempotencyKey::parse("create-test").unwrap(),
        )
    }
    #[test]
    fn oversized_journal_does_not_advertise_creation_recovery() {
        let (_dir, state, id, _key) = fixture();
        let scope = scope(&state, &Domain::parse("example.com").unwrap()).unwrap();
        let journal = Journal {
            request_id: id,
            plan: plan(),
            root: "x".repeat(16 * 1024),
            identity: false,
            root_attempted: false,
            service: false,
            exec: false,
            route: false,
            completed: None,
        };
        save(&scope, &journal).unwrap();
        let record = state::TransactionState::start(id, None, OPERATION);
        assert!(!available(&scope, &record));
    }

    #[test]
    fn site_is_published_only_after_runtime_probe_and_same_key_replays_without_steps() {
        let (_dir, state, id, key) = fixture();
        let fake = Fake::default();
        let plan = plan();
        let result = execute(&state, &fake, &plan, id, &key).unwrap();
        assert_eq!(
            *fake.calls.borrow(),
            [
                "available",
                "identity",
                "root",
                "pool",
                "service",
                "exec",
                "probe",
                "route",
                "verify"
            ]
        );
        fake.calls.borrow_mut().clear();
        assert_eq!(
            execute(&state, &fake, &plan, fresh(), &key).unwrap().domain,
            result.domain
        );
        assert!(fake.calls.borrow().is_empty());
        let mut changed = plan.clone();
        changed.worker_count = 8;
        assert_eq!(
            execute(&state, &fake, &changed, fresh(), &key)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }
    #[test]
    fn every_failed_boundary_compensates_in_reverse_without_publishing_unprobed_site() {
        for point in [
            "available",
            "identity",
            "root",
            "pool",
            "service",
            "exec",
            "probe",
            "route",
            "verify",
        ] {
            let (_dir, state, id, key) = fixture();
            let fake = Fake::default();
            *fake.fail.borrow_mut() = Some(point.into());
            assert!(
                execute(&state, &fake, &plan(), id, &key).is_err(),
                "{point}"
            );
            let status =
                crate::operation_status::load_create(&state, "example.test", &id.to_string())
                    .unwrap();
            assert_eq!(
                status.transaction.status,
                TransactionStatus::Failed,
                "{point}"
            );
            let calls = fake.calls.borrow();
            if point == "probe" {
                assert!(!calls.iter().any(|s| s == "route"));
            }
            if point == "verify" {
                assert_eq!(
                    &calls[calls.len() - 5..],
                    [
                        "remove-route",
                        "remove-exec",
                        "remove-service",
                        "remove-root",
                        "release-identity"
                    ]
                );
            }
        }
    }
    #[test]
    fn failed_compensation_retains_journal_and_explicit_recovery_finishes_it() {
        let (_dir, state, id, key) = fixture();
        let fake = Fake::default();
        *fake.fail.borrow_mut() = Some("verify".into());
        *fake.fail_cleanup.borrow_mut() = true;
        assert!(execute(&state, &fake, &plan(), id, &key).is_err());
        assert_eq!(
            crate::operation_status::load_create(&state, "example.test", &id.to_string())
                .unwrap()
                .transaction
                .status,
            TransactionStatus::InProgress
        );
        assert!(
            execute(
                &state,
                &fake,
                &plan(),
                fresh(),
                &IdempotencyKey::parse("another-key").unwrap()
            )
            .is_err()
        );
        *fake.fail_cleanup.borrow_mut() = false;
        let recovered = recover(&state, &fake, "example.test", id).unwrap();
        assert_eq!(recovered.transaction.status, TransactionStatus::Failed);
        let count = fake.calls.borrow().len();
        assert_eq!(
            recover(&state, &fake, "example.test", id)
                .unwrap()
                .transaction,
            recovered.transaction
        );
        assert_eq!(fake.calls.borrow().len(), count);
    }
    #[test]
    fn recovery_refuses_live_owner_and_foreign_domain_without_cleanup() {
        let (_dir, state, id, key) = fixture();
        let fake = Fake::default();
        *fake.fail.borrow_mut() = Some("verify".into());
        *fake.fail_cleanup.borrow_mut() = true;
        assert!(execute(&state, &fake, &plan(), id, &key).is_err());
        let scope = scope(&state, &Domain::parse("example.test").unwrap()).unwrap();
        let guard = lock::acquire(&scope, &preflight::lock_path(), id).unwrap();
        let count = fake.calls.borrow().len();
        assert!(recover(&state, &fake, "example.test", id).is_err());
        assert!(recover(&state, &fake, "other.test", id).is_err());
        assert_eq!(fake.calls.borrow().len(), count);
        drop(guard);
    }
    #[test]
    fn terminal_journal_metadata_does_not_block_a_later_explicit_creation() {
        let (_dir, state, id, key) = fixture();
        let fake = Fake::default();
        *fake.fail.borrow_mut() = Some("available".into());
        assert!(execute(&state, &fake, &plan(), id, &key).is_err());
        let scope = scope(&state, &Domain::parse("example.test").unwrap()).unwrap();
        scope
            .write_atomic(&journal_path(id), b"leftover terminal journal")
            .unwrap();
        *fake.fail.borrow_mut() = None;
        fake.calls.borrow_mut().clear();
        assert!(
            execute(
                &state,
                &fake,
                &plan(),
                fresh(),
                &IdempotencyKey::parse("new-intent").unwrap()
            )
            .is_ok()
        );
        assert!(!scope.exists(&journal_path(id)));
        assert!(
            !fake
                .calls
                .borrow()
                .iter()
                .any(|call| call.starts_with("remove"))
        );
    }

    #[test]
    fn plans_refuse_unsafe_paths_worker_counts_profiles_and_unknown_fields() {
        for root in ["../escape", "/tmp/x", "public/../secret", "public//web"] {
            let mut p = plan();
            p.relative_root = Some(root.into());
            assert!(p.validate().is_err(), "{root}");
        }
        for n in [0, 65] {
            let mut p = plan();
            p.worker_count = n;
            assert!(p.validate().is_err());
        }
        assert!(
            serde_json::from_str::<Plan>(
                r#"{"domain":"example.test","runtimeId":"fp1-php83","extra":true}"#
            )
            .is_err()
        );
        let mut p = plan();
        p.domain = "sites".into();
        assert!(p.validate().is_err());
    }
}
