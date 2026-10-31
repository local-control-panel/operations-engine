//! Recoverable publication of prebuilt static output. No application code runs.
use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    operation_status::OperationStatus,
    site::{Domain, SiteRelativePath},
    site_migrate_runtime::StepError,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::io::Read;
pub const OPERATION: &str = "site.publishStatic";
pub const RECOVER_OPERATION: &str = "site.recoverStatic";
pub const PUBLIC_ROOT: &str = "/var/lib/wcp-static";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub domain: String,
    pub source_path: String,
    #[serde(default)]
    pub spa_fallback: bool,
}
impl Plan {
    pub fn validate(&self) -> Result<Domain, StepError> {
        let domain = Domain::parse(&self.domain).map_err(|_| invalid())?;
        let path = std::path::Path::new(&self.source_path);
        if !path.is_absolute()
            || self.source_path.len() > 4096
            || self.source_path.chars().any(char::is_control)
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid());
        }
        Ok(domain)
    }
}
pub trait Backend {
    fn check(&self, plan: &Plan) -> Result<Option<String>, StepError>;
    fn activate_route(&self, plan: &Plan, previous: Option<&str>) -> Result<(), StepError>;
    fn restore_route(&self, plan: &Plan, previous: Option<&str>) -> Result<(), StepError>;
    fn probe(&self, plan: &Plan, release: Option<RequestId>) -> Result<(), StepError>;
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishResult {
    pub domain: String,
    pub release_id: RequestId,
    pub previous_release_id: Option<RequestId>,
    pub publishing_root: String,
    pub spa_fallback: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    plan: Plan,
    request_id: RequestId,
    previous: Option<RequestId>,
    previous_route: Option<String>,
}
fn rel(s: &str) -> SiteRelativePath {
    SiteRelativePath::parse(s).unwrap()
}
fn invalid() -> StepError {
    StepError::new(ErrorCode::InvalidInput, "invalid static publication plan")
}
fn internal() -> StepError {
    StepError::new(
        ErrorCode::Internal,
        "static publication requires status inspection or recovery",
    )
}
fn conflict() -> StepError {
    StepError::new(
        ErrorCode::Conflict,
        "static publication is active or requires recovery",
    )
}
fn tx(id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{id}.json"))
}
fn scope(state: &ManagedRoot, domain: &str) -> Result<ManagedRoot, StepError> {
    Domain::parse(domain).map_err(|_| invalid())?;
    let path = rel(&format!("static-publish/{domain}"));
    state.create_dir_all(&path).map_err(|_| internal())?;
    let root = state.open_managed_dir(&path).map_err(|_| internal())?;
    root.set_own_mode(0o700).map_err(|_| internal())?;
    for p in ["transactions", "locks", "audit", "staging"] {
        root.create_dir_all(&rel(p)).map_err(|_| internal())?;
    }
    Ok(root)
}
fn read_json<T: serde::de::DeserializeOwned>(
    root: &ManagedRoot,
    path: &SiteRelativePath,
) -> Result<T, StepError> {
    let f = root.open_regular_read(path).map_err(|_| internal())?;
    let mut bytes = Vec::new();
    f.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| internal())?;
    if bytes.len() > 65536 {
        return Err(internal());
    }
    serde_json::from_slice(&bytes).map_err(|_| internal())
}
fn save(root: &ManagedRoot, j: &Journal) -> Result<(), StepError> {
    root.write_atomic_private(
        &rel("pending.json"),
        &serde_json::to_vec(j).map_err(|_| internal())?,
    )
    .map_err(|_| internal())
}
fn current(site: &ManagedRoot) -> Result<Option<RequestId>, StepError> {
    match site.read_link(&rel("current")) {
        Ok(p) => {
            let s = p.to_str().ok_or_else(internal)?;
            let id = s.strip_prefix("releases/").ok_or_else(internal)?;
            Ok(Some(RequestId::parse(id).map_err(|_| internal())?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(internal()),
    }
}
fn switch(
    site: &ManagedRoot,
    target: Option<RequestId>,
    nonce: RequestId,
) -> Result<(), StepError> {
    let temp = rel(&format!(".current-{nonce}"));
    if site.symlink_metadata(&temp).is_ok() {
        site.remove_file(&temp).map_err(|_| internal())?;
    }
    if let Some(id) = target {
        site.open_managed_dir(&rel(&format!("releases/{id}")))
            .map_err(|_| internal())?;
        site.symlink(&temp, &rel(&format!("releases/{id}")))
            .map_err(|_| internal())?;
        site.rename(&temp, &rel("current"))
            .map_err(|_| internal())?;
    } else if current(site)?.is_some() {
        site.remove_file(&rel("current")).map_err(|_| internal())?;
    }
    site.sync_all().map_err(|_| internal())
}
fn site(public: &ManagedRoot, domain: &str) -> Result<ManagedRoot, StepError> {
    public
        .create_dir_all(&rel(domain))
        .map_err(|_| internal())?;
    let s = public
        .open_child_dir_nofollow(&rel(domain))
        .map_err(|_| internal())?;
    s.create_dir_all(&rel("releases")).map_err(|_| internal())?;
    Ok(s)
}
fn permissions(root: &ManagedRoot) -> Result<(), StepError> {
    for entry in root.child_entries().map_err(|_| internal())? {
        let p = SiteRelativePath::parse(entry.name).map_err(|_| internal())?;
        if entry.is_dir {
            permissions(&root.open_child_dir_nofollow(&p).map_err(|_| internal())?)?;
        } else {
            root.set_mode(&p, 0o444).map_err(|_| internal())?;
        }
    }
    root.set_own_mode(0o555).map_err(|_| internal())?;
    root.sync_all().map_err(|_| internal())
}
pub fn execute(
    state_root: &ManagedRoot,
    public: &ManagedRoot,
    source: &ManagedRoot,
    backend: &impl Backend,
    plan: &Plan,
    id: RequestId,
    key: &IdempotencyKey,
) -> Result<PublishResult, StepError> {
    plan.validate()?;
    let scope = scope(state_root, &plan.domain)?;
    let admitted = preflight::run(&scope, id, Some(key), OPERATION).map_err(|_| conflict())?;
    let mut transaction = match admitted {
        preflight::Outcome::Replay(old) => {
            let old_plan: Plan = read_json(&scope, &rel(&format!("transactions/{old}.plan.json")))?;
            if old_plan != *plan {
                return Err(conflict());
            }
            let record = state::load(&scope, &tx(old)).map_err(|_| internal())?;
            return match record.status {
                TransactionStatus::Committed => serde_json::from_value(
                    record.outcome.and_then(|o| o.result).ok_or_else(internal)?,
                )
                .map_err(|_| internal()),
                TransactionStatus::InProgress => Err(conflict()),
                TransactionStatus::Failed => Err(StepError::new(
                    ErrorCode::Conflict,
                    "static publication previously failed; use a new request after inspection",
                )),
            };
        }
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    scope
        .write_atomic_private(
            &rel(&format!("transactions/{id}.plan.json")),
            &serde_json::to_vec(plan).map_err(|_| internal())?,
        )
        .map_err(|_| internal())?;
    if scope.symlink_metadata(&rel("pending.json")).is_ok() {
        let pending: Journal = read_json(&scope, &rel("pending.json"))?;
        let previous = state::load(&scope, &tx(pending.request_id)).map_err(|_| internal())?;
        if previous.status == TransactionStatus::InProgress {
            transaction
                .state
                .mark_failed(ErrorCode::Conflict, "earlier publication requires recovery")
                .map_err(|_| internal())?;
            state::save(&scope, &tx(id), &transaction.state).map_err(|_| internal())?;
            return Err(conflict());
        }
        scope
            .remove_file(&rel("pending.json"))
            .map_err(|_| internal())?;
    }
    let prepared = (|| {
        let route = backend.check(plan)?;
        let site = site(public, &plan.domain)?;
        let previous = current(&site)?;
        if previous.is_some() != route.is_some() {
            return Err(conflict());
        }
        let j = Journal {
            plan: plan.clone(),
            request_id: id,
            previous,
            previous_route: route,
        };
        save(&scope, &j)?;
        Ok((site, j))
    })();
    let (site, j) = match prepared {
        Ok(v) => v,
        Err(e) => {
            transaction
                .state
                .mark_failed(e.code, &e.message)
                .map_err(|_| internal())?;
            state::save(&scope, &tx(id), &transaction.state).map_err(|_| internal())?;
            return Err(e);
        }
    };
    let outcome = (|| {
        if source.symlink_metadata(&rel("wcp-release.txt")).is_ok() {
            return Err(invalid());
        }
        let staging = rel(&format!("staging/{id}"));
        scope.create_dir(&staging).map_err(|_| internal())?;
        let copied = scope.open_managed_dir(&staging).map_err(|_| internal())?;
        copied.set_own_mode(0o700).map_err(|_| internal())?;
        crate::static_artifact::copy_private(source, &copied).map_err(|_| {
            StepError::new(ErrorCode::InvalidInput, "static artifact validation failed")
        })?;
        copied
            .create_new(&rel("wcp-release.txt"), id.to_string().as_bytes())
            .map_err(|_| internal())?;
        permissions(&copied)?;
        // Keep the directory private and movable until the same-filesystem rename.
        copied.set_own_mode(0o700).map_err(|_| internal())?;
        scope
            .rename_to(&staging, &site, &rel(&format!("releases/{id}")))
            .map_err(|_| internal())?;
        copied.set_own_mode(0o555).map_err(|_| internal())?;
        copied.sync_all().map_err(|_| internal())?;
        site.sync_all().map_err(|_| internal())?;
        crate::failpoint::hit("static-before-switch");
        switch(&site, Some(id), id)?;
        crate::failpoint::hit("static-after-switch");
        backend.activate_route(plan, j.previous_route.as_deref())?;
        backend.probe(plan, Some(id))?;
        Ok(PublishResult {
            domain: plan.domain.clone(),
            release_id: id,
            previous_release_id: j.previous,
            publishing_root: format!("{PUBLIC_ROOT}/{}/current", plan.domain),
            spa_fallback: plan.spa_fallback,
        })
    })();
    match outcome {
        Ok(result) => {
            transaction
                .state
                .mark_committed(serde_json::to_value(&result).map_err(|_| internal())?)
                .map_err(|_| internal())?;
            state::save(&scope, &tx(id), &transaction.state).map_err(|_| internal())?;
            let _ = audit::append(
                &scope,
                &rel("audit/events.jsonl"),
                &AuditRecord::result(id, true, None),
            );
            scope
                .remove_file(&rel("pending.json"))
                .map_err(|_| internal())?;
            Ok(result)
        }
        Err(e) => {
            undo(&site, backend, &j)?;
            transaction
                .state
                .mark_failed(e.code, &e.message)
                .map_err(|_| internal())?;
            state::save(&scope, &tx(id), &transaction.state).map_err(|_| internal())?;
            let _ = audit::append(
                &scope,
                &rel("audit/events.jsonl"),
                &AuditRecord::result(id, false, Some(e.code)),
            );
            scope
                .remove_file(&rel("pending.json"))
                .map_err(|_| internal())?;
            Err(e)
        }
    }
}
fn undo(site: &ManagedRoot, backend: &impl Backend, j: &Journal) -> Result<(), StepError> {
    let live = current(site)?;
    if live != Some(j.request_id) && live != j.previous {
        return Err(conflict());
    }
    switch(site, j.previous, j.request_id)?;
    backend.restore_route(&j.plan, j.previous_route.as_deref())?;
    backend.probe(&j.plan, j.previous)
}
pub fn status(
    state_root: &ManagedRoot,
    domain: &str,
    id: RequestId,
) -> Result<OperationStatus, StepError> {
    let scope = scope(state_root, domain)?;
    let transaction = state::load(&scope, &tx(id))
        .map_err(|_| StepError::new(ErrorCode::NotFound, "static publication not found"))?;
    if transaction.operation != OPERATION {
        return Err(internal());
    }
    let active = lock::holder(&scope, &preflight::lock_path()).map_err(|_| internal())? == Some(id);
    let recoverable = match scope.symlink_metadata(&rel("pending.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Ok(_) => {
            read_json::<Journal>(&scope, &rel("pending.json")).is_ok_and(|j| j.request_id == id)
        }
        Err(_) => false,
    };
    Ok(OperationStatus {
        recovery_action: if !active
            && recoverable
            && transaction.status == TransactionStatus::InProgress
        {
            Some(RECOVER_OPERATION)
        } else {
            None
        },
        transaction,
        active,
    })
}
pub fn recover(
    state_root: &ManagedRoot,
    public: &ManagedRoot,
    backend: &impl Backend,
    domain: &str,
    id: RequestId,
) -> Result<OperationStatus, StepError> {
    let scope = scope(state_root, domain)?;
    let guard = lock::acquire(&scope, &preflight::lock_path(), id).map_err(|_| conflict())?;
    let mut record = state::load(&scope, &tx(id)).map_err(|_| internal())?;
    if record.operation != OPERATION {
        return Err(internal());
    }
    let journal = match scope.symlink_metadata(&rel("pending.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Ok(_) => Some(read_json::<Journal>(&scope, &rel("pending.json"))?),
        Err(_) => return Err(internal()),
    };
    if record.status == TransactionStatus::InProgress {
        if let Some(j) = &journal {
            if j.request_id != id || j.plan.domain != domain {
                return Err(conflict());
            }
            j.plan.validate()?;
            undo(&site(public, domain)?, backend, j)?;
        }
        // No checkpoint means execution never crossed its first mutation boundary.
        record
            .mark_failed(
                ErrorCode::Cancelled,
                if journal.is_some() {
                    "interrupted publication rolled back; previous serving state verified"
                } else {
                    "interrupted before publication checkpoint; no serving changes were attempted"
                },
            )
            .map_err(|_| internal())?;
        state::save(&scope, &tx(id), &record).map_err(|_| internal())?;
    }
    if journal.is_some_and(|j| j.request_id == id) {
        scope
            .remove_file(&rel("pending.json"))
            .map_err(|_| internal())?;
    }

    let _ = audit::append(
        &scope,
        &rel("audit/events.jsonl"),
        &AuditRecord::result(id, record.status == TransactionStatus::Committed, None),
    );
    drop(guard);
    status(state_root, domain, id)
}

#[cfg(any())]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{
        cell::{Cell, RefCell},
        fs,
        panic::{AssertUnwindSafe, catch_unwind},
    };
    const DOMAIN: &str = "static.example.test";
    struct Fake {
        route: RefCell<Option<String>>,
        fail: Cell<bool>,
        crash: Cell<bool>,
    }
    impl Backend for Fake {
        fn check(&self, _: &Plan) -> Result<Option<String>, StepError> {
            Ok(self.route.borrow().clone())
        }
        fn activate_route(&self, _: &Plan, _: Option<&str>) -> Result<(), StepError> {
            if self.crash.replace(false) {
                panic!("simulated process termination after switch");
            }
            if self.fail.replace(false) {
                return Err(internal());
            }
            *self.route.borrow_mut() = Some("static".into());
            Ok(())
        }
        fn restore_route(&self, _: &Plan, previous: Option<&str>) -> Result<(), StepError> {
            *self.route.borrow_mut() = previous.map(str::to_owned);
            Ok(())
        }
        fn probe(&self, _: &Plan, _: Option<RequestId>) -> Result<(), StepError> {
            Ok(())
        }
    }
    fn managed(dir: &tempfile::TempDir) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(dir.path()).unwrap()).unwrap()
    }
    fn id() -> RequestId {
        RequestId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
    }
    fn key(id: RequestId) -> IdempotencyKey {
        IdempotencyKey::parse(&id.to_string()).unwrap()
    }
    fn fixture() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        tempfile::TempDir,
        Plan,
        Fake,
    ) {
        let state = tempfile::tempdir().unwrap();
        let public = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("index.html"), "first").unwrap();
        let plan = Plan {
            domain: DOMAIN.into(),
            source_path: source.path().to_str().unwrap().into(),
            spa_fallback: false,
        };
        (
            state,
            public,
            source,
            plan,
            Fake {
                route: RefCell::new(None),
                fail: Cell::new(false),
                crash: Cell::new(false),
            },
        )
    }
    #[test]
    fn publish_replay_and_failed_artifact_preserve_release() {
        let (s, p, a, plan, b) = fixture();
        let id = id();
        let first = execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            id,
            &key(id),
        )
        .unwrap();
        assert_eq!(first.release_id, id);
        assert_eq!(
            execute(
                &managed(&s),
                &managed(&p),
                &managed(&a),
                &b,
                &plan,
                id,
                &key(id)
            )
            .unwrap()
            .release_id,
            id
        );
        fs::write(a.path().join("secret.php"), "secret").unwrap();
        let next = super::tests::id();
        assert!(
            execute(
                &managed(&s),
                &managed(&p),
                &managed(&a),
                &b,
                &plan,
                next,
                &key(next)
            )
            .is_err()
        );
        assert_eq!(
            fs::read_to_string(p.path().join(format!("{DOMAIN}/current/index.html"))).unwrap(),
            "first"
        );
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(id)
        );
    }
    #[test]
    fn route_failure_restores_previous_release() {
        let (s, p, a, plan, b) = fixture();
        let old = id();
        execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            old,
            &key(old),
        )
        .unwrap();
        fs::write(a.path().join("index.html"), "second").unwrap();
        b.fail.set(true);
        let next = id();
        assert!(
            execute(
                &managed(&s),
                &managed(&p),
                &managed(&a),
                &b,
                &plan,
                next,
                &key(next)
            )
            .is_err()
        );
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(old)
        );
        assert_eq!(
            status(&managed(&s), DOMAIN, next)
                .unwrap()
                .transaction
                .status,
            TransactionStatus::Failed
        );
    }
    #[test]
    fn interrupted_after_switch_requires_explicit_verified_rollback() {
        let (s, p, a, plan, b) = fixture();
        let old = id();
        execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            old,
            &key(old),
        )
        .unwrap();
        let next = id();
        b.crash.set(true);
        assert!(
            catch_unwind(AssertUnwindSafe(|| execute(
                &managed(&s),
                &managed(&p),
                &managed(&a),
                &b,
                &plan,
                next,
                &key(next)
            )))
            .is_err()
        );
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(next)
        );
        assert_eq!(
            status(&managed(&s), DOMAIN, next).unwrap().recovery_action,
            Some(RECOVER_OPERATION)
        );
        let r = recover(&managed(&s), &managed(&p), &b, DOMAIN, next).unwrap();
        assert_eq!(r.transaction.status, TransactionStatus::Failed);
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(old)
        );
        assert!(recover(&managed(&s), &managed(&p), &b, DOMAIN, next).is_ok());
    }
    #[test]
    fn rejects_bad_plans() {
        let (_, _, _, mut plan, _) = fixture();
        plan.domain = "bad\nroot /etc".into();
        assert!(plan.validate().is_err());
        plan.domain = DOMAIN.into();
        plan.source_path = "/var/www/../secrets".into();
        assert!(plan.validate().is_err());
        assert!(
            serde_json::from_str::<Plan>(
                r#"{"domain":"example.test","sourcePath":"/tmp/out","build":"npm"}"#
            )
            .is_err()
        );
    }
    #[test]
    fn interruption_before_switch_keeps_previous_release() {
        let (s, p, a, plan, b) = fixture();
        let old = id();
        execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            old,
            &key(old),
        )
        .unwrap();
        let next = id();
        let root = scope(&managed(&s), DOMAIN).unwrap();
        let admitted = preflight::run(&root, next, Some(&key(next)), OPERATION).unwrap();
        save(
            &root,
            &Journal {
                plan: plan.clone(),
                request_id: next,
                previous: Some(old),
                previous_route: Some("static".into()),
            },
        )
        .unwrap();
        drop(admitted);
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(old)
        );
        let recovered = recover(&managed(&s), &managed(&p), &b, DOMAIN, next).unwrap();
        assert_eq!(recovered.transaction.status, TransactionStatus::Failed);
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(old)
        );
    }
    #[test]
    fn completed_checkpoint_cleanup_never_rolls_back_committed_release() {
        let (s, p, a, plan, b) = fixture();
        let committed = id();
        execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            committed,
            &key(committed),
        )
        .unwrap();
        let root = scope(&managed(&s), DOMAIN).unwrap();
        save(
            &root,
            &Journal {
                plan: plan.clone(),
                request_id: committed,
                previous: None,
                previous_route: None,
            },
        )
        .unwrap();
        let recovered = recover(&managed(&s), &managed(&p), &b, DOMAIN, committed).unwrap();
        assert_eq!(recovered.transaction.status, TransactionStatus::Committed);
        assert_eq!(
            current(&site(&managed(&p), DOMAIN).unwrap()).unwrap(),
            Some(committed)
        );
        assert!(root.symlink_metadata(&rel("pending.json")).is_err());
        let next = id();
        execute(
            &managed(&s),
            &managed(&p),
            &managed(&a),
            &b,
            &plan,
            next,
            &key(next),
        )
        .unwrap();
    }
    #[test]
    fn recovery_without_checkpoint_does_not_claim_a_serving_probe() {
        let (s, p, _, _, b) = fixture();
        let next = id();
        let root = scope(&managed(&s), DOMAIN).unwrap();
        drop(preflight::run(&root, next, Some(&key(next)), OPERATION).unwrap());
        let recovered = recover(&managed(&s), &managed(&p), &b, DOMAIN, next).unwrap();
        assert_eq!(recovered.transaction.status, TransactionStatus::Failed);
        assert!(
            serde_json::to_string(&recovered)
                .unwrap()
                .contains("no serving changes were attempted")
        );
    }
    #[cfg(feature = "failpoints")]
    #[test]
    fn crash_process_child() {
        let Ok(base) = std::env::var("WCP_STATIC_CRASH_FIXTURE") else {
            return;
        };
        let open = |name: &str| {
            ManagedRoot::open(&TrustedRoot::parse(std::path::Path::new(&base).join(name)).unwrap())
                .unwrap()
        };
        let request =
            RequestId::parse(&std::env::var("WCP_STATIC_CRASH_REQUEST").unwrap()).unwrap();
        let plan = Plan {
            domain: DOMAIN.into(),
            source_path: format!("{base}/source"),
            spa_fallback: false,
        };
        let backend = Fake {
            route: RefCell::new(Some("static".into())),
            fail: Cell::new(false),
            crash: Cell::new(false),
        };
        execute(
            &open("state"),
            &open("public"),
            &open("source"),
            &backend,
            &plan,
            request,
            &key(request),
        )
        .unwrap();
        panic!("crash point did not terminate child");
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn sigkill_before_and_after_switch_preserves_previous_release_on_recovery() {
        use std::os::unix::process::ExitStatusExt;
        for point in ["static-before-switch", "static-after-switch"] {
            let base = tempfile::tempdir().unwrap();
            for name in ["state", "public", "source"] {
                fs::create_dir(base.path().join(name)).unwrap();
            }
            let open = |name: &str| {
                ManagedRoot::open(&TrustedRoot::parse(base.path().join(name)).unwrap()).unwrap()
            };
            fs::write(base.path().join("source/index.html"), "previous").unwrap();
            let plan = Plan {
                domain: DOMAIN.into(),
                source_path: base.path().join("source").to_str().unwrap().into(),
                spa_fallback: false,
            };
            let backend = Fake {
                route: RefCell::new(None),
                fail: Cell::new(false),
                crash: Cell::new(false),
            };
            let old = id();
            execute(
                &open("state"),
                &open("public"),
                &open("source"),
                &backend,
                &plan,
                old,
                &key(old),
            )
            .unwrap();
            fs::write(base.path().join("source/index.html"), "new").unwrap();
            let next = id();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "static_publish::tests::crash_process_child",
                    "--nocapture",
                ])
                .env("WCP_STATIC_CRASH_FIXTURE", base.path())
                .env("WCP_STATIC_CRASH_REQUEST", next.to_string())
                .env("WCP_FAILPOINT", point)
                .output()
                .unwrap();
            assert_eq!(
                child.status.signal(),
                Some(libc::SIGKILL),
                "{point}: {:?}",
                child
            );
            let site = site(&open("public"), DOMAIN).unwrap();
            assert_eq!(
                current(&site).unwrap(),
                Some(if point == "static-before-switch" {
                    old
                } else {
                    next
                })
            );
            assert_eq!(
                status(&open("state"), DOMAIN, next)
                    .unwrap()
                    .recovery_action,
                Some(RECOVER_OPERATION)
            );
            recover(&open("state"), &open("public"), &backend, DOMAIN, next).unwrap();
            assert_eq!(current(&site).unwrap(), Some(old));
            assert_eq!(
                fs::read_to_string(
                    base.path()
                        .join(format!("public/{DOMAIN}/current/index.html"))
                )
                .unwrap(),
                "previous"
            );
        }
    }
}
