use std::cell::RefCell;

use super::*;
use crate::{site::TrustedRoot, transaction::state::TransactionState};

const ID: &str = "123e4567-e89b-12d3-a456-426614174001";
const OTHER: &str = "123e4567-e89b-12d3-a456-426614174002";
const DOMAIN: &str = "shop.example.test";

const ROUTE: &str = "shop.example.test {\n    basic_auth {\n        admin hash\n    }\n    reverse_proxy runtime-php83:80 {\n        header_up X-WCP-Runtime-ID php83\n    }\n    log {\n        log_append runtime_id php83\n    }\n}\n";

fn domain() -> Domain {
    Domain::parse(DOMAIN).unwrap()
}

fn runtime(id: &str) -> RuntimeId {
    RuntimeId::parse(id).unwrap()
}

fn identity(port: u16) -> Identity {
    Identity {
        os_user: "wcp-site-1".into(),
        uid: 20001,
        gid: 20001,
        port,
        root: "/var/www/shop.example.test/public".into(),
        worker_mode: false,
        worker_count: 1,
    }
}

/// The host, as far as the migration can tell: what exists where.
struct World {
    route: String,
    kind: RouteKind,
    old_identity: bool,
    old_service: bool,
    old_exec: bool,
    new_identity: bool,
    new_service: bool,
    new_exec: bool,
    pool_stopped: bool,
    log: Vec<String>,
}

struct Fake {
    world: RefCell<World>,
    /// Calls named here fail: `allocate`, `write_service`, `exec`,
    /// `probe:<service>`, `activate_route`, `restore_route`,
    /// `remove_exec:<pool>`, `remove_service:<pool>`, `release:<pool>`, `stop:<pool>`.
    fails: RefCell<Vec<String>>,
}

impl Fake {
    fn new(kind: RouteKind) -> Self {
        Self {
            world: RefCell::new(World {
                route: ROUTE.into(),
                kind,
                old_identity: true,
                old_service: true,
                old_exec: true,
                new_identity: false,
                new_service: false,
                new_exec: false,
                pool_stopped: false,
                log: Vec::new(),
            }),
            fails: RefCell::new(Vec::new()),
        }
    }

    fn fail(&self, what: &str) {
        self.fails.borrow_mut().push(what.to_owned());
    }

    fn heal(&self) {
        self.fails.borrow_mut().clear();
    }

    fn step(&self, name: &str) -> Result<(), StepError> {
        self.world.borrow_mut().log.push(name.to_owned());
        if self.fails.borrow().iter().any(|f| f == name) {
            return Err(StepError::new(
                ErrorCode::SubprocessFailed,
                format!("{name} failed"),
            ));
        }
        Ok(())
    }

    fn log(&self) -> Vec<String> {
        self.world.borrow().log.clone()
    }

    fn route(&self) -> String {
        self.world.borrow().route.clone()
    }

    fn target_is_clean(&self) -> bool {
        let w = self.world.borrow();
        !w.new_identity && !w.new_service && !w.new_exec
    }

    fn old_is_intact(&self) -> bool {
        let w = self.world.borrow();
        w.old_identity && w.old_service && w.old_exec
    }
}

impl Backend for Fake {
    fn read_route(&self, _: &Domain) -> Result<Route, StepError> {
        let w = self.world.borrow();
        Ok(Route {
            kind: w.kind,
            content: w.route.clone(),
        })
    }

    fn read_identity(&self, pool: &RuntimeId, _: &Domain) -> Result<Option<Identity>, StepError> {
        let w = self.world.borrow();
        let present = if pool.as_str() == "php83" {
            w.old_identity
        } else {
            w.new_identity
        };
        Ok(present.then(|| identity(8001)))
    }

    fn allocate_identity(
        &self,
        _: &RuntimeId,
        _: &Domain,
        from: &Identity,
    ) -> Result<Identity, StepError> {
        self.step("allocate")?;
        self.world.borrow_mut().new_identity = true;
        Ok(Identity {
            port: 8101,
            ..from.clone()
        })
    }

    fn write_service(&self, _: &RuntimeId, _: &Domain, _: &Identity) -> Result<(), StepError> {
        self.step("write_service")?;
        self.world.borrow_mut().new_service = true;
        Ok(())
    }

    fn activate_exec_config(
        &self,
        _: &RuntimeId,
        _: &Domain,
        content: &str,
    ) -> Result<(), StepError> {
        self.step("exec")?;
        assert!(
            content.contains("reverse_proxy 127.0.0.1:8101"),
            "{content}"
        );
        self.world.borrow_mut().new_exec = true;
        Ok(())
    }

    fn probe(
        &self,
        service: &str,
        _: &Domain,
        root: &str,
        _: Option<&HealthCheck>,
    ) -> Result<(), StepError> {
        assert_eq!(root, "/var/www/shop.example.test/public");
        self.step(&format!("probe:{service}"))
    }

    fn activate_route(
        &self,
        _: &Domain,
        kind: RouteKind,
        content: &str,
        expected: &ConfigHash,
    ) -> Result<(), StepError> {
        let restoring = content == ROUTE;
        self.step(if restoring {
            "restore_route"
        } else {
            "activate_route"
        })?;
        let mut w = self.world.borrow_mut();
        assert_eq!(kind, w.kind);
        if sha(&w.route) != *expected {
            return Err(StepError::new(
                ErrorCode::ConfigHashMismatch,
                "the route changed",
            ));
        }
        w.route = content.to_owned();
        Ok(())
    }

    fn remove_exec_config(&self, pool: &RuntimeId, _: &Domain) -> Result<(), StepError> {
        self.step(&format!("remove_exec:{pool}"))?;
        let mut w = self.world.borrow_mut();
        if pool.as_str() == "php83" {
            w.old_exec = false;
        } else {
            w.new_exec = false;
        }
        Ok(())
    }

    fn remove_service(&self, pool: &RuntimeId, _: &Domain) -> Result<(), StepError> {
        self.step(&format!("remove_service:{pool}"))?;
        let mut w = self.world.borrow_mut();
        if pool.as_str() == "php83" {
            w.old_service = false;
        } else {
            w.new_service = false;
        }
        Ok(())
    }

    fn release_identity(&self, pool: &RuntimeId, _: &Domain) -> Result<(), StepError> {
        self.step(&format!("release:{pool}"))?;
        let mut w = self.world.borrow_mut();
        if pool.as_str() == "php83" {
            w.old_identity = false;
        } else {
            w.new_identity = false;
        }
        Ok(())
    }

    fn stop_idle_pool(&self, pool: &RuntimeId) -> Result<(), StepError> {
        self.step(&format!("stop:{pool}"))?;
        self.world.borrow_mut().pool_stopped = true;
        Ok(())
    }
}

struct Fx {
    _dir: tempfile::TempDir,
    state: ManagedRoot,
}

impl Fx {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = TrustedRoot::parse(dir.path().canonicalize().unwrap()).unwrap();
        Self {
            state: ManagedRoot::open(&root).unwrap(),
            _dir: dir,
        }
    }

    fn request(&self, target: &str, id: &str) -> Request {
        Request::parse(DOMAIN, target, None, None, None, true, id, None).unwrap()
    }

    fn scope(&self) -> ManagedRoot {
        open_scope(&self.state, &domain()).unwrap()
    }

    fn journals(&self) -> Vec<String> {
        self.scope()
            .open_managed_dir(&rel("pending"))
            .unwrap()
            .file_names()
            .unwrap()
    }

    fn status(&self, id: &str) -> TransactionStatus {
        state::load(&self.scope(), &rel(&format!("transactions/{id}.json")))
            .unwrap()
            .status
    }
}

#[test]
fn a_migration_moves_the_route_and_cleans_the_old_pool() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    let result = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap();
    assert_eq!(result.from_runtime_id, "php83");
    assert_eq!(result.to_runtime_id, "php84");
    assert_eq!(result.port, 8101);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let route = fake.route();
    assert!(route.contains("reverse_proxy runtime-php84:80 {"));
    assert!(route.contains("header_up X-WCP-Runtime-ID php84"));
    assert!(route.contains("log_append runtime_id php84"));
    assert!(route.contains("basic_auth"), "other blocks are kept");
    assert_eq!(
        fake.log(),
        [
            "allocate",
            "write_service",
            "exec",
            "probe:runtime-php84",
            "activate_route",
            "probe:ingress",
            "remove_exec:php83",
            "remove_service:php83",
            "release:php83",
            "stop:php83",
        ]
    );
    let w = fake.world.borrow();
    assert!(w.new_identity && w.new_service && w.new_exec);
    assert!(!w.old_identity && !w.old_service && !w.old_exec);
    drop(w);
    assert!(fx.journals().is_empty());
    assert_eq!(fx.status(ID), TransactionStatus::Committed);
}

#[test]
fn a_failure_before_the_cutover_leaves_the_site_exactly_as_it_was() {
    for failing in ["allocate", "write_service", "exec", "probe:runtime-php84"] {
        let fx = Fx::new();
        let fake = Fake::new(RouteKind::Live);
        fake.fail(failing);
        let error = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap_err();
        let (_, message) = error.protocol();
        assert!(
            message.contains("rolled back to php83"),
            "{failing}: {message}"
        );
        assert_eq!(fake.route(), ROUTE, "{failing}");
        assert!(fake.target_is_clean(), "{failing}");
        assert!(fake.old_is_intact(), "{failing}");
        assert!(
            !fake.log().contains(&"activate_route".to_owned()),
            "{failing}"
        );
        assert!(fx.journals().is_empty(), "{failing}");
        assert_eq!(fx.status(ID), TransactionStatus::Failed, "{failing}");
    }
}

#[test]
fn a_rejected_cutover_removes_the_target_artifacts() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    fake.fail("activate_route");
    let error = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap_err();
    assert!(error.protocol().1.contains("rolled back to php83"));
    assert_eq!(fake.route(), ROUTE);
    assert!(fake.target_is_clean() && fake.old_is_intact());
    assert!(fx.journals().is_empty());
}

#[test]
fn a_failed_check_through_the_ingress_puts_the_old_route_back() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    fake.fail("probe:ingress");
    let error = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap_err();
    let (code, message) = error.protocol();
    assert_eq!(code, ErrorCode::SubprocessFailed);
    assert!(message.contains("Post-cutover check failed"), "{message}");
    assert!(message.contains("rolled back to php83"), "{message}");
    assert_eq!(fake.route(), ROUTE, "byte for byte");
    assert!(fake.target_is_clean() && fake.old_is_intact());
    assert!(fx.journals().is_empty());
}

#[test]
fn when_the_route_cannot_be_restored_the_target_stays_and_the_journal_is_kept() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    fake.fail("probe:ingress");
    fake.fail("restore_route");
    let error = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap_err();
    let (_, message) = error.protocol();
    assert!(message.contains("site.reconcile"), "{message}");
    assert!(
        fake.route().contains("runtime-php84"),
        "the route still points at the target"
    );
    let w = fake.world.borrow();
    assert!(
        w.new_identity && w.new_service && w.new_exec,
        "still referenced"
    );
    drop(w);
    assert_eq!(fx.journals().len(), 1);
    assert_eq!(fx.status(ID), TransactionStatus::Failed);

    // Once the host heals, site.reconcile finishes the rollback.
    fake.heal();
    let recovery = recover(
        &fx.state,
        &fake,
        &domain(),
        &format!("{ID}.json"),
        RequestId::parse(OTHER).unwrap(),
    );
    assert_eq!(recovery, Recovery::RolledBack);
    assert_eq!(fake.route(), ROUTE);
    assert!(fake.target_is_clean() && fake.old_is_intact());
    assert!(fx.journals().is_empty());
}

#[test]
fn a_cleanup_failure_on_the_old_pool_is_a_warning_not_a_rollback() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    fake.fail("remove_service:php83");
    fake.fail("stop:php83");
    let result = execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap();
    assert_eq!(result.warnings.len(), 2, "{:?}", result.warnings);
    assert!(
        result
            .warnings
            .iter()
            .all(|w| w.starts_with("oldPoolCleanupFailed"))
    );
    assert!(
        fake.route().contains("runtime-php84"),
        "the migration stands"
    );
    let w = fake.world.borrow();
    assert!(w.new_exec && w.new_service && w.new_identity);
    assert!(w.old_service, "what failed is still there");
    assert!(!w.old_exec && !w.old_identity, "the rest was still cleaned");
    drop(w);
    assert_eq!(fx.status(ID), TransactionStatus::Committed);
    assert!(fx.journals().is_empty());
}

#[test]
fn the_old_pool_is_stopped_only_when_asked() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    let request = Request::parse(DOMAIN, "php84", None, None, None, false, ID, None).unwrap();
    execute(&fx.state, &fake, &request).unwrap();
    assert!(
        !fake.log().iter().any(|c| c.starts_with("stop:")),
        "{:?}",
        fake.log()
    );
}

#[test]
fn a_parked_site_is_retargeted_without_a_check_through_the_ingress() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Backup);
    execute(&fx.state, &fake, &fx.request("php84", ID)).unwrap();
    assert!(!fake.log().contains(&"probe:ingress".to_owned()));
    assert!(fake.route().contains("runtime-php84"));
}

#[test]
fn a_request_that_cannot_work_changes_nothing() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    let error = execute(&fx.state, &fake, &fx.request("php83", ID)).unwrap_err();
    assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
    assert!(fake.log().is_empty());
    assert!(fx.journals().is_empty());

    let fake = Fake::new(RouteKind::Live);
    fake.world.borrow_mut().route = "shop.example.test {\n    respond ok\n}\n".into();
    let error = execute(&fx.state, &fake, &fx.request("php84", OTHER)).unwrap_err();
    assert_eq!(error.protocol().0, ErrorCode::InvalidInput);

    let fake = Fake::new(RouteKind::Live);
    fake.world.borrow_mut().old_identity = false;
    let error = execute(
        &fx.state,
        &fake,
        &fx.request("php84", "123e4567-e89b-12d3-a456-426614174003"),
    )
    .unwrap_err();
    assert_eq!(error.protocol().0, ErrorCode::NotFound);
}

#[test]
fn a_retry_with_the_same_key_returns_the_first_result() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    let first = Request::parse(DOMAIN, "php84", None, None, None, true, ID, Some("key-1")).unwrap();
    let a = execute(&fx.state, &fake, &first).unwrap();
    let again = Request::parse(
        DOMAIN,
        "php84",
        None,
        None,
        None,
        true,
        OTHER,
        Some("key-1"),
    )
    .unwrap();
    let b = execute(&fx.state, &fake, &again).unwrap();
    assert_eq!(a, b);
    assert_eq!(fake.log().iter().filter(|c| *c == "allocate").count(), 1);
}

/// What a killed engine leaves: a journal and an `InProgress` record.
fn killed(fx: &Fx, fake: &Fake, phase: Phase, flags: TargetArtifacts, route_is_new: bool) {
    let new_route = retarget_route(ROUTE, &runtime("php84")).unwrap();
    let journal = Journal {
        request_id: ID.into(),
        domain: DOMAIN.into(),
        from_runtime: "php83".into(),
        to_runtime: "php84".into(),
        route_kind: RouteKind::Live,
        previous_route: ROUTE.into(),
        previous_route_sha256: sha(ROUTE).as_str().to_owned(),
        new_route_sha256: sha(&new_route).as_str().to_owned(),
        phase,
        target: flags,
        stop_idle_source: true,
    };
    let scope = fx.scope();
    Store { scope: &scope }.create(&journal).unwrap();
    state::save(
        &scope,
        &rel(&format!("transactions/{ID}.json")),
        &TransactionState::start(RequestId::parse(ID).unwrap(), None, OPERATION),
    )
    .unwrap();
    let mut w = fake.world.borrow_mut();
    w.new_identity = flags.identity;
    w.new_service = flags.service;
    w.new_exec = flags.exec_config;
    if route_is_new {
        w.route = new_route;
    }
}

fn all_target() -> TargetArtifacts {
    TargetArtifacts {
        identity: true,
        service: true,
        exec_config: true,
    }
}

fn reconcile(fx: &Fx, fake: &Fake) -> Recovery {
    recover(
        &fx.state,
        fake,
        &domain(),
        &format!("{ID}.json"),
        RequestId::parse(OTHER).unwrap(),
    )
}

#[test]
fn a_migration_killed_after_the_cutover_is_rolled_back() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cutover, all_target(), true);
    assert_eq!(reconcile(&fx, &fake), Recovery::RolledBack);
    assert_eq!(fake.route(), ROUTE);
    assert!(fake.target_is_clean() && fake.old_is_intact());
    assert!(fx.journals().is_empty());
    assert_eq!(fx.status(ID), TransactionStatus::Failed);
    // Nothing is left for a second run.
    assert!(fx.journals().is_empty());
}

#[test]
fn a_migration_killed_during_the_cutover_with_the_old_route_still_live_only_loses_the_target() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cutover, all_target(), false);
    assert_eq!(reconcile(&fx, &fake), Recovery::RolledBack);
    assert_eq!(fake.route(), ROUTE);
    assert!(fake.target_is_clean() && fake.old_is_intact());
    assert!(
        !fake.log().contains(&"restore_route".to_owned()),
        "{:?}",
        fake.log()
    );
}

#[test]
fn a_migration_killed_while_preparing_removes_only_what_may_exist() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    let flags = TargetArtifacts {
        identity: true,
        service: false,
        exec_config: false,
    };
    killed(&fx, &fake, Phase::Preparing, flags, false);
    assert_eq!(reconcile(&fx, &fake), Recovery::RolledBack);
    assert_eq!(fake.log(), ["release:php84"]);
}

#[test]
fn a_migration_killed_in_the_cleanup_phase_is_finished_not_undone() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cleanup, all_target(), true);
    assert_eq!(reconcile(&fx, &fake), Recovery::Completed);
    assert!(fake.route().contains("runtime-php84"));
    let w = fake.world.borrow();
    assert!(w.new_identity && w.new_service && w.new_exec);
    assert!(!w.old_identity && !w.old_service && !w.old_exec);
    drop(w);
    assert!(fx.journals().is_empty());
    assert_eq!(fx.status(ID), TransactionStatus::Committed);
}

#[test]
fn a_journal_beside_a_committed_record_is_only_removed() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cutover, all_target(), true);
    let scope = fx.scope();
    let path = rel(&format!("transactions/{ID}.json"));
    let mut record = state::load(&scope, &path).unwrap();
    record.mark_committed(serde_json::json!({})).unwrap();
    state::save(&scope, &path, &record).unwrap();
    assert_eq!(reconcile(&fx, &fake), Recovery::Cleared);
    assert!(
        fake.route().contains("runtime-php84"),
        "a committed migration is not undone"
    );
    assert!(fake.log().is_empty());
    assert!(fx.journals().is_empty());
}

#[test]
fn a_route_someone_else_changed_is_not_overwritten() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cutover, all_target(), true);
    fake.world.borrow_mut().route = "shop.example.test {\n    respond edited\n}\n".into();
    assert!(matches!(reconcile(&fx, &fake), Recovery::Attention(_)));
    assert!(fake.route().contains("respond edited"));
    assert!(
        fake.world.borrow().new_exec,
        "the target is kept while the route is unknown"
    );
    assert_eq!(fx.journals().len(), 1);
}

#[test]
fn a_live_migration_is_left_alone() {
    let fx = Fx::new();
    let fake = Fake::new(RouteKind::Live);
    killed(&fx, &fake, Phase::Cutover, all_target(), true);
    let scope = fx.scope();
    let _held = lock::acquire(
        &scope,
        &rel("locks/mutation.lock"),
        RequestId::parse("123e4567-e89b-12d3-a456-426614174077").unwrap(),
    )
    .unwrap();
    assert_eq!(reconcile(&fx, &fake), Recovery::Busy);
    assert!(fake.log().is_empty());
}

#[test]
fn the_route_is_retargeted_line_by_line() {
    let new = retarget_route(ROUTE, &runtime("php84")).unwrap();
    assert_eq!(
        new,
        ROUTE
            .replace("runtime-php83:80", "runtime-php84:80")
            .replace("X-WCP-Runtime-ID php83", "X-WCP-Runtime-ID php84")
            .replace("runtime_id php83", "runtime_id php84")
    );
    let plain = "a.test {\n    reverse_proxy runtime-php83:80\n}";
    assert_eq!(
        retarget_route(plain, &runtime("php84")).unwrap(),
        "a.test {\n    reverse_proxy runtime-php84:80\n}"
    );
    assert!(retarget_route("a.test {\n}\n", &runtime("php84")).is_none());
    assert_eq!(runtime_of_route(ROUTE), Some(runtime("php83")));
    assert_eq!(
        runtime_of_route("a.test {\n    reverse_proxy 127.0.0.1:80\n}"),
        None
    );
}

/// The route the panel itself writes (`build_ingress_route_caddyfile`), with a
/// ban import, request headers and basic auth added on top.
#[test]
fn the_panels_own_route_is_retargeted_keeping_everything_else() {
    let route = "shop.example.test {\n    import /etc/wcp/ingress.d/bans/bans.caddy\n    basic_auth {\n        staging $2b$hash\n    }\n    reverse_proxy runtime-fp1-php83:80 {\n        header_up X-Request-ID {http.request.uuid}\n        header_up X-WCP-Runtime-ID fp1-php83\n        header_down X-Request-ID {http.request.uuid}\n    }\n    log_append request_id {http.request.uuid}\n    log_append domain shop.example.test\n    log_append runtime_id fp1-php83\n}\n";
    let new = retarget_route(route, &runtime("fp1-php85")).unwrap();
    assert!(new.contains("reverse_proxy runtime-fp1-php85:80 {"));
    assert!(new.contains("header_up X-WCP-Runtime-ID fp1-php85"));
    assert!(new.contains("log_append runtime_id fp1-php85"));
    assert!(!new.contains("fp1-php83"));
    for kept in [
        "import /etc/wcp/ingress.d/bans/bans.caddy",
        "staging $2b$hash",
        "header_down X-Request-ID",
        "log_append domain shop.example.test",
    ] {
        assert!(new.contains(kept), "{kept}");
    }
    assert_eq!(runtime_of_route(route), Some(runtime("fp1-php83")));
}

#[test]
fn a_configured_health_check_goes_over_http_to_a_pool_and_https_to_the_ingress() {
    let check = HealthCheck {
        path: "/health?full=1".into(),
        expected_status: 200,
        expected_body: None,
    };
    let pool = health_curl_args("runtime-fp1-php85", &domain(), &check, "__M__");
    assert_eq!(&pool[..4], ["exec", "-T", "runtime-fp1-php85", "curl"]);
    assert!(pool.contains(&format!("Host: {DOMAIN}")));
    assert!(pool.contains(&"http://127.0.0.1/health?full=1".to_owned()));
    assert!(pool.contains(&"__M__%{http_code}".to_owned()));
    assert!(!pool.iter().any(|a| a == "--resolve"));

    let ingress = health_curl_args("ingress", &domain(), &check, "__M__");
    assert!(ingress.contains(&"--resolve".to_owned()));
    assert!(ingress.contains(&format!("{DOMAIN}:443:127.0.0.1")));
    assert!(ingress.contains(&format!("https://{DOMAIN}/health?full=1")));
    assert!(!ingress.iter().any(|a| a.starts_with("Host:")));
}

#[test]
fn the_health_body_is_compared_exactly_and_the_status_is_read_from_the_end() {
    let check = HealthCheck {
        path: "/h".into(),
        expected_status: 204,
        expected_body: Some("ok\n".into()),
    };
    assert!(check_health("ok\n__M__204", "__M__", &check).is_ok());
    assert!(check_health("ok__M__204", "__M__", &check).is_err());
}

#[test]
fn a_health_check_needs_the_expected_status_and_body() {
    let check = HealthCheck {
        path: "/health".into(),
        expected_status: 200,
        expected_body: Some("ok".into()),
    };
    assert!(check_health("okMARK200", "MARK", &check).is_ok());
    assert!(check_health("okMARKxyz", "MARK", &check).is_err_and(|e| e.contains("invalid")));
    assert!(check_health("okMARK", "MARK", &check).is_err());
    assert!(check_health("ok", "MARK", &check).is_err());
    assert!(check_health("nopeMARK200", "MARK", &check).is_err_and(|e| e.contains("content")));
    assert!(check_health("okMARK503", "MARK", &check).is_err_and(|e| e.contains("503")));
    let bare = HealthCheck {
        expected_body: None,
        ..check
    };
    assert!(check_health("anythingMARK200", "MARK", &bare).is_ok());
}

#[test]
fn the_request_is_validated() {
    let parse = |t: &str, p: Option<&str>, s: Option<u16>, b: Option<&str>| {
        Request::parse(DOMAIN, t, p, s, b, false, ID, None)
    };
    assert!(parse("php84", None, None, None).is_ok());
    assert!(parse("php84", Some("/health"), Some(200), Some("ok")).is_ok());
    assert_eq!(
        parse("php84", Some("/h"), None, None)
            .unwrap()
            .health
            .unwrap()
            .expected_status,
        200
    );
    assert_eq!(
        parse("PHP", None, None, None).err(),
        Some(RequestError::InvalidRuntimeId)
    );
    assert_eq!(
        parse("php84", Some("//evil"), None, None).err(),
        Some(RequestError::InvalidHealthPath)
    );
    assert_eq!(
        parse("php84", Some("x"), None, None).err(),
        Some(RequestError::InvalidHealthPath)
    );
    assert_eq!(
        parse("php84", Some("/a#b"), None, None).err(),
        Some(RequestError::InvalidHealthPath)
    );
    assert_eq!(
        parse("php84", Some("/a\nb"), None, None).err(),
        Some(RequestError::InvalidHealthPath)
    );
    assert_eq!(
        parse("php84", Some("/h"), Some(99), None).err(),
        Some(RequestError::InvalidHealthStatus)
    );
    assert_eq!(
        parse("php84", None, Some(200), None).err(),
        Some(RequestError::IncompleteHealthCheck)
    );
    assert_eq!(
        Request::parse("Bad Domain", "php84", None, None, None, false, ID, None).err(),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        Request::parse(DOMAIN, "php84", None, None, None, false, "nope", None).err(),
        Some(RequestError::InvalidRequestId)
    );
}
