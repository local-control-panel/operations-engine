use serde::Serialize;

use crate::protocol::{Response, ResponseBuildError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResult {
    operations: &'static [&'static str],
    output_formats: [&'static str; 1],
    features: Features,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Features {
    json_lines_progress: bool,
    cancellation: bool,
    mutations: bool,
    /// The `ops-engine agent <sub>` helper commands this engine has.
    agent_helpers: &'static [&'static str],
    /// `site.changeLog.append`/`list` exist and the engine journals its own
    /// `engine.*` and `site.deploy`/`rollback`/`renameManifest`/`unenroll`
    /// operations (`source: "engine"`).
    change_log: bool,
    /// The `cms` values `site.adminUsers`/`site.adminLogin` accept. Clients
    /// show the one-time login only for a listed CMS; an engine without this
    /// field supports WordPress only.
    admin_login_cms: &'static [&'static str],
    /// `wordpress.clone` accepts `stagingDefaults` (a closed list of safety
    /// settings applied to the copy). Without this field the engine rejects
    /// the key, so clients send it only when this is true.
    clone_staging_defaults: bool,
    /// `drupal.updateDb` backs the database up first and wraps the run in
    /// maintenance mode, restoring the previous mode afterwards. Clients may
    /// then drop their own reminder to back up.
    drupal_update_db_safety: bool,
    /// `wordpress.rotateDebugLog` accepts `--compress` (gzip of the rotated
    /// copy). An engine without this field rejects the flag.
    debug_log_gzip: bool,
    content_recovery_evidence: bool,
    /// The sensitive-path catalog `ingress.applyAdminPaths` accepts, per site
    /// kind. Absent on an engine without the operation.
    admin_paths: Vec<AdminPathsKind>,
    /// `ingress.applyAdminPaths` accepts an allowlist and Basic auth together
    /// and a `rateLimit` (enforced by the brute-force guard agent). Without
    /// this field it takes exactly one `mode`.
    admin_paths_combined: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminPathsKind {
    kind: &'static str,
    paths: Vec<AdminPathsEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminPathsEntry {
    id: &'static str,
    patterns: &'static [&'static str],
    public_exceptions: &'static [&'static str],
}

fn admin_paths_catalog() -> Vec<AdminPathsKind> {
    crate::ingress::admin_paths::CATALOG
        .iter()
        .map(|kind| AdminPathsKind {
            kind: kind.kind,
            paths: kind
                .entries
                .iter()
                .map(|entry| AdminPathsEntry {
                    id: entry.id,
                    patterns: entry.paths,
                    public_exceptions: entry.except,
                })
                .collect(),
        })
        .collect()
}

/// Every protocol operation this engine implements, as `capabilities`
/// reports them. Agents' `requires_ops` are checked against this list.
pub const OPERATIONS: &[&str] = &[
    "version",
    "capabilities",
    "doctor",
    "operation.status",
    "operation.resourceStatus",
    "operation.list",
    "operation.incomplete",
    "backup.delete",
    "backup.importRemote",
    "backup.installRclone",
    "backup.createDatabase",
    "backup.scheduleDatabase",
    "backup.unscheduleDatabase",
    "backup.listScheduledDatabase",
    "backup.runScheduledDatabase",
    "backup.activateConfig",
    "backup.triggerNow",
    "site.list",
    "site.deploy",
    "site.recoverDeployment",
    "site.create",
    "site.recoverCreate",
    "site.publishStatic",
    "site.staticStatus",
    "site.recoverStatic",
    "site.rollback",
    "site.moveRoot",
    "site.prepareRoot",
    "site.removeRoot",
    "site.releaseRoot",
    "site.renameManifest",
    "site.enroll",
    "site.unenroll",
    "site.allocateIdentity",
    "site.releaseIdentity",
    "site.updateIdentity",
    "site.renameIdentity",
    "engine.install",
    "engine.rollback",
    "ingress.activateConfig",
    "ingress.park",
    "ingress.unpark",
    "ingress.removeRoute",
    "ingress.setEnabled",
    "ingress.applyBans",
    "ingress.applyAdminPaths",
    "ingress.reconcile",
    "runtime.activateConfig",
    "runtime.removeConfig",
    "runtime.reconcile",
    "cron.installTab",
    "db.restore",
    "db.restoreProtected",
    "db.restoreRecoveryInfo",
    "db.recoverRestore",
    "db.export",
    "db.provisionMariaDb",
    "db.dropMariaDb",
    "db.dropMariaDbUser",
    "db.clearMariaSlowLog",
    "db.configureMariaSlowLog",
    "db.deleteValkeyKey",
    "db.flushValkeyDb",
    "db.flushAllValkey",
    "db.provisionValkeySite",
    "db.revokeValkeySite",
    "db.flushValkeySite",
    "db.renameValkeySite",
    "db.provisionPostgres",
    "db.dropPostgres",
    "db.provisionPostgresUser",
    "db.dropPostgresUser",
    "dbTool.converge",
    "dbTool.remove",
    "compose.activateConfig",
    "meilisearch.upgrade",
    "meilisearch.cleanup",
    "permissions.fixOwnership",
    "permissions.fixWorldWritable",
    "wordpress.cleanup",
    "wordpress.install",
    "wordpress.import",
    "wordpress.clone",
    "joomla.clone",
    "drupal.clone",
    "wordpress.migrateExport",
    "wordpress.migrateDiscard",
    "wordpress.migrateImport",
    "wordpress.updateCore",
    "wordpress.updatePlugins",
    "wordpress.updateThemes",
    "wordpress.rotateCredentials",
    "wordpress.multisiteDeleteSite",
    "wordpress.dropTables",
    "wordpress.boundedAction",
    // The typed replacements for free-form `wp:cli` mutations
    // (cache/rewrite flush, salts, cron, config flags,
    // maintenance, users, search-replace, site URL, plugin
    // install), carried by `wordpress.boundedAction`.
    "wordpress.typedActions",
    "wordpress.setSmtpRelay",
    "wordpress.rotateDebugLog",
    "cms.clearCache",
    "cms.maintenance",
    "cms.safeMode",
    "drupal.automatedCron",
    "drupal.cacheRebuild",
    "drupal.cronRun",
    "drupal.installDrush",
    "drupal.maintenance",
    "drupal.updateDb",
    "drupal.watchdog",
    "tool.install",
    "tool.remove",
    "tool.status",
    "agent.activateBruteforceConfig",
    "agent.install",
    "agent.installFromRegistry",
    "agent.approve",
    "agent.unapprove",
    "agent.remove",
    "agent.bruteforceUnban",
    "agent.run",
    "agent.configure",
    "system.activateAutoupdatesConfig",
    "system.installAutoupdates",
    "system.installDocker",
    "system.startDocker",
    "system.signalProcess",
    "system.createSwap",
    "system.deleteSwap",
    "system.resizeSwap",
    "stack.deploy",
    "stack.reloadCaddy",
    "stack.stopIdleRuntime",
    "stack.ensureRuntime",
    "stack.reloadWorkers",
    "stack.flushFpc",
    "stack.writeSiteService",
    "stack.activateSiteConfig",
    "stack.removeSiteService",
    "docker.prune",
    "docker.containerAction",
    "docker.setLimits",
    "docker.network",
    "docker.imagePull",
    "docker.imageRemove",
    "docker.volumeRemove",
    "site.writeEnvFile",
    "site.quarantineFile",
    "site.phpInfoSession",
    "site.probe",
    "site.setErrorPages",
    "site.exportArchive",
    "site.importArchive",
    "site.discardArchive",
    "site.reconcile",
    "site.recoverContent",
    "site.migrateRuntime",
    "system.service",
    "compose.action",
    "compose.remove",
    "site.changeLog.append",
    "site.changeLog.list",
    "site.adminUsers",
    "site.adminLogin",
];

/// CMS kinds the one-time admin login supports.
pub const ADMIN_LOGIN_CMS: &[&str] = &["wordpress", "joomla", "drupal"];

pub fn run() -> Result<Response, ResponseBuildError> {
    Response::success(
        "capabilities",
        CapabilitiesResult {
            operations: OPERATIONS,
            output_formats: ["json"],
            features: Features {
                json_lines_progress: false,
                cancellation: false,
                mutations: true,
                agent_helpers: crate::agent_lifecycle::AGENT_HELPERS,
                change_log: cfg!(unix),
                admin_login_cms: ADMIN_LOGIN_CMS,
                clone_staging_defaults: true,
                drupal_update_db_safety: true,
                debug_log_gzip: true,
                content_recovery_evidence: true,
                admin_paths: admin_paths_catalog(),
                admin_paths_combined: true,
            },
        },
    )
}
