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
}

pub fn run() -> Result<Response, ResponseBuildError> {
    Response::success(
        "capabilities",
        CapabilitiesResult {
            operations: &[
                "version",
                "capabilities",
                "doctor",
                "operation.status",
                "operation.list",
                "backup.delete",
                "backup.importRemote",
                "backup.installRclone",
                "backup.createDatabase",
                "backup.activateConfig",
                "backup.triggerNow",
                "site.deploy",
                "site.rollback",
                "site.moveRoot",
                "site.renameManifest",
                "engine.install",
                "engine.rollback",
                "ingress.activateConfig",
                "ingress.park",
                "ingress.unpark",
                "ingress.reconcile",
                "runtime.activateConfig",
                "runtime.reconcile",
                "cron.installTab",
                "db.restore",
                "db.export",
                "db.provisionMariaDb",
                "db.dropMariaDb",
                "db.dropMariaDbUser",
                "db.clearMariaSlowLog",
                "db.configureMariaSlowLog",
                "db.deleteValkeyKey",
                "db.flushValkeyDb",
                "db.flushAllValkey",
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
                "wordpress.migrateExport",
                "wordpress.migrateDiscard",
                "wordpress.migrateImport",
                "wordpress.updateCore",
                "wordpress.updatePlugins",
                "wordpress.updateThemes",
                "wordpress.rotateCredentials",
                "wordpress.multisiteDeleteSite",
                "wordpress.boundedAction",
                // The typed replacements for free-form `wp:cli` mutations
                // (cache/rewrite flush, salts, cron, config flags,
                // maintenance, users, search-replace, site URL, plugin
                // install), carried by `wordpress.boundedAction`.
                "wordpress.typedActions",
                "wordpress.setSmtpRelay",
                "agent.activateBruteforceConfig",
                "system.activateAutoupdatesConfig",
                "system.installAutoupdates",
                "system.installDocker",
                "system.startDocker",
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
            ],
            output_formats: ["json"],
            features: Features {
                json_lines_progress: false,
                cancellation: false,
                mutations: true,
            },
        },
    )
}
