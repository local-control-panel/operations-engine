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
                "backup.delete",
                "backup.createDatabase",
                "backup.activateConfig",
                "backup.triggerNow",
                "site.deploy",
                "site.rollback",
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
                "wordpress.updateCore",
                "wordpress.updatePlugins",
                "wordpress.updateThemes",
                "agent.activateBruteforceConfig",
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
