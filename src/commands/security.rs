use crate::{
    cli::SecurityCommand,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    security_feed,
};

pub fn run(command: SecurityCommand) -> Result<Response, ResponseBuildError> {
    match command {
        SecurityCommand::SetPolicy { mode, request_id } => {
            let mode = match mode.as_str() {
                "off" => security_feed::Mode::Off,
                "check-only" => security_feed::Mode::CheckOnly,
                _ => {
                    return Ok(Response::failure(
                        security_feed::SET_POLICY,
                        ErrorCode::InvalidInput,
                        "mode must be off or check-only",
                    ));
                }
            };
            mutate(security_feed::SET_POLICY, &request_id, |state, id| {
                security_feed::set_policy(state, mode, id).map(|()| {
                    let timer = crate::security_timer::sync(
                        mode == security_feed::Mode::CheckOnly,
                        std::path::Path::new(crate::security_timer::UNIT_DIR),
                        std::path::Path::new(crate::security_timer::RUN_DIR),
                        "systemctl",
                    );
                    serde_json::json!({
                        "mode": if mode == security_feed::Mode::Off { "off" } else { "checkOnly" },
                        "timer": timer.name(),
                    })
                })
            })
        }
        SecurityCommand::Refresh { request_id } => {
            mutate(security_feed::REFRESH, &request_id, |state, id| {
                security_feed::refresh(
                    state,
                    &security_feed::Http,
                    &security_feed::origin_from_env(),
                    security_feed::now_unix(),
                    id,
                )
                .map(|result| serde_json::to_value(result).unwrap())
            })
        }
        SecurityCommand::Status => with_state(security_feed::STATUS, |state| {
            Response::success(
                security_feed::STATUS,
                security_feed::status(state, security_feed::now_unix()),
            )
        }),
        SecurityCommand::Affected => with_state(security_feed::AFFECTED, |state| {
            let status = security_feed::status(state, security_feed::now_unix());
            let (rules, skipped) = status.accepted.as_ref().map_or((Vec::new(), 0), |a| {
                (a.image_rules.clone(), a.skipped_rules)
            });
            Response::success(
                security_feed::AFFECTED,
                crate::security_affected::evaluate(
                    &crate::security_affected::Docker { program: "docker" },
                    &rules,
                    skipped,
                    status.freshness,
                ),
            )
        }),
        SecurityCommand::History { limit } => with_state(security_feed::HISTORY, |state| {
            Response::success(
                security_feed::HISTORY,
                security_feed::history(
                    state,
                    limit.unwrap_or(security_feed::DEFAULT_HISTORY_LIMIT),
                ),
            )
        }),
    }
}

fn with_state(
    operation: &'static str,
    f: impl FnOnce(&crate::filesystem::ManagedRoot) -> Result<Response, ResponseBuildError>,
) -> Result<Response, ResponseBuildError> {
    use crate::{config::EngineConfig, filesystem::ManagedRoot};
    let Ok(config) =
        EngineConfig::load_root_owned(std::path::Path::new("/etc/operations-engine/config.json"))
    else {
        return Ok(Response::failure(
            operation,
            ErrorCode::Internal,
            crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
        ));
    };
    let Ok(state) = ManagedRoot::open(&config.state_root) else {
        return Ok(Response::failure(
            operation,
            ErrorCode::Internal,
            "engine state root is unavailable",
        ));
    };
    f(&state)
}

fn mutate(
    operation: &'static str,
    request_id: &str,
    f: impl FnOnce(
        &crate::filesystem::ManagedRoot,
        crate::transaction::RequestId,
    ) -> Result<serde_json::Value, security_feed::Error>,
) -> Result<Response, ResponseBuildError> {
    let Ok(id) = crate::transaction::RequestId::parse(request_id) else {
        return Ok(Response::failure(
            operation,
            ErrorCode::InvalidInput,
            "request-id is invalid",
        ));
    };
    with_state(operation, |state| match f(state, id) {
        Ok(value) => Response::success(operation, value),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(operation, code, &message))
        }
    })
}
