use crate::{
    cli::SecurityCommand,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    security_baseline::{self, Op},
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
        SecurityCommand::BaselineCapture {
            request_file,
            request_id,
            idempotency_key,
        } => baseline(
            Op::Capture,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SecurityCommand::BaselineCompare {
            request_file,
            request_id,
        } => baseline(Op::Compare, &request_file, &request_id, None),
        SecurityCommand::BaselineAccept {
            request_file,
            request_id,
            idempotency_key,
        } => baseline(
            Op::Accept,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SecurityCommand::BaselinePrune {
            request_file,
            request_id,
            idempotency_key,
        } => baseline(
            Op::Prune,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
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

fn baseline(
    op: Op,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = match op {
        Op::Capture => security_baseline::CAPTURE,
        Op::Compare => security_baseline::COMPARE,
        Op::Accept => security_baseline::ACCEPT,
        Op::Prune => security_baseline::PRUNE,
    };
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let Ok(config) = EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) else {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        };
        let Ok(json) = crate::commands::read_root_owned_content_file(path) else {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            ));
        };
        let request =
            match security_baseline::Request::parse(op, &json, request_id, idempotency_key) {
                Ok(request) => request,
                Err(_) => {
                    return Ok(Response::failure(
                        operation,
                        ErrorCode::InvalidInput,
                        "request-file is not a valid baseline request",
                    ));
                }
            };
        let content_roots: Vec<std::path::PathBuf> = config
            .content_roots
            .iter()
            .filter_map(|root| std::fs::canonicalize(root.as_path()).ok())
            .collect();
        let Ok(state) = ManagedRoot::open(&config.state_root) else {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        };
        let context = security_baseline::Context {
            engine_state: &state,
            content_roots,
            limits: security_baseline::scan::Limits::DEFAULT,
        };
        let result = match op {
            Op::Capture => security_baseline::capture(&context, &request),
            Op::Compare => security_baseline::compare(&context, &request),
            Op::Accept => security_baseline::accept(&context, &request),
            Op::Prune => security_baseline::prune(&context, &request),
        };
        match result {
            Ok(value) | Err(security_baseline::Error::PostCommit { result: value }) => {
                Response::success(operation, value)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "security baselines require a Unix host",
        ))
    }
}
