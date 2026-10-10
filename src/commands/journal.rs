use crate::{
    cli::JournalCommand,
    protocol::{Response, ResponseBuildError},
};

#[cfg(unix)]
use crate::{
    config::EngineConfig,
    error::ErrorCode,
    filesystem::ManagedRoot,
    journal::{self, JournalError, JournalResult, NewEntry, Query, RawEntry, Source},
    transaction::{IdempotencyKey, RequestId},
};

pub fn run(command: JournalCommand) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        match command {
            JournalCommand::Append {
                actor,
                action,
                result,
                site,
                operation_id,
                target,
                error_code,
                summary,
                request_id,
                idempotency_key,
            } => append(
                RawEntry {
                    actor: &actor,
                    action: &action,
                    result: &result,
                    site: site.as_deref(),
                    operation_id: operation_id.as_deref(),
                    target: target.as_deref(),
                    error_code: error_code.as_deref(),
                    summary: summary.as_deref(),
                },
                &request_id,
                idempotency_key.as_deref(),
            ),
            JournalCommand::List {
                site,
                since,
                action_prefix,
                result,
                source,
                limit,
                before_seq,
            } => list(&result, &source, {
                Query {
                    site,
                    since_unix_secs: since,
                    action_prefix,
                    result: None,
                    source: None,
                    limit,
                    before_seq,
                }
            }),
        }
    }
    #[cfg(not(unix))]
    {
        let operation = command.operation();
        Ok(Response::failure(
            operation,
            crate::error::ErrorCode::UnsupportedPlatform,
            "journal operations require a Unix host",
        ))
    }
}

#[cfg(unix)]
fn state_root(operation: &'static str) -> Result<ManagedRoot, Response> {
    let fail = |message: &str| Response::failure(operation, ErrorCode::Internal, message);
    let config =
        EngineConfig::load_root_owned(std::path::Path::new("/etc/operations-engine/config.json"))
            .map_err(|_| fail(crate::commands::CONFIG_UNAVAILABLE_MESSAGE))?;
    ManagedRoot::open(&config.state_root).map_err(|_| fail("engine state root is unavailable"))
}

#[cfg(unix)]
fn journal_failure(operation: &'static str, error: JournalError) -> Response {
    match error {
        JournalError::Busy => Response::failure(
            operation,
            ErrorCode::Conflict,
            "the change journal is busy; retry",
        ),
        JournalError::Io => Response::failure(
            operation,
            ErrorCode::Internal,
            "the change journal is unavailable",
        ),
    }
}

#[cfg(unix)]
fn append(
    raw: RawEntry<'_>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = journal::APPEND_OPERATION;
    let invalid = |message: &str| {
        Ok(Response::failure(
            operation,
            ErrorCode::InvalidInput,
            message,
        ))
    };
    let Ok(request_id) = RequestId::parse(request_id) else {
        return invalid("request-id is not a canonical UUID");
    };
    let key = match key.map(IdempotencyKey::parse).transpose() {
        Ok(key) => key,
        Err(_) => return invalid("idempotency-key is invalid"),
    };
    let entry = match NewEntry::parse(raw) {
        Ok(entry) => entry,
        Err(rejected) => return invalid(rejected.message()),
    };
    let state = match state_root(operation) {
        Ok(state) => state,
        Err(response) => return Ok(response),
    };
    match journal::append(
        &state,
        &entry,
        request_id,
        key.as_ref(),
        Source::Api,
        journal::unix_now_secs(),
    ) {
        Ok(outcome) => Response::success(operation, outcome),
        Err(error) => Ok(journal_failure(operation, error)),
    }
}

#[cfg(unix)]
fn list(
    result: &Option<String>,
    source: &Option<String>,
    mut query: Query,
) -> Result<Response, ResponseBuildError> {
    let operation = journal::LIST_OPERATION;
    let invalid = |message: &str| {
        Ok(Response::failure(
            operation,
            ErrorCode::InvalidInput,
            message,
        ))
    };
    if let Some(value) = result {
        match JournalResult::parse(value) {
            Some(parsed) => query.result = Some(parsed),
            None => return invalid("result is invalid"),
        }
    }
    if let Some(value) = source {
        match Source::parse(value) {
            Some(parsed) => query.source = Some(parsed),
            None => return invalid("source is invalid"),
        }
    }
    if let Err(rejected) = query.validate() {
        return invalid(rejected.message());
    }
    let state = match state_root(operation) {
        Ok(state) => state,
        Err(response) => return Ok(response),
    };
    match journal::list(&state, &query) {
        Ok(outcome) => Response::success(operation, outcome),
        Err(error) => Ok(journal_failure(operation, error)),
    }
}
