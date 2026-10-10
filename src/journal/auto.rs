//! The engine journals its own mutating operations, best effort.
//!
//! Only operations whose identity is fully known from the command line
//! (a `--request-id` and, where the operation is site-scoped, a canonical
//! `--site-id`) are wired: nothing is parsed out of request files and no
//! response body is read. A failed journal write never changes the
//! operation's response. Entries carry `source: "engine"`, `actor:
//! "engine"` and the operation's request id as both entry id and
//! `operationId`; a replayed request finds its entry already there.
//!
//! Wired: `site.deploy`, `site.rollback`, `site.renameManifest`,
//! `site.unenroll`, `engine.install`, `engine.rollback`. Every other
//! mutating operation is listed in `docs/protocol.md` ("Change journal") as
//! a follow-up: they take a request file or a domain instead of a site id,
//! and need their own cheap, secret-free way to name the site.

use crate::{
    cli::{Command, EngineCommand, SiteCommand},
    error::ErrorCode,
    filesystem::ManagedRoot,
    protocol::Response,
    site::SiteId,
    transaction::{IdempotencyKey, RequestId},
};

use super::{JournalResult, NewEntry, RawEntry, Source};

#[derive(Debug, Eq, PartialEq)]
pub struct Plan {
    pub action: &'static str,
    pub site: Option<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

/// What to journal for `command`, or `None` when it is not wired (or its
/// identity is not valid, in which case the operation rejects it anyway).
pub fn plan(command: &Command) -> Option<Plan> {
    let (action, site, request_id, key) = match command {
        Command::Site { command } => match command {
            SiteCommand::Deploy {
                site_id,
                request_id,
                idempotency_key,
                ..
            } => ("site.deploy", Some(site_id), request_id, idempotency_key),
            SiteCommand::Rollback {
                site_id,
                request_id,
                idempotency_key,
                ..
            } => ("site.rollback", Some(site_id), request_id, idempotency_key),
            SiteCommand::RenameManifest {
                site_id,
                request_id,
                idempotency_key,
                ..
            } => (
                "site.renameManifest",
                Some(site_id),
                request_id,
                idempotency_key,
            ),
            SiteCommand::Unenroll {
                site_id,
                request_id,
                idempotency_key,
            } => ("site.unenroll", Some(site_id), request_id, idempotency_key),
            _ => return None,
        },
        Command::Engine { command } => match command {
            EngineCommand::Install {
                request_id,
                idempotency_key,
                ..
            } => ("engine.install", None, request_id, idempotency_key),
            EngineCommand::Rollback {
                request_id,
                idempotency_key,
            } => ("engine.rollback", None, request_id, idempotency_key),
        },
        _ => return None,
    };
    let site = match site {
        Some(site) => Some(SiteId::parse(site).ok()?.to_string()),
        None => None,
    };
    Some(Plan {
        action,
        site,
        request_id: RequestId::parse(request_id).ok()?,
        idempotency_key: key
            .as_deref()
            .map(IdempotencyKey::parse)
            .transpose()
            .ok()?,
    })
}

/// The journal entry for `plan` given the operation's outcome. `None` when
/// the request never reached the operation (invalid input).
pub fn entry(plan: &Plan, response: &Response) -> Option<NewEntry> {
    let (result, error_code) = if response.ok {
        (JournalResult::Ok, None)
    } else {
        let code = response.error.as_ref().map(|error| error.code);
        if code == Some(ErrorCode::InvalidInput) {
            return None;
        }
        let name = code
            .and_then(|code| serde_json::to_value(code).ok())
            .and_then(|value| value.as_str().map(str::to_owned));
        (JournalResult::Failed, name)
    };
    let operation_id = plan.request_id.to_string();
    NewEntry::parse(RawEntry {
        actor: "engine",
        action: plan.action,
        result: match result {
            JournalResult::Ok => "ok",
            _ => "failed",
        },
        site: plan.site.as_deref(),
        operation_id: Some(&operation_id),
        error_code: error_code.as_deref(),
        ..RawEntry::default()
    })
    .ok()
}

/// Writes the entry below `state`. Errors are returned for tests; the
/// production caller [`record`] ignores them.
pub fn write(
    state: &ManagedRoot,
    plan: &Plan,
    response: &Response,
    now: u64,
) -> Result<(), super::JournalError> {
    let Some(entry) = entry(plan, response) else {
        return Ok(());
    };
    super::append(
        state,
        &entry,
        plan.request_id,
        plan.idempotency_key.as_ref(),
        Source::Engine,
        now,
    )
    .map(|_| ())
}

/// Best-effort production hook, called by `lib::execute` after the
/// operation ran.
pub fn record(plan: &Plan, response: &Response) {
    let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
        "/etc/operations-engine/config.json",
    )) else {
        return;
    };
    let Ok(state) = ManagedRoot::open(&config.state_root) else {
        return;
    };
    let _ = write(&state, plan, response, super::unix_now_secs());
}
