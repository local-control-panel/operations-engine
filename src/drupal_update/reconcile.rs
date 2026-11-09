//! Completing an update that was interrupted (the engine was killed, the host
//! rebooted, the SSH session dropped).
//!
//! There is no daemon: the next Drupal request for the same project does it,
//! under the project's resource lock and the update scope's mutation lock, so
//! no live update can be mistaken for an interrupted one. Every bundle of
//! this project whose step journal did not end in `finished` or `rolledBack`
//! is rolled back from its recovery bundle, oldest first, and the rollback is
//! always run whole: every part of it (empty the root, extract, empty the
//! database, import) is safe to repeat, which is simpler and safer than
//! remembering where it stopped. The journal only tells whether the update
//! got far enough to need that.
//!
//! A bundle that cannot be rolled back stops the new request with `recovery
//! required` and stays for the next attempt or a manual `restoreUpdate`.

use super::{
    Context, Error, Manifest, RESTORE, rel, rollback,
    steps::{self, Step},
};
use crate::{
    drupal_action,
    error::ErrorCode,
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};

/// More bundles than this in the directory are not scanned.
const MAX_BUNDLES: usize = 512;

/// Rolls back what an earlier request of this project left half done.
/// `current` is the request that asks; `leave` is a bundle that request is
/// about to restore itself.
pub(super) fn reconcile(
    ctx: &Context<'_>,
    base: &drupal_action::Request,
    scope: &ManagedRoot,
    current: RequestId,
    leave: Option<RequestId>,
) -> Result<(), Error> {
    for id in incomplete(ctx, base, scope, current, leave) {
        rollback(ctx, base, id).map_err(|error| {
            Error::RecoveryRequired(format!(
                "an earlier update was interrupted and rolling it back failed ({}); its recovery \
                 bundle {id} is kept",
                error.protocol().1
            ))
        })?;
    }
    close_interrupted(scope, current, leave);
    Ok(())
}

/// Ids of this project's bundles that need a rollback, oldest first.
fn incomplete(
    ctx: &Context<'_>,
    base: &drupal_action::Request,
    scope: &ManagedRoot,
    current: RequestId,
    leave: Option<RequestId>,
) -> Vec<RequestId> {
    let Ok(entries) = std::fs::read_dir(ctx.backup_path.join("drupal-updates")) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten().take(MAX_BUNDLES) {
        let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|name| RequestId::parse(name).ok())
        else {
            continue;
        };
        if id == current || Some(id) == leave {
            continue;
        }
        let Some(manifest) = ctx
            .backup_root
            .read_to_string(&rel(format!("drupal-updates/{id}/manifest.json")))
            .ok()
            .and_then(|text| serde_json::from_str::<Manifest>(&text).ok())
        else {
            continue;
        };
        if manifest.project_root != base.root().display().to_string() {
            continue;
        }
        let needs_rollback = match steps::load(ctx, id).and_then(|journal| journal.last()) {
            Some(last) => !matches!(last, Step::Finished | Step::RolledBack),
            // Killed between the manifest and the first journal entry, or a
            // bundle from before the journal: only a transaction that never
            // finished says it was interrupted.
            None => transaction_in_progress(scope, id),
        };
        if needs_rollback {
            found.push((manifest.created_at_unix_secs, id));
        }
    }
    found.sort_by_key(|(created, _)| *created);
    found.into_iter().map(|(_, id)| id).collect()
}

fn transaction_path(id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}

fn transaction_in_progress(scope: &ManagedRoot, id: RequestId) -> bool {
    state::load(scope, &transaction_path(id))
        .is_ok_and(|record| record.status == TransactionStatus::InProgress)
}

/// Finishes the records of requests that died, so they stop showing as
/// running and a retry with their key gets a plain answer.
fn close_interrupted(scope: &ManagedRoot, current: RequestId, leave: Option<RequestId>) {
    let Ok(dir) = scope.open_managed_dir(&SiteRelativePath::parse("transactions").unwrap()) else {
        return;
    };
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
    for name in dir.file_names().unwrap_or_default() {
        let Some(id) = name
            .strip_suffix(".json")
            .and_then(|stem| RequestId::parse(stem).ok())
        else {
            continue;
        };
        if id == current || Some(id) == leave {
            continue;
        }
        let Ok(mut record) = state::load(scope, &transaction_path(id)) else {
            continue;
        };
        let ours = [super::CORE, super::PACKAGES, RESTORE].contains(&record.operation.as_str());
        if record.status != TransactionStatus::InProgress || !ours {
            continue;
        }
        let _ = record.mark_failed(
            ErrorCode::Internal,
            "the request was interrupted; a later request brought the site back to a consistent state",
        );
        let _ = state::save(scope, &transaction_path(id), &record);
        let _ = audit::append(
            scope,
            &audit_path,
            &AuditRecord::result(id, false, Some(ErrorCode::Internal)),
        );
    }
}
