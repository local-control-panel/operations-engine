//! A diagnostic journal of how far one Drupal update got, so an interrupted
//! update can be told apart from one that never started changing anything.
//!
//! `drupal-updates/<request id>/steps.json` in the backup root lists each
//! step reached, with the time. It holds step names only: no paths, tool
//! output or secrets. Writing it is best effort and never fails an update; it
//! only informs the decision a later request makes about an interrupted
//! update, it is not the recovery data (the bundle is).
//!
//! After a step is written the process may be killed on purpose in tests:
//! `WCP_FAILPOINT=drupal-update-after-<step>` (failpoints feature). The steps are the
//! shared ones of `update_steps`.

use super::{Context, now, rel};
use crate::transaction::RequestId;
pub use crate::update_steps::{Journal, Step};

fn path(id: RequestId) -> crate::site::SiteRelativePath {
    rel(format!("drupal-updates/{id}/steps.json"))
}

/// The journal of an update; an absent or unreadable one is `None`.
pub(super) fn load(ctx: &Context<'_>, id: RequestId) -> Option<Journal> {
    Journal::parse(&ctx.backup_root.read_to_string(&path(id)).ok()?)
}

/// Appends `step` to the journal of update `id`, then hits the step's
/// failpoint. Errors are ignored: the journal is diagnostic.
pub fn record(ctx: &Context<'_>, id: RequestId, step: Step) {
    let journal = load(ctx, id).unwrap_or_default();
    if let Some(bytes) = journal.with_step(step, now()) {
        let _ = ctx.backup_root.write_atomic(&path(id), &bytes);
    }
    crate::failpoint::hit(&step.failpoint("drupal"));
}
