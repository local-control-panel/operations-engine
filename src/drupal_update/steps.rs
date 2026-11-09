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
//! `WCP_FAILPOINT=drupal-update-after-<step>` (failpoints feature).

use super::{Context, now, rel};
use crate::transaction::RequestId;
use serde::{Deserialize, Serialize};

const MAX_STEPS: usize = 32;
const MAX_JOURNAL_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Step {
    /// The recovery bundle is complete (manifest written).
    Bundled,
    MaintenanceOn,
    ComposerDone,
    DatabaseUpdated,
    /// The health probe after the update passed.
    Probed,
    /// The update ended well and maintenance is back to its earlier state.
    Finished,
    RollbackStarted,
    FilesRestored,
    DatabaseRestored,
    /// The rollback ended and its probe passed.
    RolledBack,
}

impl Step {
    fn failpoint(self) -> &'static str {
        match self {
            Self::Bundled => "drupal-update-after-bundled",
            Self::MaintenanceOn => "drupal-update-after-maintenance-on",
            Self::ComposerDone => "drupal-update-after-composer-done",
            Self::DatabaseUpdated => "drupal-update-after-database-updated",
            Self::Probed => "drupal-update-after-probed",
            Self::Finished => "drupal-update-after-finished",
            Self::RollbackStarted => "drupal-update-after-rollback-started",
            Self::FilesRestored => "drupal-update-after-files-restored",
            Self::DatabaseRestored => "drupal-update-after-database-restored",
            Self::RolledBack => "drupal-update-after-rolled-back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub step: Step,
    pub at_unix_secs: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    pub version: u32,
    pub steps: Vec<Entry>,
}

fn path(id: RequestId) -> crate::site::SiteRelativePath {
    rel(format!("drupal-updates/{id}/steps.json"))
}

/// The journal of an update; an absent or unreadable one is `None`.
fn load(ctx: &Context<'_>, id: RequestId) -> Option<Journal> {
    let text = ctx.backup_root.read_to_string(&path(id)).ok()?;
    if text.len() > MAX_JOURNAL_BYTES {
        return None;
    }
    serde_json::from_str(&text).ok()
}

/// Appends `step` to the journal of update `id`, then hits the step's
/// failpoint. Errors are ignored: the journal is diagnostic.
pub fn record(ctx: &Context<'_>, id: RequestId, step: Step) {
    let mut journal = load(ctx, id).unwrap_or_default();
    journal.version = 1;
    if journal.steps.len() < MAX_STEPS {
        journal.steps.push(Entry {
            step,
            at_unix_secs: now(),
        });
        if let Ok(bytes) = serde_json::to_vec(&journal) {
            let _ = ctx.backup_root.write_atomic(&path(id), &bytes);
        }
    }
    crate::failpoint::hit(step.failpoint());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_round_trips_and_names_steps_in_camel_case() {
        let journal = Journal {
            version: 1,
            steps: vec![Entry {
                step: Step::DatabaseUpdated,
                at_unix_secs: 7,
            }],
        };
        let text = serde_json::to_string(&journal).unwrap();
        assert_eq!(
            text,
            r#"{"version":1,"steps":[{"step":"databaseUpdated","atUnixSecs":7}]}"#
        );
        let back: Journal = serde_json::from_str(&text).unwrap();
        assert_eq!(back.steps[0].step, Step::DatabaseUpdated);
    }
}
