//! The steps of a recovery-first update (Drupal, Joomla) as one type.
//!
//! Each update keeps a diagnostic journal, `<bundles>/<request id>/steps.json`,
//! of how far it got, so a later request can tell an interrupted update from
//! one that never started changing anything. The journal holds step names and
//! times only: no paths, tool output or secrets. It is not the recovery data
//! (the recovery bundle is) and writing it never fails an update.
//!
//! The serialized names are part of what is on disk: a journal written by an
//! earlier engine must still parse, so a name is never changed, only added.
//! After a step is written a test build may kill the process on purpose:
//! `WCP_FAILPOINT=<kind>-update-after-<step in kebab case>` (failpoints
//! feature), see [`Step::failpoint`].

use serde::{Deserialize, Serialize};

pub const MAX_STEPS: usize = 32;
pub const MAX_JOURNAL_BYTES: usize = 8 * 1024;

/// One step reached. Which steps an update uses depends on the CMS: Drupal
/// has `MaintenanceOn`, `ComposerDone` and `DatabaseUpdated`; Joomla has
/// `OfflineOn` and `Updated`. The rest are shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Step {
    /// The recovery bundle is complete (manifest written).
    Bundled,
    /// Drupal: maintenance mode is on.
    MaintenanceOn,
    /// Joomla: the site is offline.
    OfflineOn,
    /// Drupal: Composer finished.
    ComposerDone,
    /// Drupal: `updatedb` finished.
    DatabaseUpdated,
    /// Joomla: `core:update` returned success.
    Updated,
    /// The health probe after the update passed.
    Probed,
    /// The update ended well and the site is back in its earlier mode.
    Finished,
    RollbackStarted,
    FilesRestored,
    DatabaseRestored,
    /// The rollback ended and its probe passed.
    RolledBack,
}

impl Step {
    /// Every step, for tests that must cover them all.
    pub const ALL: [Step; 12] = [
        Self::Bundled,
        Self::MaintenanceOn,
        Self::OfflineOn,
        Self::ComposerDone,
        Self::DatabaseUpdated,
        Self::Updated,
        Self::Probed,
        Self::Finished,
        Self::RollbackStarted,
        Self::FilesRestored,
        Self::DatabaseRestored,
        Self::RolledBack,
    ];

    /// The step name in kebab case, as used in failpoint names.
    pub fn kebab(self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::MaintenanceOn => "maintenance-on",
            Self::OfflineOn => "offline-on",
            Self::ComposerDone => "composer-done",
            Self::DatabaseUpdated => "database-updated",
            Self::Updated => "updated",
            Self::Probed => "probed",
            Self::Finished => "finished",
            Self::RollbackStarted => "rollback-started",
            Self::FilesRestored => "files-restored",
            Self::DatabaseRestored => "database-restored",
            Self::RolledBack => "rolled-back",
        }
    }

    /// `drupal-update-after-composer-done` for `kind = "drupal"`.
    pub fn failpoint(self, kind: &str) -> String {
        format!("{kind}-update-after-{}", self.kebab())
    }

    /// The update is over, one way or the other: nothing is left to roll back.
    pub fn is_final(self) -> bool {
        matches!(self, Self::Finished | Self::RolledBack)
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

impl Journal {
    pub fn last(&self) -> Option<Step> {
        self.steps.last().map(|entry| entry.step)
    }

    /// How far the update got, for a status answer. `None` for an empty
    /// journal: nothing is known then, which is not the same as "no steps".
    pub fn progress(&self) -> Option<Progress> {
        Some(Progress {
            last_step: self.last()?,
            bundle_complete: self.steps.iter().any(|entry| entry.step == Step::Bundled),
        })
    }

    /// Reads a journal; text that is too large or not a journal is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_JOURNAL_BYTES {
            return None;
        }
        serde_json::from_str(text).ok()
    }

    /// The journal with `step` added at `at_unix_secs`, as bytes to write;
    /// `None` when the journal is full or cannot be encoded.
    pub fn with_step(mut self, step: Step, at_unix_secs: u64) -> Option<Vec<u8>> {
        self.version = 1;
        if self.steps.len() >= MAX_STEPS {
            return None;
        }
        self.steps.push(Entry { step, at_unix_secs });
        serde_json::to_vec(&self).ok()
    }
}

/// What `operation.status` adds for an update: the last step in the journal
/// and whether the recovery bundle was complete (`Bundled` reached). Read
/// only; without a readable journal neither field is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub last_step: Step,
    pub bundle_complete: bool,
}

/// The directory below the backup root that holds the step journals of an
/// operation; `None` for an operation that keeps none.
pub fn journal_dir(operation: &str) -> Option<&'static str> {
    match operation {
        "drupal.updateCore" | "drupal.updatePackages" => Some("drupal-updates"),
        "joomla.updateCore" => Some("joomla-updates"),
        _ => None,
    }
}

/// Whether an update whose journal ends in `last` was interrupted and needs a
/// rollback. `None` when there is no journal: the caller decides from the
/// transaction record instead.
pub fn needs_rollback(last: Option<Step>) -> Option<bool> {
    last.map(|step| !step.is_final())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialized name and failpoint suffix of every step: what earlier
    /// engines wrote and what the failpoint tests set. Changing a row breaks
    /// journals on disk.
    const TABLE: [(Step, &str, &str); 12] = [
        (Step::Bundled, "bundled", "bundled"),
        (Step::MaintenanceOn, "maintenanceOn", "maintenance-on"),
        (Step::OfflineOn, "offlineOn", "offline-on"),
        (Step::ComposerDone, "composerDone", "composer-done"),
        (Step::DatabaseUpdated, "databaseUpdated", "database-updated"),
        (Step::Updated, "updated", "updated"),
        (Step::Probed, "probed", "probed"),
        (Step::Finished, "finished", "finished"),
        (Step::RollbackStarted, "rollbackStarted", "rollback-started"),
        (Step::FilesRestored, "filesRestored", "files-restored"),
        (
            Step::DatabaseRestored,
            "databaseRestored",
            "database-restored",
        ),
        (Step::RolledBack, "rolledBack", "rolled-back"),
    ];

    #[test]
    fn names_on_disk_and_failpoints_are_unchanged() {
        assert_eq!(TABLE.len(), Step::ALL.len());
        for (step, serialized, kebab) in TABLE {
            assert!(Step::ALL.contains(&step));
            assert_eq!(
                serde_json::to_string(&step).unwrap(),
                format!("\"{serialized}\"")
            );
            assert_eq!(
                serde_json::from_str::<Step>(&format!("\"{serialized}\"")).unwrap(),
                step
            );
            assert_eq!(step.kebab(), kebab);
            assert_eq!(
                step.failpoint("drupal"),
                format!("drupal-update-after-{kebab}")
            );
            assert_eq!(
                step.failpoint("joomla"),
                format!("joomla-update-after-{kebab}")
            );
        }
    }

    #[test]
    fn the_kebab_name_is_the_serialized_name_in_kebab_case() {
        for step in Step::ALL {
            let serialized: String =
                serde_json::from_str(&serde_json::to_string(&step).unwrap()).unwrap();
            let mut kebab = String::new();
            for c in serialized.chars() {
                if c.is_ascii_uppercase() {
                    kebab.push('-');
                    kebab.push(c.to_ascii_lowercase());
                } else {
                    kebab.push(c);
                }
            }
            assert_eq!(step.kebab(), kebab);
        }
    }

    #[test]
    fn journals_written_by_the_earlier_engines_still_parse() {
        let drupal = r#"{"version":1,"steps":[{"step":"bundled","atUnixSecs":1},{"step":"maintenanceOn","atUnixSecs":2},{"step":"composerDone","atUnixSecs":3},{"step":"databaseUpdated","atUnixSecs":4},{"step":"probed","atUnixSecs":5},{"step":"finished","atUnixSecs":6}]}"#;
        let joomla = r#"{"version":1,"steps":[{"step":"bundled","atUnixSecs":1},{"step":"offlineOn","atUnixSecs":2},{"step":"updated","atUnixSecs":3},{"step":"rollbackStarted","atUnixSecs":4},{"step":"filesRestored","atUnixSecs":5},{"step":"databaseRestored","atUnixSecs":6},{"step":"rolledBack","atUnixSecs":7}]}"#;
        assert_eq!(Journal::parse(drupal).unwrap().last(), Some(Step::Finished));
        assert_eq!(
            Journal::parse(joomla).unwrap().last(),
            Some(Step::RolledBack)
        );
        assert!(
            Journal::parse(r#"{"version":1,"steps":[{"step":"nope","atUnixSecs":1}]}"#).is_none()
        );
        assert!(Journal::parse("{").is_none());
        assert!(Journal::parse(&" ".repeat(MAX_JOURNAL_BYTES + 1)).is_none());
    }

    #[test]
    fn a_step_is_appended_and_the_journal_stays_bounded() {
        let bytes = Journal::default()
            .with_step(Step::DatabaseUpdated, 7)
            .unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"version":1,"steps":[{"step":"databaseUpdated","atUnixSecs":7}]}"#
        );
        let mut journal = Journal::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
        journal.steps = (0..MAX_STEPS)
            .map(|i| Entry {
                step: Step::Bundled,
                at_unix_secs: i as u64,
            })
            .collect();
        assert!(journal.with_step(Step::Probed, 1).is_none());
    }

    #[test]
    fn only_an_update_that_did_not_end_needs_a_rollback() {
        for step in Step::ALL {
            let ended = matches!(step, Step::Finished | Step::RolledBack);
            assert_eq!(needs_rollback(Some(step)), Some(!ended), "{step:?}");
        }
        assert_eq!(needs_rollback(None), None);
    }

    #[test]
    fn failpoint_names_are_unique_per_kind_and_step() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in ["drupal", "joomla"] {
            for step in Step::ALL {
                assert!(seen.insert(step.failpoint(kind)), "{kind} {step:?}");
            }
        }
        assert_eq!(seen.len(), 2 * Step::ALL.len());
    }

    #[test]
    fn progress_names_the_last_step_and_whether_the_bundle_was_complete() {
        assert_eq!(Journal::default().progress(), None);
        let journal = |steps: &[Step]| Journal {
            version: 1,
            steps: steps
                .iter()
                .map(|&step| Entry {
                    step,
                    at_unix_secs: 1,
                })
                .collect(),
        };
        assert_eq!(
            journal(&[Step::Bundled, Step::MaintenanceOn, Step::Probed]).progress(),
            Some(Progress {
                last_step: Step::Probed,
                bundle_complete: true
            })
        );
        assert_eq!(
            journal(&[Step::MaintenanceOn]).progress(),
            Some(Progress {
                last_step: Step::MaintenanceOn,
                bundle_complete: false
            })
        );
    }

    #[test]
    fn only_the_update_operations_keep_a_journal() {
        assert_eq!(journal_dir("drupal.updateCore"), Some("drupal-updates"));
        assert_eq!(journal_dir("drupal.updatePackages"), Some("drupal-updates"));
        assert_eq!(journal_dir("joomla.updateCore"), Some("joomla-updates"));
        assert_eq!(journal_dir("drupal.restoreUpdate"), None);
        assert_eq!(journal_dir("site.deploy"), None);
    }
}
