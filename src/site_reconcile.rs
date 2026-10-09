//! `site.reconcile` (milestone 084): finishes what a killed engine left behind.
//!
//! `site.importArchive` writes `pending/<hash of the root>.json` before it
//! touches the destination and removes it only after the new content is in
//! place. A process that dies in between (SIGKILL, OOM, power) leaves that
//! marker, the previous content under `.wcp-sync-<id>/site`, and whatever part
//! of the new content was extracted. Nothing ran the rollback, and the marker
//! blocks every later import into that root.
//!
//! This operation does what the in-process rollback does, from the marker:
//! under the root's resource lock (a live import holds it, so a running
//! operation is never touched) it removes the partial root, renames the saved
//! content back, drops the snapshot directory and the marker, and marks the
//! interrupted transaction `Failed`. An import that was interrupted *after* the
//! new content was complete but before the marker went is rolled back too: its
//! transaction never committed, so the caller never saw it succeed.
//!
//! Only `site.importArchive` markers are handled. `wordpress.migrateImport`
//! markers also need a database restore and `wordpress.clone` keeps a single
//! `pending.json`; both are counted in `otherPending` and left alone.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    site::{SiteRelativePath, TrustedRoot},
    site_archive::{Error, SNAPSHOT_PREFIX, run_admitted},
    transaction::{
        RequestId, resource_lock,
        state::{self, TransactionStatus},
    },
};

pub const OPERATION: &str = "site.reconcile";

const RECONCILE_SCOPE: &str = "site-archive-reconcile";
const IMPORT_SCOPE: &str = "site-archive-import";
const OTHER_SCOPES: [&str; 1] = ["wordpress-migrate-import"];

pub struct Request {
    pub request_id: RequestId,
}

impl Request {
    pub fn parse(request_id: &str) -> Result<Self, crate::transaction::IdentifierError> {
        Ok(Self {
            request_id: RequestId::parse(request_id)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub dest_root: String,
    pub request_id: String,
    /// Why the marker was left alone; empty for the other lists.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileResult {
    /// The previous content is back and the partial new content is gone.
    pub rolled_back: Vec<Entry>,
    /// The marker was stale: the root had not been touched.
    pub cleared: Vec<Entry>,
    /// A live operation holds the root's lock.
    pub busy: Vec<Entry>,
    /// Nothing was changed; an operator has to look.
    pub needs_attention: Vec<Entry>,
    /// Markers of operations this one does not recover.
    pub other_pending: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    request_id: String,
    dest_root: PathBuf,
    saved_files: PathBuf,
}

enum Outcome {
    RolledBack,
    Cleared,
    Busy,
    Attention(&'static str),
}

pub fn reconcile(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &Request,
) -> Result<ReconcileResult, Error> {
    run_admitted(
        engine_state,
        RECONCILE_SCOPE,
        OPERATION,
        req.request_id,
        None,
        |_| {
            let mut result = ReconcileResult::default();
            let import = engine_state
                .open_managed_dir(&SiteRelativePath::parse(IMPORT_SCOPE).expect("static"))
                .ok();
            if let Some(import) = import {
                let pending = SiteRelativePath::parse("pending").expect("static");
                if let Ok(dir) = import.open_managed_dir(&pending) {
                    let mut names = dir.file_names().map_err(Error::Io)?;
                    names.sort();
                    for name in names.into_iter().filter(|n| n.ends_with(".json")) {
                        let path = SiteRelativePath::parse(format!("pending/{name}"))
                            .map_err(|_| Error::UnsafeTarget)?;
                        recover_one(
                            engine_state,
                            content_roots,
                            &import,
                            &path,
                            req,
                            &mut result,
                        );
                    }
                }
            }
            for scope in OTHER_SCOPES {
                let pending = format!("{scope}/pending");
                if let Some(dir) = SiteRelativePath::parse(pending)
                    .ok()
                    .and_then(|p| engine_state.open_managed_dir(&p).ok())
                {
                    result.other_pending += dir.file_names().map_or(0, |n| n.len() as u32);
                }
            }
            Ok(result)
        },
    )
}

fn recover_one(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    import: &ManagedRoot,
    marker_path: &SiteRelativePath,
    req: &Request,
    result: &mut ReconcileResult,
) {
    let marker: Option<Marker> = import
        .read_to_string(marker_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    let Some(marker) = marker else {
        result.needs_attention.push(Entry {
            dest_root: marker_path.as_path().display().to_string(),
            reason: "the marker cannot be read".into(),
            ..Entry::default()
        });
        return;
    };
    let entry = |reason: &str| Entry {
        dest_root: marker.dest_root.display().to_string(),
        request_id: marker.request_id.clone(),
        reason: reason.to_owned(),
    };
    let outcome = recover(
        engine_state,
        content_roots,
        import,
        marker_path,
        &marker,
        req,
    );
    match outcome {
        Outcome::RolledBack => result.rolled_back.push(entry("")),
        Outcome::Cleared => result.cleared.push(entry("")),
        Outcome::Busy => result.busy.push(entry("")),
        Outcome::Attention(reason) => result.needs_attention.push(entry(reason)),
    }
}

fn recover(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    import: &ManagedRoot,
    marker_path: &SiteRelativePath,
    marker: &Marker,
    req: &Request,
) -> Outcome {
    let Ok(id) = RequestId::parse(&marker.request_id) else {
        return Outcome::Attention("the marker names an invalid request id");
    };
    let Some((root, relative)) = content_roots.iter().find_map(|root| {
        let rel = marker.dest_root.strip_prefix(root.as_path()).ok()?;
        let rel = SiteRelativePath::parse(rel).ok()?;
        Some((root, rel))
    }) else {
        return Outcome::Attention("the destination is not under a content root");
    };
    let snapshot = SiteRelativePath::parse(format!("{SNAPSHOT_PREFIX}{id}"))
        .expect("a canonical UUID forms a valid path");
    let saved = SiteRelativePath::parse(format!("{SNAPSHOT_PREFIX}{id}/site"))
        .expect("a canonical UUID forms a valid path");
    if marker.saved_files != root.as_path().join(saved.as_path()) {
        return Outcome::Attention("the marker does not point at this request's snapshot");
    }
    let Ok(_lock) = resource_lock::acquire(engine_state, &marker.dest_root, req.request_id) else {
        return Outcome::Busy;
    };
    let Ok(content) = ManagedRoot::open(root) else {
        return Outcome::Attention("the content root cannot be opened");
    };
    let saved_exists = content.symlink_metadata(&saved).is_ok();
    let snapshot_exists = content.symlink_metadata(&snapshot).is_ok();
    let dest_exists = content.symlink_metadata(&relative).is_ok();

    let outcome = if saved_exists {
        if dest_exists && content.remove_dir_all(&relative).is_err() {
            return Outcome::Attention("the partial destination could not be removed");
        }
        if content.rename(&saved, &relative).is_err() {
            return Outcome::Attention("the saved content could not be moved back");
        }
        let _ = content.remove_dir_all(&snapshot);
        Outcome::RolledBack
    } else if snapshot_exists || dest_exists {
        // Died before the destination was moved aside: it is untouched.
        if snapshot_exists {
            let _ = content.remove_dir_all(&snapshot);
        }
        Outcome::Cleared
    } else {
        return Outcome::Attention("neither the destination nor its saved content exists");
    };
    if import.remove_file(marker_path).is_err() {
        return Outcome::Attention("the content is restored but the marker could not be removed");
    }
    fail_interrupted(import, id);
    outcome
}

/// Marks the interrupted import's `InProgress` transaction `Failed`.
fn fail_interrupted(import: &ManagedRoot, id: RequestId) {
    let Ok(path) = SiteRelativePath::parse(format!("transactions/{id}.json")) else {
        return;
    };
    let Ok(mut transaction) = state::load(import, &path) else {
        return;
    };
    if transaction.status == TransactionStatus::InProgress
        && transaction
            .mark_failed(
                crate::error::ErrorCode::Internal,
                "interrupted; rolled back by site.reconcile",
            )
            .is_ok()
    {
        let _ = state::save(import, &path, &transaction);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::transaction::state::TransactionState;
    use std::fs;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const RECONCILE_ID: &str = "123e4567-e89b-12d3-a456-426614174099";

    struct Fx {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        roots: Vec<TrustedRoot>,
    }

    impl Fx {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            fs::create_dir_all(base.join("state")).unwrap();
            fs::create_dir_all(base.join("www")).unwrap();
            let state =
                ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap();
            let roots = vec![TrustedRoot::parse(base.join("www")).unwrap()];
            Self {
                _dir: dir,
                base,
                state,
                roots,
            }
        }

        fn www(&self, path: &str) -> PathBuf {
            self.base.join("www").join(path)
        }

        /// What an import killed after it moved the site aside leaves.
        fn interrupted_import(&self, with_saved: bool, with_snapshot_dir: bool, dest: bool) {
            let marker_dir = self.base.join("state/site-archive-import/pending");
            fs::create_dir_all(&marker_dir).unwrap();
            let saved = self.www(&format!("{SNAPSHOT_PREFIX}{ID}/site"));
            fs::write(
                marker_dir.join("abc.json"),
                serde_json::json!({
                    "requestId": ID,
                    "destRoot": self.www("site"),
                    "savedFiles": saved,
                })
                .to_string(),
            )
            .unwrap();
            if with_saved {
                fs::create_dir_all(&saved).unwrap();
                fs::write(saved.join("old.txt"), "old").unwrap();
            } else if with_snapshot_dir {
                fs::create_dir_all(self.www(&format!("{SNAPSHOT_PREFIX}{ID}"))).unwrap();
            }
            if dest {
                fs::create_dir_all(self.www("site")).unwrap();
                fs::write(self.www("site/partial.txt"), "new").unwrap();
            }
            let scope = self
                .state
                .open_managed_dir(&SiteRelativePath::parse("site-archive-import").unwrap())
                .unwrap();
            fs::create_dir_all(self.base.join("state/site-archive-import/transactions")).unwrap();
            let transaction =
                TransactionState::start(RequestId::parse(ID).unwrap(), None, "site.importArchive");
            state::save(
                &scope,
                &SiteRelativePath::parse(format!("transactions/{ID}.json")).unwrap(),
                &transaction,
            )
            .unwrap();
        }

        fn run(&self) -> ReconcileResult {
            reconcile(
                &self.state,
                &self.roots,
                &Request::parse(RECONCILE_ID).unwrap(),
            )
            .unwrap()
        }

        fn marker_exists(&self) -> bool {
            self.base
                .join("state/site-archive-import/pending/abc.json")
                .exists()
        }

        fn transaction_status(&self) -> TransactionStatus {
            let scope = self
                .state
                .open_managed_dir(&SiteRelativePath::parse("site-archive-import").unwrap())
                .unwrap();
            state::load(
                &scope,
                &SiteRelativePath::parse(format!("transactions/{ID}.json")).unwrap(),
            )
            .unwrap()
            .status
        }
    }

    #[test]
    fn a_half_extracted_import_is_rolled_back() {
        let fx = Fx::new();
        fx.interrupted_import(true, true, true);
        let result = fx.run();
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert_eq!(fs::read_to_string(fx.www("site/old.txt")).unwrap(), "old");
        assert!(!fx.www("site/partial.txt").exists());
        assert!(!fx.www(&format!("{SNAPSHOT_PREFIX}{ID}")).exists());
        assert!(!fx.marker_exists());
        assert_eq!(fx.transaction_status(), TransactionStatus::Failed);
        // Nothing is left for a second run.
        let again = reconcile(
            &fx.state,
            &fx.roots,
            &Request::parse("123e4567-e89b-12d3-a456-426614174098").unwrap(),
        )
        .unwrap();
        assert_eq!(again, ReconcileResult::default());
    }

    #[test]
    fn a_missing_destination_gets_the_saved_content_back() {
        let fx = Fx::new();
        fx.interrupted_import(true, true, false);
        assert_eq!(fx.run().rolled_back.len(), 1);
        assert_eq!(fs::read_to_string(fx.www("site/old.txt")).unwrap(), "old");
    }

    #[test]
    fn a_marker_from_before_the_destination_was_touched_is_only_cleared() {
        let fx = Fx::new();
        fx.interrupted_import(false, true, true);
        let result = fx.run();
        assert_eq!(result.cleared.len(), 1, "{result:?}");
        assert!(
            fx.www("site/partial.txt").exists(),
            "the untouched site stays"
        );
        assert!(!fx.www(&format!("{SNAPSHOT_PREFIX}{ID}")).exists());
        assert!(!fx.marker_exists());
    }

    #[test]
    fn a_root_held_by_a_live_operation_is_left_alone() {
        let fx = Fx::new();
        fx.interrupted_import(true, true, true);
        let _held = resource_lock::acquire(
            &fx.state,
            &fx.www("site"),
            RequestId::parse("123e4567-e89b-12d3-a456-426614174077").unwrap(),
        )
        .unwrap();
        let result = fx.run();
        assert_eq!(result.busy.len(), 1, "{result:?}");
        assert!(fx.marker_exists());
        assert!(fx.www("site/partial.txt").exists());
    }

    #[test]
    fn nothing_to_go_back_to_and_foreign_markers_are_reported_not_touched() {
        let fx = Fx::new();
        fx.interrupted_import(false, false, false);
        let result = fx.run();
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(fx.marker_exists());

        let fx = Fx::new();
        fx.interrupted_import(true, true, true);
        let marker = fx.base.join("state/site-archive-import/pending/abc.json");
        fs::write(
            &marker,
            serde_json::json!({
                "requestId": ID,
                "destRoot": fx.www("site"),
                "savedFiles": "/etc",
            })
            .to_string(),
        )
        .unwrap();
        let result = fx.run();
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(fx.www("site/partial.txt").exists());
        assert!(
            fx.www(&format!("{SNAPSHOT_PREFIX}{ID}/site/old.txt"))
                .exists()
        );
    }

    #[test]
    fn markers_of_other_operations_are_counted() {
        let fx = Fx::new();
        let dir = fx.base.join("state/wordpress-migrate-import/pending");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("x.json"), "{}").unwrap();
        assert_eq!(fx.run().other_pending, 1);
    }
}
