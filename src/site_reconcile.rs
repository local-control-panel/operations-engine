//! `site.reconcile` (milestones 084, 088): finishes what a killed engine left behind.
//!
//! Three operations move a site's files aside, write the new content and only
//! then drop a recovery marker:
//!
//! - `site.importArchive` (`site-archive-import/pending/<hash>.json`),
//! - `wordpress.migrateImport` (`wordpress-migrate-import/pending/<hash>.json`),
//! - `wordpress.clone` (`wordpress-clone/<hash>/pending.json`).
//!
//! A process that dies in between (SIGKILL, OOM, power) leaves that marker, the
//! previous content under `<content root>/<prefix><request id>/site`, and
//! whatever part of the new content was written. The marker blocks every later
//! operation on that root and nothing ran the rollback.
//!
//! This operation does what the in-process rollback does, from the marker:
//! under the root's resource lock (a live operation holds it, so it is never
//! touched) it replays the database snapshot when the operation also changed a
//! database, removes the partial root, renames the saved content back, drops
//! the snapshot directory and the marker, and marks the interrupted
//! transaction `Failed`. An operation that was interrupted *after* the new
//! content was complete but before the marker went is rolled back too: its
//! transaction never committed, so the caller never saw it succeed.
//!
//! Replaying a database snapshot needs the MariaDB root password, which the
//! engine does not store. The caller passes it per container in the optional
//! request file; without it a marker that needs the database is reported in
//! `needsAttention` and nothing is touched. The snapshot is replayed only when
//! `mariadb-dump` finished it (`-- Dump completed`): an unfinished one means
//! the database had not been changed yet, and replaying half a dump with
//! `--add-drop-database` would destroy it.

use std::{collections::BTreeMap, io::Read, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    db_restore::ContainerName,
    filesystem::ManagedRoot,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    site::{SiteRelativePath, TrustedRoot},
    site_archive::{Error, SNAPSHOT_PREFIX, run_admitted},
    transaction::{
        RequestId, resource_lock,
        state::{self, TransactionStatus},
    },
};

pub const OPERATION: &str = "site.reconcile";

const RECONCILE_SCOPE: &str = "site-archive-reconcile";
const DB_STEP_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_PASSWORDS_BYTES: usize = 16 * 1024;
const DUMP_TRAILER: &[u8] = b"-- Dump completed";

/// What differs between the three operations whose markers are recovered.
struct Kind {
    operation: &'static str,
    /// Scope directory below the state root.
    scope: &'static str,
    /// `true`: one scope per root (`<scope>/<hash>/pending.json`); `false`:
    /// `<scope>/pending/<hash>.json`.
    scope_per_root: bool,
    /// Snapshot directory prefix next to the destination.
    snapshot_prefix: &'static str,
    /// Where the database snapshot of a request lives below the recovery
    /// root (`<dir>/<request id>/target.sql`); `None` when no database is involved.
    db_dir: Option<&'static str>,
    /// Remove `<db_dir>/<request id>` after a rollback (clone keeps it).
    drop_db_dir: bool,
}

const KINDS: [Kind; 3] = [
    Kind {
        operation: "site.importArchive",
        scope: "site-archive-import",
        scope_per_root: false,
        snapshot_prefix: SNAPSHOT_PREFIX,
        db_dir: None,
        drop_db_dir: false,
    },
    Kind {
        operation: "wordpress.migrateImport",
        scope: "wordpress-migrate-import",
        scope_per_root: false,
        snapshot_prefix: ".wcp-migrate-",
        db_dir: Some("wordpress-migrate"),
        drop_db_dir: true,
    },
    Kind {
        operation: "wordpress.clone",
        scope: "wordpress-clone",
        scope_per_root: true,
        snapshot_prefix: ".wcp-clone-",
        db_dir: Some("wordpress-clone"),
        drop_db_dir: false,
    },
];

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a std::path::Path,
    pub content_roots: &'a [TrustedRoot],
    /// Where database snapshots are kept (`/var/backups/wcp`); `None`
    /// disables database recovery.
    pub recovery_root: Option<&'a TrustedRoot>,
    pub docker_program: &'a str,
    /// The operations `site.migrateRuntime` is made of; `None` leaves its
    /// journals alone.
    pub migrate: Option<&'a dyn crate::site_migrate_runtime::Backend>,
}

pub struct Request {
    pub request_id: RequestId,
    /// MariaDB root password per container, from the request file.
    mariadb_root_passwords: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Secrets {
    #[serde(default)]
    mariadb_root_passwords: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum RequestError {
    InvalidRequestId,
    InvalidDocument,
}

impl Request {
    pub fn parse(request_id: &str, document: Option<&str>) -> Result<Self, RequestError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let mariadb_root_passwords = match document {
            None => BTreeMap::new(),
            Some(text) => {
                let secrets: Secrets =
                    serde_json::from_str(text).map_err(|_| RequestError::InvalidDocument)?;
                if secrets.mariadb_root_passwords.len() > 32
                    || secrets
                        .mariadb_root_passwords
                        .iter()
                        .any(|(name, password)| {
                            ContainerName::parse(name).is_err()
                                || password.is_empty()
                                || password.len() > 256
                        })
                {
                    return Err(RequestError::InvalidDocument);
                }
                secrets.mariadb_root_passwords
            }
        };
        Ok(Self {
            request_id,
            mariadb_root_passwords,
        })
    }

    pub const fn max_document_bytes() -> usize {
        MAX_PASSWORDS_BYTES
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub operation: String,
    pub dest_root: String,
    pub request_id: String,
    /// Why the marker was left alone; empty for the other lists.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Set only when the marker waits for this container's MariaDB root
    /// password (`--request-file`); the caller can look it up and run again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub needs_password_for: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileResult {
    /// The previous content is back and the partial new content is gone.
    pub rolled_back: Vec<Entry>,
    /// A `site.migrateRuntime` that had reached its cleanup phase: finished,
    /// not undone (the site already runs on the new pool).
    #[serde(default)]
    pub completed: Vec<Entry>,
    /// The marker was stale: the root had not been touched.
    pub cleared: Vec<Entry>,
    /// A live operation holds the root's lock.
    pub busy: Vec<Entry>,
    /// Nothing was changed; an operator has to look.
    pub needs_attention: Vec<Entry>,
    /// Markers this operation does not recover (the single marker file
    /// `wordpress.migrateImport` wrote before markers were per root).
    pub other_pending: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    request_id: String,
    #[serde(alias = "stagingRoot")]
    dest_root: PathBuf,
    saved_files: PathBuf,
    #[serde(default)]
    database_container: Option<String>,
    #[serde(default)]
    database_snapshot: Option<PathBuf>,
    /// Whether the destination existed before the operation. Markers written
    /// before milestone 088 do not say.
    #[serde(default)]
    had_target: Option<bool>,
}

enum Outcome {
    NeedsPassword(String),
    RolledBack,
    Cleared,
    Busy,
    Attention(&'static str),
}

pub fn reconcile(ctx: &Context<'_>, req: &Request) -> Result<ReconcileResult, Error> {
    run_admitted(
        ctx.engine_state,
        RECONCILE_SCOPE,
        OPERATION,
        req.request_id,
        None,
        |_| {
            let mut result = ReconcileResult::default();
            for kind in &KINDS {
                for (scope, marker_path) in markers(ctx, kind) {
                    recover_one(ctx, kind, &scope, &marker_path, req, &mut result);
                }
            }
            if let Some(backend) = ctx.migrate {
                migrations(ctx, backend, req, &mut result);
            }
            let legacy =
                SiteRelativePath::parse("wordpress-migrate-import/pending.json").expect("static");
            if ctx.engine_state.exists(&legacy) {
                result.other_pending += 1;
            }
            Ok(result)
        },
    )
}

/// Finishes every interrupted `site.migrateRuntime` from its journal.
fn migrations(
    ctx: &Context<'_>,
    backend: &dyn crate::site_migrate_runtime::Backend,
    req: &Request,
    result: &mut ReconcileResult,
) {
    use crate::site_migrate_runtime::{self as migrate, Recovery};

    let list = |path: std::path::PathBuf| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    };
    let base = ctx.state_root.join(migrate::SCOPE);
    for name in list(base.clone()) {
        let Ok(domain) = crate::site::Domain::parse(&name) else {
            continue;
        };
        for journal in list(base.join(&name).join("pending")) {
            let Some(id) = journal.strip_suffix(".json") else {
                continue;
            };
            let entry = |reason: &str| Entry {
                operation: migrate::OPERATION.into(),
                dest_root: domain.to_string(),
                request_id: id.to_owned(),
                reason: reason.to_owned(),
                needs_password_for: String::new(),
            };
            match migrate::recover(ctx.engine_state, backend, &domain, &journal, req.request_id) {
                Recovery::RolledBack => result.rolled_back.push(entry("")),
                Recovery::Completed => result.completed.push(entry("")),
                Recovery::Cleared => result.cleared.push(entry("")),
                Recovery::Busy => result.busy.push(entry("")),
                Recovery::Attention(reason) => result.needs_attention.push(entry(&reason)),
            }
        }
    }
}

/// The scope directory and the marker path inside it, for every marker of `kind`.
fn markers(ctx: &Context<'_>, kind: &Kind) -> Vec<(ManagedRoot, SiteRelativePath)> {
    let rel = |p: &str| SiteRelativePath::parse(p).ok();
    let mut found = Vec::new();
    if kind.scope_per_root {
        let Ok(entries) = std::fs::read_dir(ctx.state_root.join(kind.scope)) else {
            return found;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            let Some(scope) = rel(&format!("{}/{name}", kind.scope))
                .and_then(|p| ctx.engine_state.open_managed_dir(&p).ok())
            else {
                continue;
            };
            let marker = rel("pending.json").expect("static");
            if scope.exists(&marker) {
                found.push((scope, marker));
            }
        }
    } else {
        let open = || rel(kind.scope).and_then(|p| ctx.engine_state.open_managed_dir(&p).ok());
        let Some(dir) =
            open().and_then(|s| rel("pending").and_then(|p| s.open_managed_dir(&p).ok()))
        else {
            return found;
        };
        let mut names = dir.file_names().unwrap_or_default();
        names.sort();
        for name in names.into_iter().filter(|n| n.ends_with(".json")) {
            // Each marker gets its own handle on the scope.
            if let (Some(path), Some(scope)) = (rel(&format!("pending/{name}")), open()) {
                found.push((scope, path));
            }
        }
    }
    found
}

fn recover_one(
    ctx: &Context<'_>,
    kind: &Kind,
    scope: &ManagedRoot,
    marker_path: &SiteRelativePath,
    req: &Request,
    result: &mut ReconcileResult,
) {
    let marker: Option<Marker> = scope
        .read_to_string(marker_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    let Some(marker) = marker else {
        result.needs_attention.push(Entry {
            operation: kind.operation.into(),
            dest_root: format!("{}/{}", kind.scope, marker_path.as_path().display()),
            reason: "the marker cannot be read".into(),
            ..Entry::default()
        });
        return;
    };
    let entry = |reason: &str| Entry {
        operation: kind.operation.into(),
        dest_root: marker.dest_root.display().to_string(),
        request_id: marker.request_id.clone(),
        reason: reason.to_owned(),
        needs_password_for: String::new(),
    };
    match recover(ctx, kind, scope, marker_path, &marker, req) {
        Outcome::RolledBack => result.rolled_back.push(entry("")),
        Outcome::Cleared => result.cleared.push(entry("")),
        Outcome::Busy => result.busy.push(entry("")),
        Outcome::Attention(reason) => result.needs_attention.push(entry(reason)),
        Outcome::NeedsPassword(container) => result.needs_attention.push(Entry {
            needs_password_for: container,
            ..entry(
                "the database must be restored: pass the MariaDB root password of its container",
            )
        }),
    }
}

fn recover(
    ctx: &Context<'_>,
    kind: &Kind,
    scope: &ManagedRoot,
    marker_path: &SiteRelativePath,
    marker: &Marker,
    req: &Request,
) -> Outcome {
    let Ok(id) = RequestId::parse(&marker.request_id) else {
        return Outcome::Attention("the marker names an invalid request id");
    };
    let Some((root, relative)) = ctx.content_roots.iter().find_map(|root| {
        let rel = marker.dest_root.strip_prefix(root.as_path()).ok()?;
        let rel = SiteRelativePath::parse(rel).ok()?;
        Some((root, rel))
    }) else {
        return Outcome::Attention("the destination is not under a content root");
    };
    let prefix = kind.snapshot_prefix;
    let snapshot = SiteRelativePath::parse(format!("{prefix}{id}"))
        .expect("a canonical UUID forms a valid path");
    let saved = SiteRelativePath::parse(format!("{prefix}{id}/site"))
        .expect("a canonical UUID forms a valid path");
    if marker.saved_files != root.as_path().join(saved.as_path()) {
        return Outcome::Attention("the marker does not point at this request's snapshot");
    }
    // The database snapshot path is derived, never taken from the marker.
    let db = match (kind.db_dir, ctx.recovery_root) {
        (Some(dir), Some(recovery)) => {
            let snapshot_rel = SiteRelativePath::parse(format!("{dir}/{id}/target.sql"))
                .expect("a canonical UUID forms a valid path");
            if marker.database_snapshot.as_deref()
                != Some(&recovery.as_path().join(snapshot_rel.as_path()))
            {
                return Outcome::Attention(
                    "the marker does not point at this request's database snapshot",
                );
            }
            Some((recovery, dir, snapshot_rel))
        }
        (Some(_), None) => return Outcome::Attention("database recovery is not available"),
        (None, _) => None,
    };
    let Ok(_lock) = resource_lock::acquire(ctx.engine_state, &marker.dest_root, req.request_id)
    else {
        return Outcome::Busy;
    };
    // A transaction that committed before the engine died on its way to
    // remove the marker succeeded: the content stays, only the marker goes.
    if transaction_committed(scope, id) {
        if scope.remove_file(marker_path).is_err() {
            return Outcome::Attention(
                "the operation committed but the marker could not be removed",
            );
        }
        return Outcome::Cleared;
    }
    let Ok(content) = ManagedRoot::open(root) else {
        return Outcome::Attention("the content root cannot be opened");
    };
    let saved_exists = content.symlink_metadata(&saved).is_ok();
    let snapshot_exists = content.symlink_metadata(&snapshot).is_ok();
    let dest_exists = content.symlink_metadata(&relative).is_ok();

    // Did the operation get as far as changing the destination?
    let created_new = marker.had_target == Some(false) && dest_exists;
    let touched = saved_exists || created_new;
    // `hadTarget: false` with nothing on disk: killed before the destination
    // was created (e.g. while the database snapshot was being dumped); the
    // marker is stale, not a mystery.
    if marker.had_target != Some(false) && !(touched || snapshot_exists || dest_exists) {
        return Outcome::Attention("neither the destination nor its saved content exists");
    }
    if !touched && db.is_some() && marker.had_target.is_none() {
        // A marker without `hadTarget` cannot tell an untouched destination
        // from one the operation created from nothing.
        return Outcome::Attention("an older marker: cannot tell whether the destination is new");
    }

    // The database goes back first, as in the in-process rollback.
    if let (true, Some((recovery, _, snapshot_rel))) = (touched, &db) {
        let Some(container) = marker.database_container.as_deref() else {
            return Outcome::Attention("the marker names no database container");
        };
        if ContainerName::parse(container).is_err() {
            return Outcome::Attention("the marker names an invalid database container");
        }
        let Ok(path) = recovery.resolve_existing(snapshot_rel) else {
            return Outcome::Attention("the database snapshot is missing");
        };
        if !dump_is_complete(&path) {
            return Outcome::Attention("the database snapshot is incomplete");
        }
        let Some(password) = req.mariadb_root_passwords.get(container) else {
            return Outcome::NeedsPassword(container.to_owned());
        };
        if !restore_database(ctx.docker_program, container, password, &path) {
            return Outcome::Attention("the database snapshot could not be replayed");
        }
    }

    let outcome = if touched {
        if dest_exists && content.remove_dir_all(&relative).is_err() {
            return Outcome::Attention("the partial destination could not be removed");
        }
        if saved_exists && content.rename(&saved, &relative).is_err() {
            return Outcome::Attention("the saved content could not be moved back");
        }
        let _ = content.remove_dir_all(&snapshot);
        Outcome::RolledBack
    } else {
        // Died before the destination was moved aside: it is untouched.
        if snapshot_exists {
            let _ = content.remove_dir_all(&snapshot);
        }
        Outcome::Cleared
    };
    if let (true, Some((recovery, dir, _))) = (kind.drop_db_dir, &db) {
        if let (Ok(dir), Ok(managed)) = (
            SiteRelativePath::parse(format!("{dir}/{id}")),
            ManagedRoot::open(recovery),
        ) {
            let _ = managed.remove_dir_all(&dir);
        }
    }
    if scope.remove_file(marker_path).is_err() {
        return Outcome::Attention("the content is restored but the marker could not be removed");
    }
    fail_interrupted(scope, id);
    outcome
}

fn transaction_committed(scope: &ManagedRoot, id: RequestId) -> bool {
    SiteRelativePath::parse(format!("transactions/{id}.json"))
        .ok()
        .and_then(|path| state::load(scope, &path).ok())
        .is_some_and(|transaction| transaction.status == TransactionStatus::Committed)
}

/// `mariadb-dump` ends a finished dump with `-- Dump completed on <date>`.
fn dump_is_complete(path: &std::path::Path) -> bool {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(length) = file.seek(SeekFrom::End(0)) else {
        return false;
    };
    let tail = length.min(512);
    let mut buffer = vec![0u8; tail as usize];
    file.seek(SeekFrom::End(-(tail as i64))).is_ok()
        && file.read_exact(&mut buffer).is_ok()
        && buffer
            .windows(DUMP_TRAILER.len())
            .any(|w| w == DUMP_TRAILER)
}

fn restore_database(
    docker: &str,
    container: &str,
    password: &str,
    snapshot: &std::path::Path,
) -> bool {
    let request = ProcessRequest::new(docker)
        .env("MYSQL_PWD", password)
        .args([
            "exec",
            "-i",
            "-e",
            "MYSQL_PWD",
            container,
            "mariadb",
            "-uroot",
        ]);
    let limits = ProcessLimits {
        timeout: DB_STEP_TIMEOUT,
        max_stdout_bytes: 64 * 1024,
        max_stderr_bytes: 64 * 1024,
    };
    process::run_with_stdin_file(&request, snapshot, &limits, &CancellationToken::default())
        .is_ok_and(|output| process::error_code(&output.termination).is_none())
}

/// Marks the interrupted operation's `InProgress` transaction `Failed`.
fn fail_interrupted(scope: &ManagedRoot, id: RequestId) {
    let Ok(path) = SiteRelativePath::parse(format!("transactions/{id}.json")) else {
        return;
    };
    let Ok(mut transaction) = state::load(scope, &path) else {
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
        let _ = state::save(scope, &path, &transaction);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::transaction::state::TransactionState;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const RECONCILE_ID: &str = "123e4567-e89b-12d3-a456-426614174099";
    const DUMP: &str =
        "-- dump of target\nCREATE TABLE t (id int);\n-- Dump completed on 2026-10-09\n";
    const PASSWORDS: &str = r#"{"mariadbRootPasswords":{"mariadb":"s3cret"}}"#;

    struct Fx {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        roots: Vec<TrustedRoot>,
        recovery_root: TrustedRoot,
        docker: String,
    }

    impl Fx {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "www", "recovery"] {
                fs::create_dir_all(base.join(sub)).unwrap();
            }
            let fx = Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                roots: vec![TrustedRoot::parse(base.join("www")).unwrap()],
                recovery_root: TrustedRoot::parse(base.join("recovery")).unwrap(),
                docker: base.join("docker").to_string_lossy().into_owned(),
                base,
                _dir: dir,
            };
            fx.fake_docker(false);
            fx
        }

        fn fake_docker(&self, fail: bool) {
            let base = self.base.display();
            let work = if fail {
                "cat >/dev/null; exit 1".to_owned()
            } else {
                format!("cat >> '{base}/imported.sql'")
            };
            fs::write(
                &self.docker,
                format!(
                    "#!/bin/sh\necho \"$* pw=${{MYSQL_PWD:-}}\" >> '{base}/calls.log'\n{work}\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&self.docker, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn www(&self, path: &str) -> PathBuf {
            self.base.join("www").join(path)
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.base.join("calls.log")).unwrap_or_default()
        }

        fn imported(&self) -> String {
            fs::read_to_string(self.base.join("imported.sql")).unwrap_or_default()
        }

        fn start_transaction(&self, scope_dir: &str, operation: &'static str) {
            fs::create_dir_all(self.base.join("state").join(scope_dir).join("transactions"))
                .unwrap();
            let scope = self
                .state
                .open_managed_dir(&SiteRelativePath::parse(scope_dir).unwrap())
                .unwrap();
            state::save(
                &scope,
                &SiteRelativePath::parse(format!("transactions/{ID}.json")).unwrap(),
                &TransactionState::start(RequestId::parse(ID).unwrap(), None, operation),
            )
            .unwrap();
        }

        fn transaction_status(&self, scope_dir: &str) -> TransactionStatus {
            let scope = self
                .state
                .open_managed_dir(&SiteRelativePath::parse(scope_dir).unwrap())
                .unwrap();
            state::load(
                &scope,
                &SiteRelativePath::parse(format!("transactions/{ID}.json")).unwrap(),
            )
            .unwrap()
            .status
        }

        fn leave_files(&self, prefix: &str, with_saved: bool, with_snapshot_dir: bool, dest: bool) {
            if with_saved {
                fs::create_dir_all(self.www(&format!("{prefix}{ID}/site"))).unwrap();
                fs::write(self.www(&format!("{prefix}{ID}/site/old.txt")), "old").unwrap();
            } else if with_snapshot_dir {
                fs::create_dir_all(self.www(&format!("{prefix}{ID}"))).unwrap();
            }
            if dest {
                fs::create_dir_all(self.www("site")).unwrap();
                fs::write(self.www("site/partial.txt"), "new").unwrap();
            }
        }

        /// What an import killed after it moved the site aside leaves.
        fn interrupted_import(&self, with_saved: bool, with_snapshot_dir: bool, dest: bool) {
            let marker_dir = self.base.join("state/site-archive-import/pending");
            fs::create_dir_all(&marker_dir).unwrap();
            fs::write(
                marker_dir.join("abc.json"),
                serde_json::json!({
                    "requestId": ID,
                    "destRoot": self.www("site"),
                    "savedFiles": self.www(&format!("{SNAPSHOT_PREFIX}{ID}/site")),
                })
                .to_string(),
            )
            .unwrap();
            self.leave_files(SNAPSHOT_PREFIX, with_saved, with_snapshot_dir, dest);
            self.start_transaction("site-archive-import", "site.importArchive");
        }

        /// What `wordpress.migrateImport` (or `wordpress.clone`) killed after
        /// the database snapshot was taken leaves. `had_target`: the marker's field.
        fn interrupted_db_operation(
            &self,
            clone: bool,
            had_target: Option<bool>,
            dump: Option<&str>,
            saved_and_dest: (bool, bool, bool),
        ) -> String {
            let (prefix, db_dir, dest_key) = if clone {
                (".wcp-clone-", "wordpress-clone", "stagingRoot")
            } else {
                (".wcp-migrate-", "wordpress-migrate", "destRoot")
            };
            let snapshot = self.base.join(format!("recovery/{db_dir}/{ID}/target.sql"));
            let mut marker = serde_json::json!({
                "requestId": ID,
                "database": "wp_db",
                "databaseContainer": "mariadb",
                "databaseSnapshot": snapshot,
                "savedFiles": self.www(&format!("{prefix}{ID}/site")),
            });
            marker[dest_key] = serde_json::json!(self.www("site"));
            if let Some(had) = had_target {
                marker["hadTarget"] = serde_json::json!(had);
            }
            let scope_dir = if clone {
                "wordpress-clone/abc".to_owned()
            } else {
                "wordpress-migrate-import".to_owned()
            };
            let marker_file = if clone {
                "pending.json"
            } else {
                "pending/abc.json"
            };
            let marker_path = self.base.join("state").join(&scope_dir).join(marker_file);
            fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
            fs::write(&marker_path, marker.to_string()).unwrap();
            if let Some(dump) = dump {
                fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
                fs::write(&snapshot, dump).unwrap();
            }
            let (saved, snapshot_dir, dest) = saved_and_dest;
            self.leave_files(prefix, saved, snapshot_dir, dest);
            self.start_transaction(
                &scope_dir,
                if clone {
                    "wordpress.clone"
                } else {
                    "wordpress.migrateImport"
                },
            );
            scope_dir
        }

        fn run_with(&self, document: Option<&str>) -> ReconcileResult {
            self.run_as(RECONCILE_ID, document)
        }

        fn run_as(&self, id: &str, document: Option<&str>) -> ReconcileResult {
            reconcile(
                &Context {
                    engine_state: &self.state,
                    state_root: &self.base.join("state"),
                    content_roots: &self.roots,
                    recovery_root: Some(&self.recovery_root),
                    docker_program: &self.docker,
                    migrate: None,
                },
                &Request::parse(id, document).unwrap(),
            )
            .unwrap()
        }

        fn run(&self) -> ReconcileResult {
            self.run_with(None)
        }

        fn marker_exists(&self) -> bool {
            self.base
                .join("state/site-archive-import/pending/abc.json")
                .exists()
        }
    }

    #[test]
    fn a_half_extracted_import_is_rolled_back() {
        let fx = Fx::new();
        fx.interrupted_import(true, true, true);
        let result = fx.run();
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert_eq!(result.rolled_back[0].operation, "site.importArchive");
        assert_eq!(fs::read_to_string(fx.www("site/old.txt")).unwrap(), "old");
        assert!(!fx.www("site/partial.txt").exists());
        assert!(!fx.www(&format!("{SNAPSHOT_PREFIX}{ID}")).exists());
        assert!(!fx.marker_exists());
        assert_eq!(
            fx.transaction_status("site-archive-import"),
            TransactionStatus::Failed
        );
        // Nothing is left for a second run.
        let again = fx.run_as("123e4567-e89b-12d3-a456-426614174098", None);
        assert_eq!(again, ReconcileResult::default());
        assert_eq!(fx.calls(), "", "an import has no database");
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
    fn a_new_site_killed_before_anything_was_created_is_only_cleared() {
        let fx = Fx::new();
        let scope = fx.interrupted_db_operation(
            false,
            Some(false),
            Some("partial dump"),
            (false, false, false),
        );
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.cleared.len(), 1, "{result:?}");
        assert!(result.needs_attention.is_empty(), "{result:?}");
        assert!(
            !fx.base
                .join("state")
                .join(scope)
                .join("pending/abc.json")
                .exists()
        );
        assert_eq!(fx.calls(), "", "the database was never touched");
    }

    #[test]
    fn a_half_done_migrate_import_gets_its_files_and_database_back() {
        let fx = Fx::new();
        let scope = fx.interrupted_db_operation(false, Some(true), Some(DUMP), (true, true, true));
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert_eq!(result.rolled_back[0].operation, "wordpress.migrateImport");
        assert_eq!(fs::read_to_string(fx.www("site/old.txt")).unwrap(), "old");
        assert!(!fx.www("site/partial.txt").exists());
        assert!(!fx.www(&format!(".wcp-migrate-{ID}")).exists());
        assert_eq!(fx.imported(), DUMP, "the snapshot was replayed");
        assert!(
            fx.calls()
                .contains("exec -i -e MYSQL_PWD mariadb mariadb -uroot pw=s3cret"),
            "{}",
            fx.calls()
        );
        assert!(
            !fx.base
                .join(format!("recovery/wordpress-migrate/{ID}"))
                .exists(),
            "a rolled back migration drops its recovery files, like the in-process rollback"
        );
        assert!(
            !fx.base
                .join("state/wordpress-migrate-import/pending/abc.json")
                .exists()
        );
        assert_eq!(fx.transaction_status(&scope), TransactionStatus::Failed);
        assert_eq!(
            fx.run_as("123e4567-e89b-12d3-a456-426614174098", None),
            ReconcileResult::default()
        );
    }

    #[test]
    fn without_the_password_a_database_marker_is_reported_and_nothing_is_touched() {
        let fx = Fx::new();
        let scope = fx.interrupted_db_operation(false, Some(true), Some(DUMP), (true, true, true));
        let result = fx.run();
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(result.needs_attention[0].reason.contains("root password"));
        assert_eq!(result.needs_attention[0].needs_password_for, "mariadb");
        assert!(fx.www("site/partial.txt").exists());
        assert!(fx.www(&format!(".wcp-migrate-{ID}/site/old.txt")).exists());
        assert!(
            fx.base
                .join("state/wordpress-migrate-import/pending/abc.json")
                .exists()
        );
        assert_eq!(fx.calls(), "");
        assert_eq!(fx.transaction_status(&scope), TransactionStatus::InProgress);
        // A password for another container does not help.
        let other = r#"{"mariadbRootPasswords":{"other":"x"}}"#;
        assert_eq!(
            fx.run_as("123e4567-e89b-12d3-a456-426614174098", Some(other))
                .needs_attention
                .len(),
            1
        );
    }

    #[test]
    fn an_unfinished_dump_is_never_replayed() {
        let fx = Fx::new();
        fx.interrupted_db_operation(
            false,
            Some(true),
            Some("-- half a dump\nDROP DATABASE"),
            (true, true, true),
        );
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(result.needs_attention[0].reason.contains("incomplete"));
        assert_eq!(fx.calls(), "");
        assert!(fx.www("site/partial.txt").exists());
    }

    #[test]
    fn a_failing_database_replay_leaves_the_files_alone() {
        let fx = Fx::new();
        fx.interrupted_db_operation(false, Some(true), Some(DUMP), (true, true, true));
        fx.fake_docker(true);
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(
            fx.www("site/partial.txt").exists(),
            "files are not rolled back past a database that was not"
        );
        assert!(fx.www(&format!(".wcp-migrate-{ID}/site/old.txt")).exists());
        assert!(
            fx.base
                .join("state/wordpress-migrate-import/pending/abc.json")
                .exists()
        );
    }

    #[test]
    fn a_migrate_import_that_died_before_touching_the_site_is_only_cleared() {
        let fx = Fx::new();
        // The dump finished, the site was not yet moved aside: nothing to undo,
        // no password needed.
        fx.interrupted_db_operation(false, Some(true), Some(DUMP), (false, true, true));
        let result = fx.run();
        assert_eq!(result.cleared.len(), 1, "{result:?}");
        assert!(fx.www("site/partial.txt").exists());
        assert_eq!(fx.calls(), "");
    }

    #[test]
    fn a_site_the_migration_created_from_nothing_is_removed_and_the_database_restored() {
        let fx = Fx::new();
        fx.interrupted_db_operation(false, Some(false), Some(DUMP), (false, true, true));
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert!(!fx.www("site").exists());
        assert_eq!(fx.imported(), DUMP);
    }

    #[test]
    fn a_marker_that_cannot_say_whether_the_site_was_new_is_not_guessed_at() {
        let fx = Fx::new();
        fx.interrupted_db_operation(false, None, Some(DUMP), (false, true, true));
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert!(fx.www("site/partial.txt").exists());
    }

    #[test]
    fn a_database_snapshot_path_that_is_not_ours_is_refused() {
        let fx = Fx::new();
        fx.interrupted_db_operation(false, Some(true), Some(DUMP), (true, true, true));
        let marker = fx
            .base
            .join("state/wordpress-migrate-import/pending/abc.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&marker).unwrap()).unwrap();
        value["databaseSnapshot"] = serde_json::json!("/etc/passwd");
        fs::write(&marker, value.to_string()).unwrap();
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.needs_attention.len(), 1, "{result:?}");
        assert_eq!(fx.calls(), "");
    }

    #[test]
    fn a_killed_clone_is_rolled_back_in_its_staging_root() {
        let fx = Fx::new();
        let scope = fx.interrupted_db_operation(true, Some(true), Some(DUMP), (true, true, true));
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert_eq!(result.rolled_back[0].operation, "wordpress.clone");
        assert_eq!(fs::read_to_string(fx.www("site/old.txt")).unwrap(), "old");
        assert!(!fx.www("site/partial.txt").exists());
        assert!(!fx.www(&format!(".wcp-clone-{ID}")).exists());
        assert_eq!(fx.imported(), DUMP);
        assert!(
            !fx.base
                .join("state")
                .join(&scope)
                .join("pending.json")
                .exists()
        );
        assert!(
            fx.base
                .join(format!("recovery/wordpress-clone/{ID}/target.sql"))
                .exists(),
            "the clone keeps its recovery files, as its in-process rollback does"
        );
        assert_eq!(fx.transaction_status(&scope), TransactionStatus::Failed);
    }

    #[test]
    fn an_operation_that_committed_before_its_marker_went_is_not_rolled_back() {
        let fx = Fx::new();
        let scope = fx.interrupted_db_operation(false, Some(true), Some(DUMP), (true, true, true));
        let scope_root = fx
            .state
            .open_managed_dir(&SiteRelativePath::parse(&scope).unwrap())
            .unwrap();
        let path = SiteRelativePath::parse(format!("transactions/{ID}.json")).unwrap();
        let mut transaction = state::load(&scope_root, &path).unwrap();
        transaction.mark_committed(serde_json::json!({})).unwrap();
        state::save(&scope_root, &path, &transaction).unwrap();
        let result = fx.run_with(Some(PASSWORDS));
        assert_eq!(result.cleared.len(), 1, "{result:?}");
        assert!(
            fx.www("site/partial.txt").exists(),
            "the committed content stays"
        );
        assert!(
            !fx.base
                .join("state/wordpress-migrate-import/pending/abc.json")
                .exists()
        );
        assert_eq!(fx.calls(), "", "no database replay");
        assert_eq!(fx.transaction_status(&scope), TransactionStatus::Committed);
    }

    /// Records the calls `site.migrateRuntime` recovery makes.
    struct Recorder(std::cell::RefCell<Vec<String>>);

    type Step<T> = Result<T, crate::site_migrate_runtime::StepError>;

    impl crate::site_migrate_runtime::Backend for Recorder {
        fn read_route(&self, _: &crate::site::Domain) -> Step<crate::site_migrate_runtime::Route> {
            unreachable!("a journal in the preparing phase never reads the route")
        }
        fn read_identity(
            &self,
            _: &crate::site::RuntimeId,
            _: &crate::site::Domain,
        ) -> Step<Option<crate::site_migrate_runtime::Identity>> {
            unreachable!()
        }
        fn allocate_identity(
            &self,
            _: &crate::site::RuntimeId,
            _: &crate::site::Domain,
            _: &crate::site_migrate_runtime::Identity,
        ) -> Step<crate::site_migrate_runtime::Identity> {
            unreachable!()
        }
        fn write_service(
            &self,
            _: &crate::site::RuntimeId,
            _: &crate::site::Domain,
            _: &crate::site_migrate_runtime::Identity,
        ) -> Step<()> {
            unreachable!()
        }
        fn activate_exec_config(
            &self,
            _: &crate::site::RuntimeId,
            _: &crate::site::Domain,
            _: &str,
        ) -> Step<()> {
            unreachable!()
        }
        fn probe(
            &self,
            _: &str,
            _: &crate::site::Domain,
            _: &str,
            _: Option<&crate::site_migrate_runtime::HealthCheck>,
        ) -> Step<()> {
            unreachable!()
        }
        fn activate_route(
            &self,
            _: &crate::site::Domain,
            _: crate::site_migrate_runtime::RouteKind,
            _: &str,
            _: &crate::ingress::ConfigHash,
        ) -> Step<()> {
            unreachable!()
        }
        fn remove_exec_config(
            &self,
            pool: &crate::site::RuntimeId,
            _: &crate::site::Domain,
        ) -> Step<()> {
            self.0.borrow_mut().push(format!("exec:{pool}"));
            Ok(())
        }
        fn remove_service(
            &self,
            pool: &crate::site::RuntimeId,
            _: &crate::site::Domain,
        ) -> Step<()> {
            self.0.borrow_mut().push(format!("service:{pool}"));
            Ok(())
        }
        fn release_identity(
            &self,
            pool: &crate::site::RuntimeId,
            _: &crate::site::Domain,
        ) -> Step<()> {
            self.0.borrow_mut().push(format!("identity:{pool}"));
            Ok(())
        }
        fn stop_idle_pool(&self, pool: &crate::site::RuntimeId) -> Step<()> {
            self.0.borrow_mut().push(format!("stop:{pool}"));
            Ok(())
        }
    }

    #[test]
    fn an_interrupted_runtime_migration_is_found_and_finished_by_its_journal() {
        use crate::site_migrate_runtime::{Journal, Phase, RouteKind, TargetArtifacts};
        let fx = Fx::new();
        let scope_dir = fx.base.join("state/site-migrate-runtime/shop.example.test");
        for sub in ["pending", "transactions", "locks"] {
            fs::create_dir_all(scope_dir.join(sub)).unwrap();
        }
        let journal = Journal {
            request_id: ID.into(),
            domain: "shop.example.test".into(),
            from_runtime: "php83".into(),
            to_runtime: "php84".into(),
            route_kind: RouteKind::Live,
            previous_route: "x".into(),
            previous_route_sha256: "a".repeat(64),
            new_route_sha256: "b".repeat(64),
            phase: Phase::Preparing,
            stop_idle_source: false,
            target: TargetArtifacts {
                identity: true,
                service: false,
                exec_config: false,
            },
        };
        fs::write(
            scope_dir.join(format!("pending/{ID}.json")),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        fx.start_transaction(
            "site-migrate-runtime/shop.example.test",
            "site.migrateRuntime",
        );

        let recorder = Recorder(Default::default());
        let result = reconcile(
            &Context {
                engine_state: &fx.state,
                state_root: &fx.base.join("state"),
                content_roots: &fx.roots,
                recovery_root: Some(&fx.recovery_root),
                docker_program: &fx.docker,
                migrate: Some(&recorder),
            },
            &Request::parse(RECONCILE_ID, None).unwrap(),
        )
        .unwrap();
        assert_eq!(result.rolled_back.len(), 1, "{result:?}");
        assert_eq!(result.rolled_back[0].operation, "site.migrateRuntime");
        assert_eq!(result.rolled_back[0].dest_root, "shop.example.test");
        assert_eq!(*recorder.0.borrow(), ["identity:php84"]);
        assert!(!scope_dir.join(format!("pending/{ID}.json")).exists());
        assert_eq!(
            fx.transaction_status("site-migrate-runtime/shop.example.test"),
            TransactionStatus::Failed
        );
    }

    #[test]
    fn the_request_file_is_validated() {
        let ok = |d| Request::parse(RECONCILE_ID, Some(d)).is_ok();
        assert!(ok("{}"));
        assert!(ok(PASSWORDS));
        assert!(!ok("{"));
        assert!(!ok(r#"{"mariadbRootPasswords":{"bad name":"x"}}"#));
        assert!(!ok(r#"{"mariadbRootPasswords":{"c":""}}"#));
        assert!(!ok(r#"{"other":1}"#));
        assert!(Request::parse("nope", None).is_err());
    }

    #[test]
    fn the_single_marker_of_the_old_migrate_import_is_counted_not_touched() {
        let fx = Fx::new();
        let dir = fx.base.join("state/wordpress-migrate-import");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("pending.json"), "{}").unwrap();
        assert_eq!(fx.run().other_pending, 1);
        assert!(dir.join("pending.json").exists());
    }
}
