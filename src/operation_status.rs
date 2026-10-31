use std::io::Read;

use serde::Serialize;

use crate::{
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath},
    transaction::{
        RequestId, lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    InvalidSiteId,
    InvalidDatabase,
    InvalidRequestId,
    InvalidScope,
    NotFound,
    Corrupt,
    Io,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationStatus {
    #[serde(flatten)]
    pub transaction: TransactionState,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<&'static str>,
}

pub fn load_site(
    engine_state: &ManagedRoot,
    site_id: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let site_id = SiteId::parse(site_id).map_err(|_| StatusError::InvalidSiteId)?;
    let site_path = SiteRelativePath::parse(format!("sites/{site_id}"))
        .expect("a canonical site id always produces a safe relative path");
    load_scoped(engine_state, &site_path, request_id)
}

pub fn load_database(
    engine_state: &ManagedRoot,
    database: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let database = crate::db_restore::DatabaseName::parse(database)
        .map_err(|_| StatusError::InvalidDatabase)?;
    let scope_path = SiteRelativePath::parse(format!("db-restore/{}", database.as_str()))
        .expect("a validated database name always produces a safe relative path");
    load_scoped(engine_state, &scope_path, request_id)
}

pub fn load_backup(
    engine_state: &ManagedRoot,
    database: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let database = crate::db_restore::DatabaseName::parse(database)
        .map_err(|_| StatusError::InvalidDatabase)?;
    let scope_path = SiteRelativePath::parse(format!("db-backup/{}", database.as_str()))
        .expect("a validated database name always produces a safe relative path");
    load_scoped(engine_state, &scope_path, request_id)
}

/// The managed WCP stack is the only stack; any other name is an invalid
/// scope rather than a missing record.
pub fn load_stack(
    engine_state: &ManagedRoot,
    stack: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    if stack != "wcp" {
        return Err(StatusError::InvalidScope);
    }
    let scope_path = SiteRelativePath::parse("stacks/wcp").expect("literal path is valid");
    load_scoped(engine_state, &scope_path, request_id)
}

/// Largest page `operation.list` will return; larger requests are clamped.
pub const LIST_MAX_LIMIT: usize = 100;
pub const LIST_DEFAULT_LIMIT: usize = 20;
pub const LIST_SCAN_MAX_ENTRIES: usize = 1000;
pub const LIST_RECORD_MAX_BYTES: usize = 1024 * 1024;
pub const LIST_SCAN_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The only safe next step the engine can name for a transaction. `unknown`
/// or interrupted work never maps to an automatic destructive retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NextAction {
    /// Finished; nothing to recover.
    None,
    /// The owning request still holds the mutation lock.
    Wait,
    /// Interrupted with no live owner: needs operation-specific recovery.
    ManualRecovery,
}

/// Redacted one-line view of a transaction. Never carries the stored result,
/// the error message text or the idempotency key.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSummary {
    pub request_id: RequestId,
    pub operation: String,
    pub status: TransactionStatus,
    pub started_at_unix_secs: u64,
    pub finished_at_unix_secs: Option<u64>,
    pub error_code: Option<crate::error::ErrorCode>,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<&'static str>,
    pub next_action: NextAction,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationList {
    pub operations: Vec<OperationSummary>,
    /// Records that exist but could not be read; never silently dropped.
    pub unreadable: usize,
    /// True when more records exist than `operations` holds.
    pub truncated: bool,
    /// The scan hit its entry or byte budget; results may omit newer records.
    pub scan_truncated: bool,
}

fn scope_path(
    site_id: Option<&str>,
    database: Option<&str>,
    backup_database: Option<&str>,
    stack: Option<&str>,
) -> Result<SiteRelativePath, StatusError> {
    let path = match (site_id, database, backup_database, stack) {
        (Some(site_id), None, None, None) => {
            let site_id = SiteId::parse(site_id).map_err(|_| StatusError::InvalidSiteId)?;
            format!("sites/{site_id}")
        }
        (None, Some(database), None, None) => {
            let database = crate::db_restore::DatabaseName::parse(database)
                .map_err(|_| StatusError::InvalidDatabase)?;
            format!("db-restore/{}", database.as_str())
        }
        (None, None, Some(database), None) => {
            let database = crate::db_restore::DatabaseName::parse(database)
                .map_err(|_| StatusError::InvalidDatabase)?;
            format!("db-backup/{}", database.as_str())
        }
        (None, None, None, Some("wcp")) => "stacks/wcp".to_owned(),
        _ => return Err(StatusError::InvalidScope),
    };
    Ok(SiteRelativePath::parse(path).expect("validated identifiers produce safe relative paths"))
}

/// Lists unfinished transactions first, newest within each group, without executing anything.
/// A scope that never ran a mutation is an empty list, not `NotFound`.
pub fn list(
    engine_state: &ManagedRoot,
    site_id: Option<&str>,
    database: Option<&str>,
    backup_database: Option<&str>,
    stack: Option<&str>,
    limit: Option<usize>,
) -> Result<OperationList, StatusError> {
    let scope = scope_path(site_id, database, backup_database, stack)?;
    list_scoped(engine_state, &scope, limit)
}

pub fn load_create(
    engine_state: &ManagedRoot,
    domain: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let domain = crate::site::Domain::parse(domain).map_err(|_| StatusError::InvalidScope)?;
    load_scoped(
        engine_state,
        &SiteRelativePath::parse(format!("site-create/{domain}")).unwrap(),
        request_id,
    )
}
pub fn list_create(
    engine_state: &ManagedRoot,
    domain: &str,
    limit: Option<usize>,
) -> Result<OperationList, StatusError> {
    let domain = crate::site::Domain::parse(domain).map_err(|_| StatusError::InvalidScope)?;
    list_scoped(
        engine_state,
        &SiteRelativePath::parse(format!("site-create/{domain}")).unwrap(),
        limit,
    )
}
/// Closed mapping: resource strings can never select arbitrary state directories.
pub fn resource_scope(
    content_roots: &[crate::site::TrustedRoot],
    operation: &str,
    resource: &str,
) -> Result<SiteRelativePath, StatusError> {
    let root_prefix = match operation {
        "wordpress.clone" => Some("wordpress-clone"),
        "joomla.clone" => Some("joomla-clone"),
        "wordpress.import" => Some("wordpress-import"),
        "wordpress.install" => Some("wordpress-install"),
        "wordpress.updateCore" | "wordpress.updatePlugins" | "wordpress.updateThemes" => {
            Some("wordpress-update")
        }
        "wordpress.boundedAction" | "wordpress.typedActions" => Some("wordpress-bounded-action"),
        _ => None,
    };
    let path = if let Some(prefix) = root_prefix {
        let root = std::path::Path::new(resource);
        if resource.len() > 4096
            || !root.is_absolute()
            || root
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            || !content_roots
                .iter()
                .any(|base| root.starts_with(base.as_path()) && root != base.as_path())
        {
            return Err(StatusError::InvalidScope);
        }
        format!(
            "{prefix}/{}",
            crate::transaction::resource_lock::canonical_hash(root)
        )
    } else {
        match operation {
            "site.importArchive" | "wordpress.migrateImport" | "wordpress.migrateExport" => {
                let root = std::path::Path::new(resource);
                if resource.len() > 4096
                    || !root.is_absolute()
                    || root
                        .components()
                        .any(|p| matches!(p, std::path::Component::ParentDir))
                    || !content_roots
                        .iter()
                        .any(|base| root.starts_with(base.as_path()) && root != base.as_path())
                {
                    return Err(StatusError::InvalidScope);
                }
                match operation {
                    "site.importArchive" => "site-archive-import",
                    "wordpress.migrateImport" => "wordpress-migrate-import",
                    _ => "wordpress-migrate-export",
                }
                .into()
            }
            "site.recoverContent" => format!(
                "site-content-recovery/{}",
                RequestId::parse(resource).map_err(|_| StatusError::InvalidScope)?
            ),
            "site.migrateRuntime" => format!(
                "site-migrate-runtime/{}",
                crate::site::Domain::parse(resource).map_err(|_| StatusError::InvalidScope)?
            ),
            "runtime.activateConfig" => format!(
                "runtime-config/{}",
                crate::site::RuntimeId::parse(resource).map_err(|_| StatusError::InvalidScope)?
            ),
            "meilisearch.upgrade" => {
                let name = crate::db_restore::ContainerName::parse(resource)
                    .map_err(|_| StatusError::InvalidScope)?;
                if resource.starts_with(['.', '-']) {
                    return Err(StatusError::InvalidScope);
                }
                format!("meilisearch/{}", name.as_str())
            }
            "docker.imagePull"
                if !resource.is_empty()
                    && resource.len() <= 2048
                    && !resource.chars().any(char::is_control) =>
            {
                "docker-resource".into()
            }
            "system.installDocker" if resource == "server" => "system-install-docker".into(),
            "system.startDocker" if resource == "server" => "system-start-docker".into(),
            _ => return Err(StatusError::InvalidScope),
        }
    };
    SiteRelativePath::parse(path).map_err(|_| StatusError::InvalidScope)
}
pub fn load_resource(
    root: &ManagedRoot,
    content_roots: &[crate::site::TrustedRoot],
    operation: &str,
    resource: &str,
    id: &str,
) -> Result<OperationStatus, StatusError> {
    let scope = resource_scope(content_roots, operation, resource)?;
    let mut status = load_scoped(root, &scope, id)?;
    if status.transaction.operation != operation {
        return Err(StatusError::Corrupt);
    }
    if let Some(outcome) = status.transaction.outcome.as_mut() {
        outcome.result = if outcome.ok {
            Some(serde_json::json!({"outcomeKnown":true}))
        } else {
            None
        };
        outcome.error_message = if outcome.ok {
            None
        } else {
            Some("The remote operation failed; inspect its original invocation result".into())
        };
    }
    Ok(status)
}

fn list_scoped(
    engine_state: &ManagedRoot,
    scope: &SiteRelativePath,
    limit: Option<usize>,
) -> Result<OperationList, StatusError> {
    let limit = limit.unwrap_or(LIST_DEFAULT_LIMIT).clamp(1, LIST_MAX_LIMIT);
    let scope_dir = match engine_state.open_managed_dir(scope) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OperationList {
                operations: Vec::new(),
                unreadable: 0,
                truncated: false,
                scan_truncated: false,
            });
        }
        Err(_) => return Err(StatusError::Io),
    };
    let transactions = SiteRelativePath::parse("transactions").unwrap();
    let transactions_dir = match scope_dir.open_managed_dir(&transactions) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OperationList {
                operations: Vec::new(),
                unreadable: 0,
                truncated: false,
                scan_truncated: false,
            });
        }
        Err(_) => return Err(StatusError::Io),
    };
    let lock_path = SiteRelativePath::parse("locks/mutation.lock").unwrap();
    let owner = lock::holder(&scope_dir, &lock_path).map_err(|_| StatusError::Io)?;
    let (names, mut scan_truncated) = transactions_dir
        .file_names_bounded(LIST_SCAN_MAX_ENTRIES)
        .map_err(|_| StatusError::Io)?;
    let mut unreadable = 0;
    let mut records = Vec::new();
    let mut remaining_bytes = LIST_SCAN_MAX_BYTES;
    for name in names.into_iter().filter(|name| name.ends_with(".json")) {
        // Reserve enough budget to distinguish a full record from an oversized one.
        if remaining_bytes <= 1 {
            scan_truncated = true;
            break;
        }
        let path = match SiteRelativePath::parse(&name) {
            Ok(path) => path,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let maximum = LIST_RECORD_MAX_BYTES.min(remaining_bytes - 1);
        let loaded = read_list_record(&transactions_dir, &path, maximum, &mut remaining_bytes);
        match loaded {
            Ok(record)
                if name == format!("{}.json", record.request_id)
                    && record.operation.len() <= 128
                    && record
                        .operation
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.') =>
            {
                records.push(record);
            }
            _ => unreadable += 1,
        }
    }
    scan_truncated |= remaining_bytes <= 1;
    records.sort_by(|a, b| {
        (b.status == TransactionStatus::InProgress)
            .cmp(&(a.status == TransactionStatus::InProgress))
            .then_with(|| b.started_at_unix_secs.cmp(&a.started_at_unix_secs))
            .then_with(|| a.request_id.to_string().cmp(&b.request_id.to_string()))
    });
    let truncated = records.len() > limit;
    let operations = records
        .into_iter()
        .take(limit)
        .map(|record| {
            let in_progress = record.status == TransactionStatus::InProgress;
            let active = in_progress && owner == Some(record.request_id);
            let next_action = match (in_progress, active) {
                (false, _) => NextAction::None,
                (true, true) => NextAction::Wait,
                (true, false) => NextAction::ManualRecovery,
            };
            let recovery_action = recovery_action(&scope_dir, &record, active);
            OperationSummary {
                request_id: record.request_id,
                operation: record.operation,
                status: record.status,
                started_at_unix_secs: record.started_at_unix_secs,
                finished_at_unix_secs: record.finished_at_unix_secs,
                error_code: record.outcome.and_then(|outcome| outcome.error_code),
                active,
                next_action,
                recovery_action,
            }
        })
        .collect();
    Ok(OperationList {
        operations,
        unreadable,
        truncated,
        scan_truncated,
    })
}

// Read only regular, capability-scoped records. Limits apply before JSON
// deserialization, so a corrupt or unexpectedly large outcome cannot exhaust RAM.
fn read_list_record(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    maximum: usize,
    remaining: &mut usize,
) -> Result<TransactionState, StatusError> {
    let metadata = root.symlink_metadata(path).map_err(|_| StatusError::Io)?;
    if !metadata.is_file() {
        return Err(StatusError::Corrupt);
    }
    if metadata.len() > maximum as u64 {
        if metadata.len() <= LIST_RECORD_MAX_BYTES as u64 {
            *remaining = 0;
        }
        return Err(StatusError::Corrupt);
    }
    let file = root.open_regular_read(path).map_err(|_| StatusError::Io)?;
    let mut bytes = Vec::new();
    let read_result = file.take(maximum as u64 + 1).read_to_end(&mut bytes);
    *remaining = remaining.saturating_sub(bytes.len());
    read_result.map_err(|_| StatusError::Io)?;
    if bytes.len() > maximum {
        return Err(StatusError::Corrupt);
    }
    let record = state::decode(&bytes).map_err(|_| StatusError::Corrupt)?;
    let consistent = match record.status {
        TransactionStatus::InProgress => {
            record.finished_at_unix_secs.is_none() && record.outcome.is_none()
        }
        TransactionStatus::Committed => {
            record.finished_at_unix_secs.is_some()
                && record.outcome.as_ref().is_some_and(|outcome| outcome.ok)
        }
        TransactionStatus::Failed => {
            record.finished_at_unix_secs.is_some()
                && record.outcome.as_ref().is_some_and(|outcome| !outcome.ok)
        }
    };
    if !consistent {
        return Err(StatusError::Corrupt);
    }
    Ok(record)
}

/// One interrupted transaction found by [`incomplete`].
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncompleteOperation {
    /// The scope directory below the state root, e.g. `site-archive-import`
    /// or `sites/<id>`.
    pub scope: String,
    pub request_id: RequestId,
    pub operation: String,
    pub started_at_unix_secs: u64,
    /// The operation that finishes this one, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_by: Option<&'static str>,
}

/// Operations whose interrupted runs `site.reconcile` rolls back.
const RECONCILED: [&str; 5] = [
    "site.importArchive",
    "wordpress.migrateImport",
    "wordpress.clone",
    "joomla.clone",
    "site.migrateRuntime",
];

/// A recovery marker (`pending/*.json`) found by [`incomplete`].
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingMarker {
    pub scope: String,
    pub name: String,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncompleteList {
    /// `IN_PROGRESS` transactions whose owner no longer holds the lock.
    pub interrupted: Vec<IncompleteOperation>,
    /// Transactions still running right now (not a problem).
    pub active: usize,
    /// Recovery markers waiting for `site.reconcile` or an operator.
    pub markers: Vec<PendingMarker>,
    /// Transaction records that could not be read.
    pub unreadable: usize,
}

/// Finds every scope below the state root (two levels deep) that has a
/// `transactions/` directory and reports the interrupted ones. Reads only.
pub fn incomplete(
    engine_state: &ManagedRoot,
    state_root: &std::path::Path,
) -> Result<IncompleteList, StatusError> {
    let mut scopes = Vec::new();
    collect_scopes(state_root, std::path::Path::new(""), 0, &mut scopes);
    scopes.sort();
    let mut list = IncompleteList {
        interrupted: Vec::new(),
        active: 0,
        markers: Vec::new(),
        unreadable: 0,
    };
    for scope in scopes {
        let Ok(path) = SiteRelativePath::parse(scope.to_string_lossy().as_ref()) else {
            continue;
        };
        let Ok(dir) = engine_state.open_managed_dir(&path) else {
            continue;
        };
        let label = scope.to_string_lossy().into_owned();
        if let Ok(pending) = dir.open_managed_dir(&SiteRelativePath::parse("pending").unwrap()) {
            let mut names = pending.file_names().unwrap_or_default();
            names.sort();
            list.markers
                .extend(names.into_iter().map(|name| PendingMarker {
                    scope: label.clone(),
                    name,
                }));
        }
        // `wordpress.clone` keeps one marker per scope, not a `pending/` directory.
        if dir.exists(&SiteRelativePath::parse("pending.json").unwrap()) {
            list.markers.push(PendingMarker {
                scope: label.clone(),
                name: "pending.json".into(),
            });
        }
        let Ok(transactions) =
            dir.open_managed_dir(&SiteRelativePath::parse("transactions").unwrap())
        else {
            continue;
        };
        let lock_path = SiteRelativePath::parse("locks/mutation.lock").unwrap();
        // A scope without a lock file has never run a mutation: no owner.
        let owner = if dir.exists(&SiteRelativePath::parse("locks").unwrap()) {
            lock::holder(&dir, &lock_path).map_err(|_| StatusError::Io)?
        } else {
            None
        };
        let mut names = transactions.file_names().map_err(|_| StatusError::Io)?;
        names.sort();
        for name in names.into_iter().filter(|n| n.ends_with(".json")) {
            let Ok(path) = SiteRelativePath::parse(&name) else {
                list.unreadable += 1;
                continue;
            };
            match state::load(&transactions, &path) {
                Ok(record) if record.status == TransactionStatus::InProgress => {
                    if owner == Some(record.request_id) {
                        list.active += 1;
                    } else {
                        list.interrupted.push(IncompleteOperation {
                            scope: label.clone(),
                            request_id: record.request_id,
                            recovered_by: RECONCILED
                                .contains(&record.operation.as_str())
                                .then_some("site.reconcile"),
                            operation: record.operation,
                            started_at_unix_secs: record.started_at_unix_secs,
                        });
                    }
                }
                Ok(_) => {}
                Err(_) => list.unreadable += 1,
            }
        }
    }
    Ok(list)
}

fn collect_scopes(
    root: &std::path::Path,
    relative: &std::path::Path,
    depth: usize,
    out: &mut Vec<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(root.join(relative)) else {
        return;
    };
    if !relative.as_os_str().is_empty() && root.join(relative).join("transactions").is_dir() {
        out.push(relative.to_path_buf());
        return;
    }
    if depth >= 2 {
        return;
    }
    for entry in entries.flatten() {
        // A symlink is never followed.
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_scopes(root, &relative.join(entry.file_name()), depth + 1, out);
        }
    }
}

fn load_scoped(
    engine_state: &ManagedRoot,
    scope_path: &SiteRelativePath,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let request_id = RequestId::parse(request_id).map_err(|_| StatusError::InvalidRequestId)?;
    let site_state = engine_state.open_managed_dir(scope_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StatusError::NotFound
        } else {
            StatusError::Io
        }
    })?;
    let transaction_path = SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical request id always produces a safe relative path");
    let metadata = site_state
        .symlink_metadata(&transaction_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StatusError::NotFound
            } else {
                StatusError::Io
            }
        })?;
    if !metadata.is_file() || metadata.len() > LIST_RECORD_MAX_BYTES as u64 {
        return Err(StatusError::Corrupt);
    }
    let mut remaining = LIST_RECORD_MAX_BYTES;
    let transaction = read_list_record(
        &site_state,
        &transaction_path,
        LIST_RECORD_MAX_BYTES,
        &mut remaining,
    )?;
    if transaction.request_id != request_id {
        return Err(StatusError::Corrupt);
    }
    let active = if transaction.status == TransactionStatus::InProgress {
        let lock_path = SiteRelativePath::parse("locks/mutation.lock").unwrap();
        lock::holder(&site_state, &lock_path).map_err(|_| StatusError::Io)?
            == Some(transaction.request_id)
    } else {
        false
    };
    let recovery_action = recovery_action(&site_state, &transaction, active);
    Ok(OperationStatus {
        recovery_action,
        transaction,
        active,
    })
}

fn recovery_action(
    scope: &ManagedRoot,
    record: &state::TransactionState,
    active: bool,
) -> Option<&'static str> {
    if active {
        None
    } else if crate::deployment_recovery::available(scope, record) {
        Some("site.recoverDeployment")
    } else if crate::db_restore::protected::available(scope, record) {
        Some("db.recoverRestore")
    } else if crate::site_create::available(scope, record) {
        Some("site.recoverCreate")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        site::TrustedRoot,
        transaction::state::{TransactionState, TransactionStatus, create},
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn state_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(directory.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        let transactions =
            SiteRelativePath::parse(format!("sites/{SITE_ID}/transactions")).unwrap();
        root.create_dir_all(&transactions).unwrap();
        root.create_dir_all(&SiteRelativePath::parse(format!("sites/{SITE_ID}/locks")).unwrap())
            .unwrap();
        (directory, root)
    }

    #[test]
    fn loads_the_exact_site_scoped_transaction() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        let request_id = RequestId::parse(REQUEST_ID).unwrap();
        let state = TransactionState::start(request_id, None, "site.deploy");
        create(
            &site,
            &SiteRelativePath::parse(format!("transactions/{REQUEST_ID}.json")).unwrap(),
            &state,
        )
        .unwrap();

        let loaded = load_site(&root, SITE_ID, REQUEST_ID).unwrap();
        assert_eq!(loaded.transaction.request_id, request_id);
        assert_eq!(loaded.transaction.status, TransactionStatus::InProgress);
        assert!(!loaded.active);
    }

    #[test]
    fn rejects_invalid_identifiers_and_reports_missing_state() {
        let (_directory, root) = state_root();
        assert_eq!(
            load_site(&root, "../site", REQUEST_ID),
            Err(StatusError::InvalidSiteId)
        );
        assert_eq!(
            load_site(&root, SITE_ID, "../request"),
            Err(StatusError::InvalidRequestId)
        );
        assert_eq!(
            load_site(&root, SITE_ID, "9b2f1c34-5678-4abc-9def-0123456789ab"),
            Err(StatusError::NotFound)
        );
    }

    #[test]
    fn in_progress_is_active_only_while_the_same_request_holds_the_lock() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        let request_id = RequestId::parse(REQUEST_ID).unwrap();
        create(
            &site,
            &SiteRelativePath::parse(format!("transactions/{REQUEST_ID}.json")).unwrap(),
            &TransactionState::start(request_id, None, "site.deploy"),
        )
        .unwrap();
        let guard = crate::transaction::lock::acquire(
            &site,
            &SiteRelativePath::parse("locks/mutation.lock").unwrap(),
            request_id,
        )
        .unwrap();

        assert!(load_site(&root, SITE_ID, REQUEST_ID).unwrap().active);
        drop(guard);
        assert!(!load_site(&root, SITE_ID, REQUEST_ID).unwrap().active);
    }

    #[test]
    fn loads_a_database_scoped_restore_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(directory.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        for child in ["locks", "transactions"] {
            root.create_dir_all(
                &SiteRelativePath::parse(format!("db-restore/site_db/{child}")).unwrap(),
            )
            .unwrap();
        }
        let scope = root
            .open_managed_dir(&SiteRelativePath::parse("db-restore/site_db").unwrap())
            .unwrap();
        let request_id = RequestId::parse(REQUEST_ID).unwrap();
        create(
            &scope,
            &SiteRelativePath::parse(format!("transactions/{REQUEST_ID}.json")).unwrap(),
            &TransactionState::start(request_id, None, "db.restore"),
        )
        .unwrap();

        let loaded = load_database(&root, "site_db", REQUEST_ID).unwrap();
        assert_eq!(loaded.transaction.operation, "db.restore");
        assert!(!loaded.active);
    }

    #[test]
    fn loads_a_database_scoped_backup_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(directory.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        for child in ["locks", "transactions"] {
            root.create_dir_all(
                &SiteRelativePath::parse(format!("db-backup/site_db/{child}")).unwrap(),
            )
            .unwrap();
        }
        let scope = root
            .open_managed_dir(&SiteRelativePath::parse("db-backup/site_db").unwrap())
            .unwrap();
        let request_id = RequestId::parse(REQUEST_ID).unwrap();
        create(
            &scope,
            &SiteRelativePath::parse(format!("transactions/{REQUEST_ID}.json")).unwrap(),
            &TransactionState::start(request_id, None, "backup.createDatabase"),
        )
        .unwrap();

        let loaded = load_backup(&root, "site_db", REQUEST_ID).unwrap();
        assert_eq!(loaded.transaction.operation, "backup.createDatabase");
        assert!(!loaded.active);
    }

    #[test]
    fn lists_newest_first_redacted_with_next_actions() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        let ids = [
            "123e4567-e89b-12d3-a456-426614174000",
            "223e4567-e89b-12d3-a456-426614174000",
            "323e4567-e89b-12d3-a456-426614174000",
        ];
        for (index, id) in ids.iter().enumerate() {
            let request_id = RequestId::parse(id).unwrap();
            let mut state = TransactionState::start(request_id, None, "site.deploy");
            state.started_at_unix_secs = 1_000 + index as u64;
            if index == 0 {
                state
                    .mark_failed(crate::error::ErrorCode::Internal, "secret path /root/x")
                    .unwrap();
            }
            create(
                &site,
                &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
                &state,
            )
            .unwrap();
        }
        let guard = crate::transaction::lock::acquire(
            &site,
            &SiteRelativePath::parse("locks/mutation.lock").unwrap(),
            RequestId::parse(ids[2]).unwrap(),
        )
        .unwrap();

        let listed = list(&root, Some(SITE_ID), None, None, None, None).unwrap();
        let order: Vec<String> = listed
            .operations
            .iter()
            .map(|entry| entry.request_id.to_string())
            .collect();
        assert_eq!(order, [ids[2], ids[1], ids[0]]);
        assert_eq!(listed.operations[0].next_action, NextAction::Wait);
        assert!(listed.operations[0].active);
        assert_eq!(listed.operations[1].next_action, NextAction::ManualRecovery);
        assert_eq!(listed.operations[2].next_action, NextAction::None);
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("secret path"));
        assert!(!json.contains("idempotencyKey"));
        drop(guard);

        let page = list(&root, Some(SITE_ID), None, None, None, Some(2)).unwrap();
        assert_eq!(page.operations.len(), 2);
        assert!(page.truncated);
    }

    #[test]
    fn older_interrupted_operation_stays_discoverable_ahead_of_newer_terminal_records() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        for (index, unfinished) in [true, false, false].into_iter().enumerate() {
            let id = RequestId::parse(&format!("{index:08x}-e89b-12d3-a456-426614174000")).unwrap();
            let mut record = TransactionState::start(id, None, "site.deploy");
            record.started_at_unix_secs = index as u64;
            if !unfinished {
                record
                    .mark_failed(crate::error::ErrorCode::Conflict, "rejected")
                    .unwrap();
            }
            create(
                &site,
                &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
                &record,
            )
            .unwrap();
        }
        let page = list(&root, Some(SITE_ID), None, None, None, Some(1)).unwrap();
        assert_eq!(page.operations.len(), 1);
        assert_eq!(page.operations[0].next_action, NextAction::ManualRecovery);
        assert!(page.truncated);
    }

    #[test]
    fn list_of_an_unused_scope_is_empty_and_bad_scopes_are_rejected() {
        let (_directory, root) = state_root();
        let empty = list(
            &root,
            Some("660e8400-e29b-41d4-a716-446655440000"),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(empty.operations.is_empty() && !empty.truncated);
        assert_eq!(
            list(&root, None, None, None, Some("other"), None),
            Err(StatusError::InvalidScope)
        );
        assert_eq!(
            list(&root, None, None, None, None, None),
            Err(StatusError::InvalidScope)
        );
    }

    #[test]
    fn list_counts_unreadable_records_instead_of_hiding_them() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        site.write_atomic(
            &SiteRelativePath::parse("transactions/garbage.json").unwrap(),
            b"{",
        )
        .unwrap();
        let listed = list(&root, Some(SITE_ID), None, None, None, None).unwrap();
        assert_eq!(listed.unreadable, 1);
    }

    #[test]
    fn list_reports_incomplete_scan_at_the_directory_entry_budget() {
        let (directory, root) = state_root();
        let transactions = directory
            .path()
            .join(format!("sites/{SITE_ID}/transactions"));
        for index in 0..=LIST_SCAN_MAX_ENTRIES {
            std::fs::write(transactions.join(format!("{index}.tmp")), "").unwrap();
        }
        let result = list(&root, Some(SITE_ID), None, None, None, None).unwrap();
        assert!(result.scan_truncated);
        assert!(!result.truncated);
        assert!(result.operations.is_empty());
    }

    #[test]
    fn list_rejects_oversized_mismatched_and_symlink_records() {
        let (directory, root) = state_root();
        let transactions = directory
            .path()
            .join(format!("sites/{SITE_ID}/transactions"));
        std::fs::write(
            transactions.join("oversized.json"),
            vec![b' '; LIST_RECORD_MAX_BYTES + 1],
        )
        .unwrap();
        let record =
            TransactionState::start(RequestId::parse(REQUEST_ID).unwrap(), None, "site.deploy");
        std::fs::write(
            transactions.join("mismatch.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            transactions.join("mismatch.json"),
            transactions.join("link.json"),
        )
        .unwrap();
        let result = list(&root, Some(SITE_ID), None, None, None, None).unwrap();
        assert!(result.operations.is_empty());
        assert_eq!(result.unreadable, if cfg!(unix) { 3 } else { 2 });
        assert!(!result.scan_truncated);
    }

    #[test]
    fn invalid_terminal_outcome_is_unreadable_instead_of_reported_as_success() {
        let (_directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        let id = RequestId::parse(REQUEST_ID).unwrap();
        let mut record = TransactionState::start(id, None, "site.deploy");
        record.status = TransactionStatus::Committed;
        create(
            &site,
            &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
            &record,
        )
        .unwrap();
        let result = list(&root, Some(SITE_ID), None, None, None, None).unwrap();
        assert!(result.operations.is_empty());
        assert_eq!(result.unreadable, 1);
    }

    #[test]
    fn list_reports_total_read_budget_without_publishing_partial_records() {
        let (directory, root) = state_root();
        let transactions = directory
            .path()
            .join(format!("sites/{SITE_ID}/transactions"));
        for index in 0..20 {
            let id = RequestId::parse(&format!("{index:08x}-e89b-12d3-a456-426614174000")).unwrap();
            let mut record = TransactionState::start(id, None, "site.deploy");
            record
                .mark_committed(serde_json::json!({"secret": "x".repeat(900_000)}))
                .unwrap();
            std::fs::write(
                transactions.join(format!("{id}.json")),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        let result = list(&root, Some(SITE_ID), None, None, None, Some(100)).unwrap();
        assert!(result.scan_truncated);
        assert!(result.operations.len() < 20);
        assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
    }

    #[test]
    fn incomplete_finds_interrupted_work_and_markers_in_every_scope() {
        let (directory, root) = state_root();
        let site = root
            .open_managed_dir(&SiteRelativePath::parse(format!("sites/{SITE_ID}")).unwrap())
            .unwrap();
        let stuck = RequestId::parse("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let done = RequestId::parse("223e4567-e89b-12d3-a456-426614174000").unwrap();
        let mut finished = TransactionState::start(done, None, "site.deploy");
        finished
            .mark_failed(crate::error::ErrorCode::Internal, "x")
            .unwrap();
        for (id, state) in [
            (stuck, TransactionState::start(stuck, None, "site.deploy")),
            (done, finished),
        ] {
            create(
                &site,
                &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
                &state,
            )
            .unwrap();
        }
        // A second, single-level scope with a recovery marker and no transaction.
        let import = directory.path().join("site-archive-import");
        std::fs::create_dir_all(import.join("pending")).unwrap();
        std::fs::create_dir_all(import.join("transactions")).unwrap();
        std::fs::write(import.join("pending/abc.json"), "{}").unwrap();

        let found = incomplete(&root, directory.path()).unwrap();
        assert_eq!(found.interrupted.len(), 1, "{found:?}");
        assert_eq!(found.interrupted[0].request_id, stuck);
        assert_eq!(found.interrupted[0].scope, format!("sites/{SITE_ID}"));
        assert_eq!(found.active, 0);
        assert_eq!(
            found.markers,
            vec![PendingMarker {
                scope: "site-archive-import".into(),
                name: "abc.json".into()
            }]
        );
    }

    #[test]
    fn incomplete_sees_clone_markers_and_names_the_recoverer() {
        let directory = tempfile::tempdir().unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let scope = directory.path().join("wordpress-clone/abc");
        for sub in ["transactions", "locks"] {
            std::fs::create_dir_all(scope.join(sub)).unwrap();
        }
        std::fs::write(scope.join("pending.json"), "{}").unwrap();
        let id = RequestId::parse("323e4567-e89b-12d3-a456-426614174000").unwrap();
        let other = RequestId::parse("423e4567-e89b-12d3-a456-426614174000").unwrap();
        let dir = root
            .open_managed_dir(&SiteRelativePath::parse("wordpress-clone/abc").unwrap())
            .unwrap();
        for (id, operation) in [(id, "wordpress.clone"), (other, "site.deploy")] {
            create(
                &dir,
                &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
                &TransactionState::start(id, None, operation),
            )
            .unwrap();
        }
        let found = incomplete(&root, directory.path()).unwrap();
        assert_eq!(
            found.markers,
            vec![PendingMarker {
                scope: "wordpress-clone/abc".into(),
                name: "pending.json".into()
            }]
        );
        let by = |op: &str| {
            found
                .interrupted
                .iter()
                .find(|i| i.operation == op)
                .unwrap()
                .recovered_by
        };
        assert_eq!(by("wordpress.clone"), Some("site.reconcile"));
        assert_eq!(by("site.deploy"), None);
    }

    #[test]
    fn incomplete_on_an_empty_state_root_is_empty() {
        let directory = tempfile::tempdir().unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let found = incomplete(&root, directory.path()).unwrap();
        assert!(found.interrupted.is_empty() && found.markers.is_empty());
    }
    #[test]
    fn fixed_resource_scopes_are_bounded_and_cannot_select_arbitrary_state() {
        let base = tempfile::tempdir().unwrap();
        let content = crate::site::TrustedRoot::parse(base.path()).unwrap();
        let roots = [content];
        let resource = base.path().join("target");
        let resource = resource.to_str().unwrap();
        let hash =
            crate::transaction::resource_lock::canonical_hash(std::path::Path::new(resource));
        assert_eq!(
            resource_scope(&roots, "wordpress.clone", resource)
                .unwrap()
                .as_path(),
            std::path::Path::new(&format!("wordpress-clone/{hash}"))
        );
        assert_eq!(
            resource_scope(&roots, "wordpress.updatePlugins", resource)
                .unwrap()
                .as_path(),
            std::path::Path::new(&format!("wordpress-update/{hash}"))
        );
        assert!(resource_scope(&roots, "arbitrary.operation", resource).is_err());
        assert!(resource_scope(&roots, "wordpress.clone", "/etc/passwd").is_err());
        assert!(
            resource_scope(&roots, "wordpress.clone", &format!("{resource}/../escape")).is_err()
        );
        assert!(resource_scope(&roots, "meilisearch.upgrade", "../escape").is_err());
        assert_eq!(
            resource_scope(&roots, "meilisearch.upgrade", "wp-stack")
                .unwrap()
                .as_path(),
            std::path::Path::new("meilisearch/wp-stack")
        );
        assert_eq!(
            resource_scope(
                &roots,
                "docker.imagePull",
                "ghcr.io/example/image@sha256:abc"
            )
            .unwrap()
            .as_path(),
            std::path::Path::new("docker-resource")
        );
    }
    #[test]
    fn resource_status_redacts_arbitrary_plugin_output_and_errors() {
        let (directory, root) = state_root();
        let content = TrustedRoot::parse(directory.path()).unwrap();
        let roots = [content];
        let target = directory.path().join("target");
        let target = target.to_str().unwrap();
        let scope = resource_scope(&roots, "wordpress.updateCore", target).unwrap();
        root.create_dir_all(&scope).unwrap();
        let scope = root.open_managed_dir(&scope).unwrap();
        scope
            .create_dir_all(&SiteRelativePath::parse("transactions").unwrap())
            .unwrap();
        let id = RequestId::parse(REQUEST_ID).unwrap();
        let mut tx = TransactionState::start(id, None, "wordpress.updateCore");
        tx.mark_committed(serde_json::json!({"output":"fixture-secret-never-return"}))
            .unwrap();
        create(
            &scope,
            &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
            &tx,
        )
        .unwrap();
        let status =
            load_resource(&root, &roots, "wordpress.updateCore", target, REQUEST_ID).unwrap();
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fixture-secret-never-return"));
        assert!(json.contains("outcomeKnown"));
        assert!(
            load_resource(&root, &roots, "wordpress.updatePlugins", target, REQUEST_ID).is_err()
        );
    }
}
