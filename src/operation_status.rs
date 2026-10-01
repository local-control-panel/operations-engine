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
    let transaction = state::load(&site_state, &transaction_path).map_err(|error| match error {
        state::StateError::NotFound => StatusError::NotFound,
        state::StateError::Corrupt => StatusError::Corrupt,
        state::StateError::AlreadyExists | state::StateError::Io => StatusError::Io,
    })?;
    let active = if transaction.status == TransactionStatus::InProgress {
        let lock_path = SiteRelativePath::parse("locks/mutation.lock").unwrap();
        lock::holder(&site_state, &lock_path).map_err(|_| StatusError::Io)?
            == Some(transaction.request_id)
    } else {
        false
    };
    Ok(OperationStatus {
        transaction,
        active,
    })
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
}
