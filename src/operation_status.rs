use serde::Serialize;

use crate::{
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath},
    transaction::{
        RequestId,
        lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    InvalidSiteId,
    InvalidRequestId,
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

pub fn load(
    engine_state: &ManagedRoot,
    site_id: &str,
    request_id: &str,
) -> Result<OperationStatus, StatusError> {
    let site_id = SiteId::parse(site_id).map_err(|_| StatusError::InvalidSiteId)?;
    let request_id = RequestId::parse(request_id).map_err(|_| StatusError::InvalidRequestId)?;
    let site_path = SiteRelativePath::parse(format!("sites/{site_id}"))
        .expect("a canonical site id always produces a safe relative path");
    let site_state = engine_state.open_managed_dir(&site_path).map_err(|error| {
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
    Ok(OperationStatus { transaction, active })
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

        let loaded = load(&root, SITE_ID, REQUEST_ID).unwrap();
        assert_eq!(loaded.transaction.request_id, request_id);
        assert_eq!(loaded.transaction.status, TransactionStatus::InProgress);
        assert!(!loaded.active);
    }

    #[test]
    fn rejects_invalid_identifiers_and_reports_missing_state() {
        let (_directory, root) = state_root();
        assert_eq!(
            load(&root, "../site", REQUEST_ID),
            Err(StatusError::InvalidSiteId)
        );
        assert_eq!(
            load(&root, SITE_ID, "../request"),
            Err(StatusError::InvalidRequestId)
        );
        assert_eq!(
            load(
                &root,
                SITE_ID,
                "9b2f1c34-5678-4abc-9def-0123456789ab"
            ),
            Err(StatusError::NotFound)
        );
    }
}
