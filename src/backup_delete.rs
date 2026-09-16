pub mod execute;

use crate::{
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "backup.delete";
pub const BACKUP_ROOT: &str = "/root/db-backups";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    file_path: String,
}

#[derive(Debug)]
pub struct Request {
    pub relative_path: SiteRelativePath,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidPath,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let relative = plan
            .file_path
            .strip_prefix(&format!("{BACKUP_ROOT}/"))
            .ok_or(RequestError::InvalidPath)?;
        if !(relative.ends_with(".sql") || relative.ends_with(".sql.gz")) {
            return Err(RequestError::InvalidPath);
        }
        Ok(Self {
            relative_path: SiteRelativePath::parse(relative)
                .map_err(|_| RequestError::InvalidPath)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub deleted: bool,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn accepts_only_sql_artifacts_beneath_the_fixed_backup_root() {
        for path in [
            "/root/db-backups",
            "/root/db-backups/../secret.sql",
            "/root/db-backups2/file.sql",
            "/etc/passwd",
            "/root/db-backups/file.txt",
        ] {
            let json = serde_json::json!({"filePath":path}).to_string();
            assert_eq!(
                Request::parse(&json, ID, None).unwrap_err(),
                RequestError::InvalidPath
            );
        }
        for path in [
            "/root/db-backups/site_20260916.sql",
            "/root/db-backups/imports/upload.sql.gz",
        ] {
            let json = serde_json::json!({"filePath":path}).to_string();
            assert!(Request::parse(&json, ID, None).is_ok());
        }
    }
}
