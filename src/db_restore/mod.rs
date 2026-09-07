//! The `db.restore` operation: runs a database client against an
//! already-on-disk dump file, for audit-trail purposes only.
//!
//! Deliberately simpler than every other mutation this engine runs: no
//! `TrustedRoot`-managed content (the dump file already exists on the host,
//! this operation does not stage or own it), no `HashGuard` (there is no
//! "expected prior content" for a destructive database import to be
//! guarded against), no rollback (`mariadb`/`psql` either accept the
//! submission or don't; there is no partial-apply state and, by explicit
//! scope decision, this operation does not snapshot the database first -
//! it is exactly as safe/unsafe as the client-side raw-SSH command it
//! replaces, gaining only structured execution and a transaction/audit
//! record of who restored what, when).

pub mod execute;

use crate::transaction::{IdempotencyKey, RequestId};

pub const OPERATION: &str = "db.restore";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbType {
    Mariadb,
    Postgres,
}

impl DbType {
    pub fn parse(value: &str) -> Result<Self, RestoreRequestError> {
        match value {
            "mariadb" => Ok(Self::Mariadb),
            "postgres" => Ok(Self::Postgres),
            _ => Err(RestoreRequestError::InvalidDbType),
        }
    }
}

/// A database name: bounded, `[A-Za-z0-9_]` only - the same rule
/// `website-control-panel`'s own `db::validate_db_name` already applies
/// client-side, mirrored here so a malformed name can never reach the
/// subprocess argv regardless of which caller is validating it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseName(String);

impl DatabaseName {
    pub fn parse(value: &str) -> Result<Self, RestoreRequestError> {
        if value.is_empty()
            || value.len() > 64
            || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(RestoreRequestError::InvalidDatabaseName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Docker container name: bounded, `[A-Za-z0-9_.-]` only - the character
/// set `docker` itself accepts for container names, which is also enough
/// to guarantee this can never be interpreted as a shell metacharacter or
/// an extra `docker exec` flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerName(String);

impl ContainerName {
    pub fn parse(value: &str) -> Result<Self, RestoreRequestError> {
        if value.is_empty()
            || value.len() > 255
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(RestoreRequestError::InvalidContainerName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Upper bound on the dump file path length submitted - not a content
/// bound (this operation never reads the file into memory; see
/// `process::run_with_stdin_file`/`run_piped`), just a sane limit on the
/// path string itself.
pub const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug, Eq, PartialEq)]
pub struct RestoreRequest {
    pub db_type: DbType,
    pub database: DatabaseName,
    pub container: ContainerName,
    /// The dump file's path on the remote host. Not validated against any
    /// `TrustedRoot` here - the caller (`website-control-panel`) already
    /// confirms it falls under its own backup/import directories
    /// (`validate_backup_path`) before ever reaching this request; this
    /// operation only runs a database client against whatever path it is
    /// given, the same trust boundary the raw-SSH command it replaces
    /// already has.
    pub file_path: String,
    /// Not staged, not written to any managed root, and not written to the
    /// engine's own audit log by value (see `execute`'s redaction) -
    /// carried only long enough to build the client subprocess's argv/env.
    pub root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreRequestError {
    InvalidDbType,
    InvalidDatabaseName,
    InvalidContainerName,
    FilePathTooLong,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RestoreRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        db_type: &str,
        database: &str,
        container: &str,
        file_path: impl Into<String>,
        root_password: impl Into<String>,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RestoreRequestError> {
        let file_path = file_path.into();
        if file_path.len() > MAX_PATH_BYTES {
            return Err(RestoreRequestError::FilePathTooLong);
        }
        Ok(Self {
            db_type: DbType::parse(db_type)?,
            database: DatabaseName::parse(database)?,
            container: ContainerName::parse(container)?,
            file_path,
            root_password: root_password.into(),
            request_id: RequestId::parse(request_id)
                .map_err(|_| RestoreRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RestoreRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `db.restore` response. No
/// content-derived fields (no hash, no "activated" flag distinguishing a
/// no-op) - unlike every config-activation operation this engine runs, a
/// restore has no converged/unconverged distinction: every successful call
/// ran the import.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub restored_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::{ContainerName, DatabaseName, DbType, RestoreRequest, RestoreRequestError};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn db_type_accepts_only_the_two_known_values() {
        assert_eq!(DbType::parse("mariadb"), Ok(DbType::Mariadb));
        assert_eq!(DbType::parse("postgres"), Ok(DbType::Postgres));
        assert_eq!(
            DbType::parse("mysql"),
            Err(RestoreRequestError::InvalidDbType)
        );
    }

    #[test]
    fn database_name_rejects_anything_outside_alnum_underscore() {
        assert!(DatabaseName::parse("site_db1").is_ok());
        assert!(DatabaseName::parse("").is_err());
        assert!(DatabaseName::parse("db; drop table x").is_err());
        assert!(DatabaseName::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn container_name_accepts_dockers_own_character_set() {
        assert!(ContainerName::parse("wcp-mariadb-1").is_ok());
        assert!(ContainerName::parse("wcp.mariadb_1").is_ok());
        assert!(ContainerName::parse("../etc/passwd").is_err());
        assert!(ContainerName::parse("").is_err());
    }

    #[test]
    fn request_parses_all_valid_fields() {
        let request = RestoreRequest::parse(
            "mariadb",
            "site_db",
            "wcp-mariadb-1",
            "/var/backups/site_db.sql",
            "s3cret",
            REQUEST_ID,
            Some("restore-1"),
        )
        .expect("request should parse");
        assert_eq!(request.db_type, DbType::Mariadb);
        assert_eq!(request.database.as_str(), "site_db");
        assert_eq!(request.container.as_str(), "wcp-mariadb-1");
        assert_eq!(request.file_path, "/var/backups/site_db.sql");
    }

    #[test]
    fn request_reports_which_field_failed() {
        assert_eq!(
            RestoreRequest::parse("oracle", "db", "c", "/path", "pw", REQUEST_ID, None)
                .unwrap_err(),
            RestoreRequestError::InvalidDbType
        );
        assert_eq!(
            RestoreRequest::parse("mariadb", "bad db", "c", "/path", "pw", REQUEST_ID, None)
                .unwrap_err(),
            RestoreRequestError::InvalidDatabaseName
        );
        assert_eq!(
            RestoreRequest::parse("mariadb", "db", "", "/path", "pw", REQUEST_ID, None)
                .unwrap_err(),
            RestoreRequestError::InvalidContainerName
        );
        assert_eq!(
            RestoreRequest::parse("mariadb", "db", "c", "/path", "pw", "not-a-uuid", None)
                .unwrap_err(),
            RestoreRequestError::InvalidRequestId
        );
    }
}
