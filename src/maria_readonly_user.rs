//! A SELECT-only MariaDB account on one site database, used to run bounded
//! read-only SQL.
//!
//! - `db.ensureReadonlyUser` creates the account `ro_<database>@localhost`
//!   (or re-asserts its grant and limits), generates a password and returns it
//!   once as a secret result. The password is never taken from the request and
//!   is never written to argv, state, audit or logs; a replay carries
//!   `alreadyIssued` and no password.
//! - `db.revokeReadonlyUser` drops the account; a missing account is a success.
//!
//! The account name is derived from the database name, so a caller can neither
//! choose nor collide it with another account, and the host is always
//! `localhost`.

pub mod execute;

use crate::{
    db_restore::{ContainerName, DatabaseName},
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt::Write;

pub const ENSURE_OPERATION: &str = "db.ensureReadonlyUser";
pub const REVOKE_OPERATION: &str = "db.revokeReadonlyUser";

/// The only host the account is created for.
pub const HOST: &str = "localhost";
/// Account names are capped at this length; a longer derived name is shortened
/// and made unique with a hash suffix. MariaDB itself allows 80 characters;
/// the lower bound keeps names portable.
pub const MAX_USER_LEN: usize = 32;
pub const MAX_QUERIES_PER_HOUR: u32 = 600;
pub const MAX_UPDATES_PER_HOUR: u32 = 0;
pub const MAX_USER_CONNECTIONS: u32 = 2;

const SYSTEM_DATABASES: [&str; 4] = ["mysql", "information_schema", "performance_schema", "sys"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnsurePlan {
    container: String,
    root_password: String,
    database: String,
    #[serde(default)]
    rotate: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokePlan {
    container: String,
    root_password: String,
    database: String,
}

#[derive(Debug)]
pub struct Request {
    pub container: ContainerName,
    pub root_password: String,
    pub database: DatabaseName,
    /// Only meaningful for `db.ensureReadonlyUser`.
    pub rotate: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidDatabase,
    ProtectedDatabase,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse_ensure(
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: EnsurePlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Self::build(
            plan.container,
            plan.root_password,
            plan.database,
            plan.rotate,
            request_id,
            key,
        )
    }

    pub fn parse_revoke(
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: RevokePlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Self::build(
            plan.container,
            plan.root_password,
            plan.database,
            false,
            request_id,
            key,
        )
    }

    fn build(
        container: String,
        root_password: String,
        database: String,
        rotate: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if root_password.len() > 4096 || root_password.contains(['\n', '\r', '\0']) {
            return Err(RequestError::InvalidSecret);
        }
        let database = DatabaseName::parse(&database).map_err(|_| RequestError::InvalidDatabase)?;
        if SYSTEM_DATABASES
            .iter()
            .any(|name| database.as_str().eq_ignore_ascii_case(name))
        {
            return Err(RequestError::ProtectedDatabase);
        }
        Ok(Self {
            container: ContainerName::parse(&container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password,
            database,
            rotate,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn username(&self) -> String {
        username_for(&self.database)
    }
}

/// `ro_<database>`; when that exceeds [`MAX_USER_LEN`], a prefix of it followed
/// by `_` and eight hex digits of the SHA-256 of the full database name.
pub fn username_for(database: &DatabaseName) -> String {
    let full = format!("ro_{}", database.as_str());
    if full.len() <= MAX_USER_LEN {
        return full;
    }
    let digest = Sha256::digest(database.as_str().as_bytes());
    let suffix = digest.iter().take(4).fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    });
    // 32 - "_" - 8 hex digits.
    format!("{}_{suffix}", &full[..MAX_USER_LEN - 9])
}

/// Escapes `_` and `%`, which are wildcards in the database part of a grant.
pub fn grant_database_pattern(database: &DatabaseName) -> String {
    database.as_str().replace('_', "\\_")
}

/// The SQL of `db.ensureReadonlyUser`. `password` is `Some` when the account
/// was just created or a rotation was requested. Names contain only
/// `[A-Za-z0-9_]` and the password only ASCII alphanumerics, so no quoting
/// character can occur.
pub fn ensure_statements(
    user: &str,
    database: &DatabaseName,
    password: Option<&str>,
) -> Vec<String> {
    let mut statements = vec![format!("CREATE USER IF NOT EXISTS '{user}'@'{HOST}';")];
    if let Some(password) = password {
        statements.push(format!(
            "ALTER USER '{user}'@'{HOST}' IDENTIFIED BY '{password}';"
        ));
    }
    statements.push(format!(
        "GRANT SELECT ON `{}`.* TO '{user}'@'{HOST}' WITH MAX_QUERIES_PER_HOUR {MAX_QUERIES_PER_HOUR} MAX_UPDATES_PER_HOUR {MAX_UPDATES_PER_HOUR} MAX_USER_CONNECTIONS {MAX_USER_CONNECTIONS};",
        grant_database_pattern(database)
    ));
    statements.push("FLUSH PRIVILEGES;".to_owned());
    statements
}

pub fn revoke_statements(user: &str) -> Vec<String> {
    vec![format!("DROP USER IF EXISTS '{user}'@'{HOST}';")]
}

#[cfg(test)]
mod tests;
