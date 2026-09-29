//! The `wordpress.rotateCredentials` operation: rotates a WordPress site's
//! database user password. Unlike `wordpress_install`/`wordpress_clone`,
//! this operation never touches the host filesystem directly — both
//! mutations (`ALTER USER` and `wp config set`) run inside containers via
//! `docker exec`, so no `TrustedRoot`/`ManagedRoot` content-root resolution
//! is needed in `execute()` itself (the dispatch layer in
//! `commands/wordpress.rs` still validates `root` against the configured
//! content roots before calling in, matching every other WordPress
//! operation). The engine reads the site's *current* `DB_USER`/
//! `DB_PASSWORD` from `wp-config.php` itself rather than trusting values
//! the panel already resolved, so the old password used for automatic
//! rollback is always the value actually in effect at the moment this
//! operation runs.

#[allow(unused_imports)]
use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::path::PathBuf;

pub const OPERATION: &str = "wordpress.rotateCredentials";

const MAX_SECRET_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    mariadb_container: String,
    db_root_password: String,
    new_password: String,
}

#[allow(dead_code)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    mariadb_container: ContainerName,
    db_root_password: String,
    new_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

/// Mirrors `website-control-panel`'s own `validate_db_credentials`: no NUL,
/// CR or LF, and non-empty.
fn validate_secret(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_SECRET_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        if plan.uid == 0 || plan.gid == 0 {
            return Err(RequestError);
        }
        validate_secret(&plan.db_root_password)?;
        validate_secret(&plan.new_password)?;

        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_root_password: plan.db_root_password,
            new_password: plan.new_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_json() -> String {
        r#"{
            "container": "runtime-1",
            "root": "/var/www/example.com",
            "uid": 1000,
            "gid": 1000,
            "mariadbContainer": "mariadb-1",
            "dbRootPassword": "root-secret",
            "newPassword": "new-secret-value"
        }"#
        .to_string()
    }

    #[test]
    fn parses_a_valid_request() {
        let request = Request::parse(&valid_json(), REQUEST_ID, None).expect("should parse");
        assert_eq!(request.root(), std::path::Path::new("/var/www/example.com"));
    }

    #[test]
    fn rejects_a_relative_root() {
        let json = valid_json().replace("/var/www/example.com", "relative/path");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_root_containing_parent_dir_segments() {
        let json = valid_json().replace("/var/www/example.com", "/var/www/../etc");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_uid_zero() {
        let json = valid_json().replace("\"uid\": 1000", "\"uid\": 0");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_gid_zero() {
        let json = valid_json().replace("\"gid\": 1000", "\"gid\": 0");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_empty_new_password() {
        let json = valid_json().replace(
            "\"newPassword\": \"new-secret-value\"",
            "\"newPassword\": \"\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_newline() {
        let json = valid_json().replace("new-secret-value", "new-secret\\nvalue");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_empty_db_root_password() {
        let json = valid_json().replace(
            "\"dbRootPassword\": \"root-secret\"",
            "\"dbRootPassword\": \"\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_malformed_mariadb_container_name() {
        let json = valid_json().replace("mariadb-1", "not a container name");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let json = valid_json().replace("\"uid\": 1000,", "\"uid\": 1000, \"unexpected\": true,");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_nul_byte() {
        let password_with_nul = "new-secret\0value";
        let json = format!(
            r#"{{
            "container": "runtime-1",
            "root": "/var/www/example.com",
            "uid": 1000,
            "gid": 1000,
            "mariadbContainer": "mariadb-1",
            "dbRootPassword": "root-secret",
            "newPassword": "{}"
        }}"#,
            password_with_nul
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_carriage_return() {
        let json = valid_json().replace("new-secret-value", "new-secret\rvalue");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_exceeding_the_length_bound() {
        let long_password = "x".repeat(257);
        let json = valid_json().replace("\"new-secret-value\"", &format!("\"{}\"", long_password));
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }
}
