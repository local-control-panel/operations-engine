//! `site.renameManifest`: points a git-deploy site's engine manifest
//! (`/etc/operations-engine/sites/<siteId>.json`) at the site's new domain
//! when the control panel renames the site (milestone 057). The panel used
//! to rewrite that file with a raw `sudo` write and put the old bytes back
//! on rollback.
//!
//! Only `domain` changes. The manifest is read through the same root-owned
//! loader every deploy uses, and both the original and the rewritten
//! document must pass `SiteManifest` validation, so a rename can neither
//! rewrite a manifest the engine would refuse nor produce one it would.
//! `contentRoot` (`sites/<siteId>/current`) is derived from the site id, not
//! the domain, and is left as written. The write is a same-directory temp
//! file renamed over the manifest, so a concurrent deploy reads either the
//! old or the new document, never a partial one.
//!
//! Idempotent by state: asking for the domain the manifest already has
//! commits without touching the file (`changed: false`). A rollback is the
//! same operation with the previous domain, which the result reports.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::SiteManifest,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{Domain, SiteId, SiteRelativePath},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const RENAME_OPERATION: &str = "site.renameManifest";

const SCOPE: &str = "site-manifest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidSiteId,
    InvalidDomain,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSiteId => "site-id must be a canonical UUID",
            Self::InvalidDomain => "domain is invalid",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

pub struct RenameRequest {
    pub site_id: SiteId,
    pub domain: Domain,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RenameRequest {
    pub fn parse(
        site_id: &str,
        domain: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        Ok(Self {
            site_id: SiteId::parse(site_id).map_err(|_| RequestError::InvalidSiteId)?,
            domain: Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameResult {
    pub site_id: String,
    pub previous_domain: String,
    pub domain: String,
    /// `false` when the manifest already named this domain.
    pub changed: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum Error {
    ResourceBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// No manifest for this site: it was never enrolled for git deploy.
    ManifestMissing,
    /// The manifest exists but is unreadable, not root-owned, or invalid.
    ManifestInvalid,
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ResourceBusy | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation on this site's manifest is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::ManifestMissing => (
                ErrorCode::NotFound,
                "the site is not configured for engine deploys".into(),
            ),
            Self::ManifestInvalid => (
                ErrorCode::InvalidInput,
                "the site manifest could not be loaded".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal site manifest error".into())
            }
        }
    }
}

/// Rewrites `<sites_dir>/<siteId>.json` so its `domain` is `req.domain`.
/// `required_uid` is the owner the manifest must have (0 in production).
pub fn rename_manifest(
    engine_state: &ManagedRoot,
    sites_dir: &Path,
    required_uid: u32,
    req: &RenameRequest,
) -> Result<RenameResult, Error> {
    let manifest_path = sites_dir.join(format!("{}.json", req.site_id));

    let scope = open_scope(engine_state).map_err(Error::Io)?;
    let _resource_lock = resource_lock::acquire(engine_state, &manifest_path, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        RENAME_OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(req.request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match rewrite(&manifest_path, required_uid, req) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn rewrite(
    manifest_path: &Path,
    required_uid: u32,
    req: &RenameRequest,
) -> Result<RenameResult, Error> {
    let raw = read_manifest(manifest_path, required_uid)?;
    let current =
        SiteManifest::from_json_for_site(&raw, req.site_id).map_err(|_| Error::ManifestInvalid)?;
    let previous_domain = current.domain;
    let result = |changed| RenameResult {
        site_id: req.site_id.to_string(),
        previous_domain: previous_domain.clone(),
        domain: req.domain.as_str().to_owned(),
        changed,
        completed_at_unix_secs: unix_now_secs(),
    };
    if previous_domain == req.domain.as_str() {
        return Ok(result(false));
    }

    let mut document: serde_json::Value =
        serde_json::from_str(&raw).map_err(|_| Error::ManifestInvalid)?;
    document
        .as_object_mut()
        .ok_or(Error::ManifestInvalid)?
        .insert("domain".into(), serde_json::json!(req.domain.as_str()));
    let updated = document.to_string();
    SiteManifest::from_json_for_site(&updated, req.site_id).map_err(|_| Error::ManifestInvalid)?;

    write_atomically(manifest_path, updated.as_bytes(), req.request_id).map_err(Error::Io)?;
    Ok(result(true))
}

/// The same checks `SiteManifest::load_root_owned` makes (owner, no
/// group/other write), against the opened handle.
fn read_manifest(path: &Path, required_uid: u32) -> Result<String, Error> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Error::ManifestMissing);
        }
        Err(_) => return Err(Error::ManifestInvalid),
    };
    let metadata = file.metadata().map_err(Error::Io)?;
    if !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::ManifestInvalid);
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|_| Error::ManifestInvalid)?;
    Ok(raw)
}

/// Same-directory temp file (`create_new`, `0644`), flushed, then renamed
/// over `path`; the directory is synced so the rename is durable.
fn write_atomically(path: &Path, content: &[u8], request_id: RequestId) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("manifest path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("manifest path has no file name"))?;
    let temp = dir.join(format!(".{name}.{request_id}.tmp"));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return written;
    }
    fs::File::open(dir)?.sync_all()
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay(scope: &ManagedRoot, original: RequestId) -> Result<RenameResult, Error> {
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != RENAME_OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use crate::site::TrustedRoot;

    use super::*;

    const SITE: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_SITE: &str = "123e4567-e89b-12d3-a456-426614174009";
    const ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174003";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        sites: std::path::PathBuf,
        uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            fs::create_dir(base.join("state")).unwrap();
            fs::create_dir(base.join("sites")).unwrap();
            let uid = fs::metadata(&base).unwrap().uid();
            let fixture = Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                sites: base.join("sites"),
                uid,
                _dir: dir,
            };
            fixture.write_manifest(SITE, "old.test");
            fixture
        }

        fn manifest_path(&self, site: &str) -> std::path::PathBuf {
            self.sites.join(format!("{site}.json"))
        }

        fn write_manifest(&self, site: &str, domain: &str) {
            let json = serde_json::json!({
                "schemaVersion": 1,
                "siteId": site,
                "domain": domain,
                "contentRoot": format!("sites/{site}/current"),
                "siteUser": "old_test",
                "repository": {
                    "url": "git@example.com:r.git",
                    "allowedBranches": ["main"],
                    "credentialId": site,
                },
            });
            let path = self.manifest_path(site);
            fs::write(&path, json.to_string()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }

        fn read(&self, site: &str) -> serde_json::Value {
            serde_json::from_str(&fs::read_to_string(self.manifest_path(site)).unwrap()).unwrap()
        }

        fn run(&self, req: &RenameRequest) -> Result<RenameResult, Error> {
            rename_manifest(&self.state, &self.sites, self.uid, req)
        }
    }

    fn req(site: &str, domain: &str, id: &str, key: Option<&str>) -> RenameRequest {
        RenameRequest::parse(site, domain, id, key).unwrap()
    }

    #[test]
    fn rewrites_only_the_domain_and_the_result_names_the_previous_one() {
        let fixture = Fixture::new();
        let before = fixture.read(SITE);

        let result = fixture
            .run(&req(SITE, "new.test", ID, Some("rename-1")))
            .unwrap();
        assert!(result.changed);
        assert_eq!(result.previous_domain, "old.test");

        let mut expected = before;
        expected["domain"] = "new.test".into();
        assert_eq!(fixture.read(SITE), expected);
        let mode = fs::metadata(fixture.manifest_path(SITE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        // No temp file is left behind.
        assert_eq!(fs::read_dir(&fixture.sites).unwrap().count(), 1);
    }

    #[test]
    fn same_key_replays_and_a_repeat_with_a_new_request_is_a_no_op() {
        let fixture = Fixture::new();
        let first = fixture
            .run(&req(SITE, "new.test", ID, Some("rename-1")))
            .unwrap();

        let replayed = fixture
            .run(&req(SITE, "new.test", ID2, Some("rename-1")))
            .unwrap();
        assert!(replayed.changed);
        assert_eq!(replayed.previous_domain, first.previous_domain);

        let repeat = fixture.run(&req(SITE, "new.test", ID3, None)).unwrap();
        assert!(!repeat.changed);
        assert_eq!(repeat.previous_domain, "new.test");
        assert_eq!(fixture.read(SITE)["domain"], "new.test");
    }

    #[test]
    fn renaming_back_with_the_previous_domain_restores_the_manifest() {
        let fixture = Fixture::new();
        let before = fixture.read(SITE);
        let forward = fixture.run(&req(SITE, "new.test", ID, None)).unwrap();
        fixture
            .run(&req(SITE, &forward.previous_domain, ID2, None))
            .unwrap();
        assert_eq!(fixture.read(SITE), before);
    }

    #[test]
    fn a_missing_manifest_is_not_found_and_recorded() {
        let fixture = Fixture::new();
        let error = fixture
            .run(&req(OTHER_SITE, "new.test", ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::ManifestMissing));
        assert_eq!(error.protocol().0, ErrorCode::NotFound);
        assert!(
            fixture
                .state
                .exists(&rel(&format!("site-manifest/transactions/{ID}.json")))
        );
    }

    #[test]
    fn refuses_a_manifest_for_another_site_a_wrong_owner_or_a_writable_mode() {
        let fixture = Fixture::new();
        // Manifest content naming a different site than its file name.
        fs::copy(
            fixture.manifest_path(SITE),
            fixture.manifest_path(OTHER_SITE),
        )
        .unwrap();
        assert!(matches!(
            fixture.run(&req(OTHER_SITE, "new.test", ID, None)),
            Err(Error::ManifestInvalid)
        ));

        let wrong_owner = rename_manifest(
            &fixture.state,
            &fixture.sites,
            fixture.uid + 1,
            &req(SITE, "new.test", ID2, None),
        );
        assert!(matches!(wrong_owner, Err(Error::ManifestInvalid)));

        fs::set_permissions(
            fixture.manifest_path(SITE),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(
            fixture.run(&req(SITE, "new.test", ID3, None)),
            Err(Error::ManifestInvalid)
        ));
        assert_eq!(fixture.read(SITE)["domain"], "old.test");
    }

    #[test]
    fn a_held_resource_lock_blocks_the_rewrite() {
        let fixture = Fixture::new();
        let _held = resource_lock::acquire(
            &fixture.state,
            &fixture.manifest_path(SITE),
            RequestId::parse(ID2).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            fixture.run(&req(SITE, "new.test", ID, None)),
            Err(Error::ResourceBusy)
        ));
        assert_eq!(fixture.read(SITE)["domain"], "old.test");
    }

    #[test]
    fn rejects_malformed_requests() {
        assert_eq!(
            RenameRequest::parse("nope", "new.test", ID, None).err(),
            Some(RequestError::InvalidSiteId)
        );
        assert_eq!(
            RenameRequest::parse(SITE, "../etc", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            RenameRequest::parse(SITE, "new.test", "not-a-uuid", None).err(),
            Some(RequestError::InvalidRequestId)
        );
    }
}
