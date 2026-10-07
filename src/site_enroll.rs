//! `site.enroll` / `site.unenroll`: the engine's one writer of a git-deploy
//! site's enrolment, the root-owned manifest
//! (`<sites dir>/<siteId>.json`) and the deploy key the manifest's
//! `credentialId` names (`<credential root>/<siteId>`, owned by the site
//! user, `0600`). Milestone 063. The control panel used to write both with
//! raw `sudo tee`/`chown`/`chmod` and to `rm -f` a database-supplied key path
//! on disconnect; with `site.renameManifest` (057) this makes the engine the
//! only manifest writer.
//!
//! `site.enroll` takes a staged request file (root-owned, `0600`) because it
//! carries the private key; the key is never an argument and never appears in
//! results, transaction records, audit events or error text. The manifest is
//! built here from validated fields in the exact shape every deploy loads
//! (`contentRoot` is always `sites/<siteId>/current`, `credentialId` is the
//! site id) and must pass `SiteManifest` validation before anything is
//! written.
//!
//! Both files are written as same-directory temp files renamed into place.
//! The credential goes first and the manifest last, so a deploy never sees a
//! manifest whose key is missing; if the manifest write fails the previous
//! credential is put back (or removed when there was none). Enrolling is
//! idempotent by state: identical manifest and key (content, owner, mode)
//! commit without a write. `site.unenroll` removes the manifest first (the
//! point after which deploys are refused) and then the key; a missing file is
//! success, so a repeat after a partial failure finishes the job.
//!
//! Both operations hold the same per-site mutation lock a deploy holds, so an
//! enrol or unenrol cannot interleave with a deploy or rollback of the site,
//! plus the manifest's resource lock shared with `site.renameManifest`.

use std::{
    fmt, fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

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

pub const ENROLL_OPERATION: &str = "site.enroll";
pub const UNENROLL_OPERATION: &str = "site.unenroll";

/// Site identities start here, like `site.prepareRoot`.
pub const MIN_SITE_IDENTITY: u32 = 1000;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidSiteId,
    InvalidRequest,
    InvalidCredential,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSiteId => "site-id must be a canonical UUID",
            Self::InvalidRequest => "request-file is not a valid site enrolment plan",
            Self::InvalidCredential => "the deploy key is not a private key of acceptable size",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEnroll {
    site_id: String,
    domain: String,
    site_user: String,
    repository: RawRepository,
    credential: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRepository {
    url: String,
    branch: String,
}

pub struct EnrollRequest {
    pub site_id: SiteId,
    pub domain: Domain,
    pub site_user: String,
    pub repository_url: String,
    pub branch: String,
    credential: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl fmt::Debug for EnrollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollRequest")
            .field("site_id", &self.site_id)
            .field("domain", &self.domain)
            .field("credential", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EnrollRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let raw: RawEnroll =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidRequest)?;
        let credential = raw.credential;
        if credential.is_empty()
            || credential.len() > MAX_CREDENTIAL_BYTES
            || credential.contains('\0')
            || !credential.contains("PRIVATE KEY-----")
        {
            return Err(RequestError::InvalidCredential);
        }
        let request = Self {
            site_id: SiteId::parse(&raw.site_id).map_err(|_| RequestError::InvalidSiteId)?,
            domain: Domain::parse(&raw.domain).map_err(|_| RequestError::InvalidRequest)?,
            site_user: raw.site_user,
            repository_url: raw.repository.url,
            branch: raw.repository.branch,
            credential,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        };
        // The manifest this request would produce must be one deploy loads.
        request.manifest_json()?;
        Ok(request)
    }

    fn manifest_json(&self) -> Result<String, RequestError> {
        let json = serde_json::json!({
            "schemaVersion": 1,
            "siteId": self.site_id.to_string(),
            "domain": self.domain.as_str(),
            "contentRoot": format!("sites/{}/current", self.site_id),
            "siteUser": self.site_user,
            "repository": {
                "url": self.repository_url,
                "allowedBranches": [self.branch],
                "credentialId": self.site_id.to_string(),
            },
        })
        .to_string();
        SiteManifest::from_json_for_site(&json, self.site_id)
            .map_err(|_| RequestError::InvalidRequest)?;
        Ok(json)
    }
}

pub struct UnenrollRequest {
    pub site_id: SiteId,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl UnenrollRequest {
    pub fn parse(site_id: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            site_id: SiteId::parse(site_id).map_err(|_| RequestError::InvalidSiteId)?,
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
pub struct EnrollResult {
    pub site_id: String,
    /// `false` when the manifest and the key already were exactly this.
    pub changed: bool,
    pub manifest_written: bool,
    pub credential_written: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnenrollResult {
    pub site_id: String,
    /// `false` when neither file existed.
    pub changed: bool,
    pub manifest_removed: bool,
    pub credential_removed: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum Error {
    Busy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// The site user does not exist or is a system account.
    InvalidSiteUser,
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Busy | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation on this site is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::InvalidSiteUser => (
                ErrorCode::InvalidInput,
                "site user does not exist or is not a site identity".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal site enrolment error".into())
            }
        }
    }
}

/// Resolves a site user to `(uid, gid)`; production uses `id -u`/`id -g`.
pub type ResolveIdentity<'a> = &'a dyn Fn(&str) -> Option<(u32, u32)>;

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub sites_dir: &'a Path,
    pub credential_dir: &'a Path,
    /// Owner an existing manifest must have to count as "already written".
    pub required_uid: u32,
    pub min_identity: u32,
    pub resolve_identity: ResolveIdentity<'a>,
}

pub fn enroll(ctx: &Context<'_>, req: &EnrollRequest) -> Result<EnrollResult, Error> {
    let manifest_path = ctx.sites_dir.join(format!("{}.json", req.site_id));
    let credential_path = ctx.credential_dir.join(req.site_id.to_string());
    let manifest_json = req
        .manifest_json()
        .map_err(|_| Error::Io(io::Error::other("manifest no longer validates")))?;

    let _resource_lock = resource_lock::acquire(ctx.engine_state, &manifest_path, req.request_id)
        .map_err(|_| Error::Busy)?;
    run_transaction(
        ctx,
        ENROLL_OPERATION,
        req.site_id,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let (uid, gid) = (ctx.resolve_identity)(&req.site_user)
                .filter(|(uid, gid)| *uid >= ctx.min_identity && *gid >= ctx.min_identity)
                .ok_or(Error::InvalidSiteUser)?;

            let manifest_current = read_file(&manifest_path)
                .map(|(bytes, meta)| {
                    bytes == manifest_json.as_bytes()
                        && meta.uid() == ctx.required_uid
                        && meta.permissions().mode() & 0o777 == 0o644
                })
                .unwrap_or(false);
            let previous_credential = read_file(&credential_path);
            let credential_current = previous_credential
                .as_ref()
                .map(|(bytes, meta)| {
                    bytes == req.credential.as_bytes()
                        && meta.uid() == uid
                        && meta.gid() == gid
                        && meta.permissions().mode() & 0o777 == 0o600
                })
                .unwrap_or(false);

            if !credential_current {
                ensure_dir(ctx.credential_dir).map_err(Error::Io)?;
                write_atomically(
                    &credential_path,
                    req.credential.as_bytes(),
                    0o600,
                    Some((uid, gid)),
                    req.request_id,
                )
                .map_err(Error::Io)?;
            }
            if !manifest_current {
                let written = ensure_dir(ctx.sites_dir).and_then(|()| {
                    write_atomically(
                        &manifest_path,
                        manifest_json.as_bytes(),
                        0o644,
                        None,
                        req.request_id,
                    )
                });
                if let Err(error) = written {
                    if !credential_current {
                        restore_credential(
                            &credential_path,
                            previous_credential.as_ref().map(|(bytes, meta)| {
                                (
                                    bytes.as_slice(),
                                    meta.uid(),
                                    meta.gid(),
                                    meta.mode() & 0o777,
                                )
                            }),
                            req.request_id,
                        );
                    }
                    return Err(Error::Io(error));
                }
            }
            Ok(EnrollResult {
                site_id: req.site_id.to_string(),
                changed: !manifest_current || !credential_current,
                manifest_written: !manifest_current,
                credential_written: !credential_current,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn unenroll(ctx: &Context<'_>, req: &UnenrollRequest) -> Result<UnenrollResult, Error> {
    let manifest_path = ctx.sites_dir.join(format!("{}.json", req.site_id));
    let credential_path = ctx.credential_dir.join(req.site_id.to_string());

    let _resource_lock = resource_lock::acquire(ctx.engine_state, &manifest_path, req.request_id)
        .map_err(|_| Error::Busy)?;
    run_transaction(
        ctx,
        UNENROLL_OPERATION,
        req.site_id,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            // Manifest first: from here on deploys of this site are refused.
            let manifest_removed = remove_if_present(&manifest_path).map_err(Error::Io)?;
            let credential_removed = remove_if_present(&credential_path).map_err(Error::Io)?;
            Ok(UnenrollResult {
                site_id: req.site_id.to_string(),
                changed: manifest_removed || credential_removed,
                manifest_removed,
                credential_removed,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

/// Preflight (idempotency, the per-site mutation lock a deploy also holds,
/// transaction record, audit start), `work`, then the committed record.
fn run_transaction<T: Serialize + DeserializeOwned>(
    ctx: &Context<'_>,
    operation: &'static str,
    site_id: SiteId,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    work: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    let site_state = preflight::open_site_state(ctx.engine_state, site_id).map_err(Error::Io)?;
    let admitted = match preflight::run(&site_state, request_id, key, operation)
        .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&site_state, operation, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(&format!("transactions/{request_id}.json"));
    let audit_path = rel("audit/events.jsonl");

    let value = match work() {
        Ok(value) => value,
        Err(error) => return Err(fail(&site_state, &state_path, &audit_path, state, error)),
    };
    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&site_state, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &site_state,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn read_file(path: &Path) -> Option<(Vec<u8>, fs::Metadata)> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some((bytes, metadata))
}

fn ensure_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
}

/// Puts the pre-enrol credential back (or removes the new one).
fn restore_credential(
    path: &Path,
    previous: Option<(&[u8], u32, u32, u32)>,
    request_id: RequestId,
) {
    match previous {
        Some((bytes, uid, gid, mode)) => {
            let _ = write_atomically(path, bytes, mode, Some((uid, gid)), request_id);
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                fs::File::open(dir)?.sync_all()?;
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Same-directory temp file (`create_new`, owner and mode set before any
/// content is written), flushed, then renamed over `path`; the directory is
/// synced so the rename is durable.
fn write_atomically(
    path: &Path,
    content: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    request_id: RequestId,
) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("path has no file name"))?;
    let temp: PathBuf = dir.join(format!(".{name}.{request_id}.tmp"));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
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

fn replay<T: DeserializeOwned>(
    scope: &ManagedRoot,
    operation: &'static str,
    original: RequestId,
) -> Result<T, Error> {
    let loaded = state::load(scope, &rel(&format!("transactions/{original}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
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
    use crate::site::TrustedRoot;

    use super::*;

    const SITE: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "123e4567-e89b-12d3-a456-426614174009";
    const ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174003";
    const ID4: &str = "123e4567-e89b-12d3-a456-426614174004";
    const KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-material\n-----END OPENSSH PRIVATE KEY-----\n";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        sites: PathBuf,
        creds: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            fs::create_dir(base.join("state")).unwrap();
            let meta = fs::metadata(&base).unwrap();
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                sites: base.join("etc/sites"),
                creds: base.join("var/credentials"),
                uid: meta.uid(),
                gid: meta.gid(),
                _dir: dir,
            }
        }

        fn run_enroll(&self, req: &EnrollRequest) -> Result<EnrollResult, Error> {
            let (uid, gid) = (self.uid, self.gid);
            let resolve = move |user: &str| (user == "site_user").then_some((uid, gid));
            enroll(&self.ctx(&resolve), req)
        }

        fn run_unenroll(&self, req: &UnenrollRequest) -> Result<UnenrollResult, Error> {
            let resolve = |_: &str| None;
            unenroll(&self.ctx(&resolve), req)
        }

        fn ctx<'a>(&'a self, resolve: ResolveIdentity<'a>) -> Context<'a> {
            Context {
                engine_state: &self.state,
                sites_dir: &self.sites,
                credential_dir: &self.creds,
                required_uid: self.uid,
                min_identity: 0,
                resolve_identity: resolve,
            }
        }

        fn manifest(&self, site: &str) -> PathBuf {
            self.sites.join(format!("{site}.json"))
        }

        fn credential(&self, site: &str) -> PathBuf {
            self.creds.join(site)
        }
    }

    fn plan(site: &str, domain: &str, branch: &str, credential: &str) -> String {
        serde_json::json!({
            "siteId": site,
            "domain": domain,
            "siteUser": "site_user",
            "repository": {"url": "git@example.com:r.git", "branch": branch},
            "credential": credential,
        })
        .to_string()
    }

    fn enroll_req(json: &str, id: &str, key: Option<&str>) -> EnrollRequest {
        EnrollRequest::parse(json, id, key).unwrap()
    }

    #[test]
    fn writes_the_manifest_and_key_with_the_documented_owner_and_modes() {
        let fixture = Fixture::new();
        let result = fixture
            .run_enroll(&enroll_req(
                &plan(SITE, "a.test", "main", KEY),
                ID,
                Some("enrol-1"),
            ))
            .unwrap();
        assert!(result.changed && result.manifest_written && result.credential_written);

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(fixture.manifest(SITE)).unwrap()).unwrap();
        assert_eq!(manifest["domain"], "a.test");
        assert_eq!(manifest["contentRoot"], format!("sites/{SITE}/current"));
        assert_eq!(manifest["repository"]["credentialId"], SITE);
        assert_eq!(manifest["repository"]["allowedBranches"][0], "main");
        SiteManifest::from_json_for_site(
            &fs::read_to_string(fixture.manifest(SITE)).unwrap(),
            SiteId::parse(SITE).unwrap(),
        )
        .unwrap();

        let key_meta = fs::metadata(fixture.credential(SITE)).unwrap();
        assert_eq!(key_meta.permissions().mode() & 0o777, 0o600);
        assert_eq!((key_meta.uid(), key_meta.gid()), (fixture.uid, fixture.gid));
        assert_eq!(fs::read_to_string(fixture.credential(SITE)).unwrap(), KEY);
        let manifest_mode = fs::metadata(fixture.manifest(SITE)).unwrap();
        assert_eq!(manifest_mode.permissions().mode() & 0o777, 0o644);
        // No temp files are left behind.
        assert_eq!(fs::read_dir(&fixture.sites).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&fixture.creds).unwrap().count(), 1);
    }

    #[test]
    fn the_key_never_reaches_the_result_or_the_transaction_and_audit_records() {
        let fixture = Fixture::new();
        let result = fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
        let mut stack = vec![fixture._dir.path().join("state")];
        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    assert!(
                        !fs::read_to_string(&path)
                            .unwrap_or_default()
                            .contains("secret-material"),
                        "{path:?}"
                    );
                }
            }
        }
        let debug = format!(
            "{:?}",
            enroll_req(&plan(SITE, "a.test", "main", KEY), ID2, None)
        );
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn replay_by_key_and_a_repeat_with_a_new_request_are_idempotent() {
        let fixture = Fixture::new();
        let json = plan(SITE, "a.test", "main", KEY);
        let first = fixture
            .run_enroll(&enroll_req(&json, ID, Some("enrol-1")))
            .unwrap();
        let replayed = fixture
            .run_enroll(&enroll_req(&json, ID2, Some("enrol-1")))
            .unwrap();
        assert!(replayed.changed);
        assert_eq!(
            replayed.completed_at_unix_secs,
            first.completed_at_unix_secs
        );

        let repeat = fixture.run_enroll(&enroll_req(&json, ID3, None)).unwrap();
        assert!(!repeat.changed && !repeat.manifest_written && !repeat.credential_written);
    }

    #[test]
    fn re_enrolling_with_changes_rewrites_only_what_differs() {
        let fixture = Fixture::new();
        fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        let moved = fixture
            .run_enroll(&enroll_req(
                &plan(SITE, "a.test", "release", KEY),
                ID2,
                None,
            ))
            .unwrap();
        assert!(moved.manifest_written && !moved.credential_written);
        let rotated_key = KEY.replace("secret-material", "other-material");
        let rotated = fixture
            .run_enroll(&enroll_req(
                &plan(SITE, "a.test", "release", &rotated_key),
                ID3,
                None,
            ))
            .unwrap();
        assert!(!rotated.manifest_written && rotated.credential_written);
        assert_eq!(
            fs::read_to_string(fixture.credential(SITE)).unwrap(),
            rotated_key
        );
    }

    #[test]
    fn a_failed_manifest_write_puts_the_previous_key_back() {
        let fixture = Fixture::new();
        fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        // Make the manifest unwritable: a directory occupies its path.
        fs::remove_file(fixture.manifest(SITE)).unwrap();
        fs::create_dir(fixture.manifest(SITE)).unwrap();
        let rotated_key = KEY.replace("secret-material", "other-material");
        let error = fixture
            .run_enroll(&enroll_req(
                &plan(SITE, "a.test", "main", &rotated_key),
                ID2,
                None,
            ))
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        assert_eq!(fs::read_to_string(fixture.credential(SITE)).unwrap(), KEY);

        // With no previous key, the new one is removed.
        let fresh = Fixture::new();
        fs::create_dir_all(fresh.manifest(OTHER)).unwrap();
        fresh
            .run_enroll(&enroll_req(&plan(OTHER, "b.test", "main", KEY), ID3, None))
            .unwrap_err();
        assert!(!fresh.credential(OTHER).exists());
    }

    #[test]
    fn refuses_unknown_and_system_site_users_before_writing() {
        let fixture = Fixture::new();
        let mut json: serde_json::Value =
            serde_json::from_str(&plan(SITE, "a.test", "main", KEY)).unwrap();
        json["siteUser"] = "nobody_here".into();
        let error = fixture
            .run_enroll(&enroll_req(&json.to_string(), ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::InvalidSiteUser));
        assert!(!fixture.manifest(SITE).exists());
        assert!(!fixture.creds.exists());

        let (uid, gid) = (fixture.uid, fixture.gid);
        let resolve = move |_: &str| Some((uid, gid));
        let mut ctx = fixture.ctx(&resolve);
        ctx.min_identity = uid + 1;
        assert!(matches!(
            enroll(
                &ctx,
                &enroll_req(&plan(SITE, "a.test", "main", KEY), ID2, None)
            ),
            Err(Error::InvalidSiteUser)
        ));
    }

    #[test]
    fn rejects_malformed_requests() {
        let ok = plan(SITE, "a.test", "main", KEY);
        assert_eq!(
            EnrollRequest::parse("{}", ID, None).err(),
            Some(RequestError::InvalidRequest)
        );
        assert_eq!(
            EnrollRequest::parse(&plan("nope", "a.test", "main", KEY), ID, None).err(),
            Some(RequestError::InvalidSiteId)
        );
        assert_eq!(
            EnrollRequest::parse(&plan(SITE, "../etc", "main", KEY), ID, None).err(),
            Some(RequestError::InvalidRequest)
        );
        assert_eq!(
            EnrollRequest::parse(&plan(SITE, "a.test", "", KEY), ID, None).err(),
            Some(RequestError::InvalidRequest)
        );
        assert_eq!(
            EnrollRequest::parse(&plan(SITE, "a.test", "main", "not a key"), ID, None).err(),
            Some(RequestError::InvalidCredential)
        );
        let huge = format!("{KEY}{}", "a".repeat(MAX_CREDENTIAL_BYTES));
        assert_eq!(
            EnrollRequest::parse(&plan(SITE, "a.test", "main", &huge), ID, None).err(),
            Some(RequestError::InvalidCredential)
        );
        let extra = ok.replace("\"credential\"", "\"extra\":1,\"credential\"");
        assert_eq!(
            EnrollRequest::parse(&extra, ID, None).err(),
            Some(RequestError::InvalidRequest)
        );
        assert_eq!(
            EnrollRequest::parse(&ok, "not-a-uuid", None).err(),
            Some(RequestError::InvalidRequestId)
        );
    }

    #[test]
    fn unenroll_removes_both_files_and_is_idempotent_by_state() {
        let fixture = Fixture::new();
        fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        fixture
            .run_enroll(&enroll_req(&plan(OTHER, "b.test", "main", KEY), ID2, None))
            .unwrap();

        let removed = fixture
            .run_unenroll(&UnenrollRequest::parse(SITE, ID3, Some("un-1")).unwrap())
            .unwrap();
        assert!(removed.changed && removed.manifest_removed && removed.credential_removed);
        assert!(!fixture.manifest(SITE).exists());
        assert!(!fixture.credential(SITE).exists());
        // Another site is untouched.
        assert!(fixture.manifest(OTHER).exists());
        assert!(fixture.credential(OTHER).exists());

        let replayed = fixture
            .run_unenroll(&UnenrollRequest::parse(SITE, ID4, Some("un-1")).unwrap())
            .unwrap();
        assert!(replayed.changed);
        let repeat = fixture
            .run_unenroll(&UnenrollRequest::parse(SITE, ID2, None).unwrap())
            .unwrap();
        assert!(!repeat.changed && !repeat.manifest_removed && !repeat.credential_removed);
    }

    #[test]
    fn unenroll_finishes_a_half_removed_enrolment() {
        let fixture = Fixture::new();
        fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        fs::remove_file(fixture.manifest(SITE)).unwrap();
        let result = fixture
            .run_unenroll(&UnenrollRequest::parse(SITE, ID2, None).unwrap())
            .unwrap();
        assert!(!result.manifest_removed && result.credential_removed);
        assert!(!fixture.credential(SITE).exists());
    }

    #[test]
    fn a_held_site_or_manifest_lock_blocks_both_operations() {
        let fixture = Fixture::new();
        {
            let _held = resource_lock::acquire(
                &fixture.state,
                &fixture.manifest(SITE),
                RequestId::parse(ID3).unwrap(),
            )
            .unwrap();
            assert!(matches!(
                fixture.run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None)),
                Err(Error::Busy)
            ));
            assert!(matches!(
                fixture.run_unenroll(&UnenrollRequest::parse(SITE, ID2, None).unwrap()),
                Err(Error::Busy)
            ));
        }
        // The per-site mutation lock a deploy holds.
        let site_state =
            preflight::open_site_state(&fixture.state, SiteId::parse(SITE).unwrap()).unwrap();
        let _deploy = crate::transaction::lock::acquire(
            &site_state,
            &preflight::lock_path(),
            RequestId::parse(ID3).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            fixture.run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None)),
            Err(Error::Preflight(_))
        ));
        assert!(!fixture.manifest(SITE).exists());
    }

    #[test]
    fn enrol_then_rename_manifest_still_loads_through_the_deploy_loader() {
        let fixture = Fixture::new();
        fixture
            .run_enroll(&enroll_req(&plan(SITE, "a.test", "main", KEY), ID, None))
            .unwrap();
        let loaded = SiteManifest::load_owned_by(
            &fixture.manifest(SITE),
            fixture.uid,
            SiteId::parse(SITE).unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.domain, "a.test");
        assert_eq!(loaded.site_user, "site_user");
    }
}
