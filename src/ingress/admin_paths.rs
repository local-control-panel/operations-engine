//! The `ingress.applyAdminPaths` operation: restricting a site's sensitive
//! admin paths (`/wp-login.php`, `/wp-admin`, `/user/login`, `/administrator`,
//! `/admin`) to an IP allowlist or to HTTP Basic auth.
//!
//! It rides on the same mechanism as `ingress.applyBans`: every route imports
//! `bans/*.caddy`, so one extra file per domain, `bans/admin-<domain>.caddy`,
//! restricts that domain without touching its route file. Each file carries a
//! `host <domain>` matcher (the import lands in every site block), so it only
//! ever affects its own site. The file is validated in a throw-away site block,
//! swapped in by renames, reloaded, and put back if the reload refuses it
//! (`apply_bans::apply_managed_file`).
//!
//! The request names a site kind and ids from a closed catalog; the engine
//! maps ids to paths, so the panel can never inject a matcher. An allowlist
//! answers 403 to every other address; Basic auth answers 401 without the
//! password. A request with no `restriction` removes the file, which restores
//! normal access.
//!
//! Only the bcrypt hash of a Basic-auth password is accepted, written to the
//! file and never returned, logged or recorded; the file's header comment
//! carries the settings (no hash) so a client can read them back.

use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    ingress::{
        ConfigHash,
        apply_bans::{BANS_DIR, apply_managed_file},
        execute::ActivateContext,
        transition::{self, LifecycleError, unix_now_secs},
    },
    process::CancellationToken,
    site::Domain,
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name.
pub const APPLY_ADMIN_PATHS_OPERATION: &str = "ingress.applyAdminPaths";

/// Prefix of the per-domain file under `bans/`.
pub const ADMIN_FILE_PREFIX: &str = "admin-";

/// Marker that starts the settings line in the file header.
pub const SETTINGS_MARKER: &str = "# wcp-admin-paths ";

pub const MAX_IPS: usize = 64;

/// One restrictable group of paths of a site kind.
pub struct CatalogEntry {
    pub id: &'static str,
    /// Caddy `path` patterns, matched case-insensitively with slashes merged.
    pub paths: &'static [&'static str],
    /// Paths inside `paths` that must stay public (front-end AJAX endpoints).
    pub except: &'static [&'static str],
}

pub struct KindCatalog {
    pub kind: &'static str,
    pub entries: &'static [CatalogEntry],
}

/// Closed catalog of sensitive paths per site kind.
pub const CATALOG: &[KindCatalog] = &[
    KindCatalog {
        kind: "wordpress",
        entries: &[
            CatalogEntry {
                id: "login",
                paths: &["/wp-login.php"],
                except: &[],
            },
            CatalogEntry {
                id: "admin",
                paths: &["/wp-admin", "/wp-admin/*"],
                // Themes and plugins call these from the public front end.
                except: &["/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php"],
            },
        ],
    },
    KindCatalog {
        kind: "drupal",
        entries: &[
            CatalogEntry {
                id: "login",
                paths: &["/user", "/user/login"],
                except: &[],
            },
            CatalogEntry {
                id: "admin",
                paths: &["/admin", "/admin/*"],
                except: &[],
            },
        ],
    },
    KindCatalog {
        kind: "joomla",
        entries: &[CatalogEntry {
            id: "admin",
            paths: &["/administrator", "/administrator/*"],
            except: &[],
        }],
    },
    KindCatalog {
        kind: "laravel",
        entries: &[CatalogEntry {
            id: "admin",
            paths: &["/admin", "/admin/*"],
            except: &[],
        }],
    },
];

pub fn catalog_for(kind: &str) -> Option<&'static KindCatalog> {
    CATALOG.iter().find(|entry| entry.kind == kind)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    IpAllowlist,
    BasicAuth,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Restriction {
    pub kind: &'static str,
    /// Catalog ids, in catalog order, de-duplicated.
    pub paths: Vec<&'static str>,
    pub mode: Mode,
    /// Canonical addresses or CIDR ranges (allowlist mode).
    pub ips: Vec<String>,
    /// Basic auth mode.
    pub username: Option<String>,
    pub password_hash: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ApplyAdminPathsRequest {
    pub domain: Domain,
    /// `None` removes the restriction.
    pub restriction: Option<Restriction>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyAdminPathsRequestError {
    InvalidJson,
    InvalidDomain,
    UnknownKind,
    UnknownPath,
    NoPaths,
    InvalidIp,
    TooManyIps,
    NoIps,
    InvalidUsername,
    InvalidPasswordHash,
    /// A field of the other mode was sent.
    MixedModes,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    domain: String,
    restriction: Option<PlanRestriction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanRestriction {
    kind: String,
    paths: Vec<String>,
    mode: Mode,
    #[serde(default)]
    ips: Vec<String>,
    username: Option<String>,
    password_hash: Option<String>,
}

/// The settings written into the file header (never the hash).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Stored<'a> {
    domain: &'a str,
    kind: &'a str,
    paths: &'a [&'static str],
    mode: Mode,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    ips: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
}

fn canonical_ip(raw: &str) -> Option<String> {
    match raw.split_once('/') {
        None => IpAddr::from_str(raw).ok().map(|ip| ip.to_string()),
        Some((address, prefix)) => {
            let ip = IpAddr::from_str(address).ok()?;
            if prefix.is_empty()
                || prefix.len() > 3
                || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let prefix: u8 = prefix.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            (prefix <= max).then(|| format!("{ip}/{prefix}"))
        }
    }
}

fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// A bcrypt hash as `caddy hash-password` prints it.
fn valid_bcrypt(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    bytes.len() == 60
        && hash.starts_with("$2")
        && matches!(bytes[2], b'a' | b'b' | b'y')
        && bytes[3] == b'$'
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'$'
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/'))
}

impl ApplyAdminPathsRequest {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, ApplyAdminPathsRequestError> {
        use ApplyAdminPathsRequestError as E;
        let plan: Plan = serde_json::from_str(json).map_err(|_| E::InvalidJson)?;
        let domain = Domain::parse(&plan.domain).map_err(|_| E::InvalidDomain)?;
        let restriction = plan.restriction.map(parse_restriction).transpose()?;
        Ok(Self {
            domain,
            restriction,
            request_id: RequestId::parse(request_id).map_err(|_| E::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| E::InvalidIdempotencyKey)?,
        })
    }

    /// The file name under the ingress root.
    pub fn file_name(&self) -> String {
        format!("{BANS_DIR}/{ADMIN_FILE_PREFIX}{}.caddy", self.domain)
    }

    /// The exact bytes of the file, or `None` when the restriction is removed.
    pub fn content(&self) -> Option<String> {
        let restriction = self.restriction.as_ref()?;
        let catalog = catalog_for(restriction.kind).expect("kind was validated");
        let mut paths: Vec<&str> = Vec::new();
        let mut except: Vec<&str> = Vec::new();
        for entry in catalog.entries {
            if restriction.paths.contains(&entry.id) {
                paths.extend(entry.paths);
                except.extend(entry.except);
            }
        }
        let digest = ConfigHash::of(self.domain.as_str().as_bytes());
        let matcher = format!("@wcp_adm_{}", &digest.as_str()[..12]);
        let stored = Stored {
            domain: self.domain.as_str(),
            kind: restriction.kind,
            paths: &restriction.paths,
            mode: restriction.mode,
            ips: &restriction.ips,
            username: restriction.username.as_deref(),
        };
        let mut out = String::from("# Managed by ingress.applyAdminPaths. Do not edit.\n");
        out.push_str(SETTINGS_MARKER);
        out.push_str(&serde_json::to_string(&stored).expect("plain struct serializes"));
        out.push('\n');
        out.push_str(&format!("{matcher} {{\n    host {}\n", self.domain));
        out.push_str(&format!("    path {}\n", paths.join(" ")));
        if !except.is_empty() {
            out.push_str(&format!("    not path {}\n", except.join(" ")));
        }
        match restriction.mode {
            Mode::IpAllowlist => {
                out.push_str(&format!(
                    "    not remote_ip {}\n}}\nrespond {matcher} 403\n",
                    restriction.ips.join(" ")
                ));
            }
            Mode::BasicAuth => {
                out.push_str(&format!(
                    "}}\nbasicauth {matcher} {{\n    {} {}\n}}\n",
                    restriction.username.as_deref().unwrap_or_default(),
                    restriction.password_hash.as_deref().unwrap_or_default()
                ));
            }
        }
        Some(out)
    }
}

fn parse_restriction(plan: PlanRestriction) -> Result<Restriction, ApplyAdminPathsRequestError> {
    use ApplyAdminPathsRequestError as E;
    let catalog = catalog_for(&plan.kind).ok_or(E::UnknownKind)?;
    if plan.paths.is_empty() {
        return Err(E::NoPaths);
    }
    for id in &plan.paths {
        if !catalog.entries.iter().any(|entry| entry.id == id) {
            return Err(E::UnknownPath);
        }
    }
    let paths: Vec<&'static str> = catalog
        .entries
        .iter()
        .filter(|entry| plan.paths.iter().any(|id| id == entry.id))
        .map(|entry| entry.id)
        .collect();
    let (mut ips, mut username, mut password_hash) = (Vec::new(), None, None);
    match plan.mode {
        Mode::IpAllowlist => {
            if plan.username.is_some() || plan.password_hash.is_some() {
                return Err(E::MixedModes);
            }
            if plan.ips.is_empty() {
                // An empty allowlist would lock every address out.
                return Err(E::NoIps);
            }
            if plan.ips.len() > MAX_IPS {
                return Err(E::TooManyIps);
            }
            ips = plan
                .ips
                .iter()
                .map(|raw| canonical_ip(raw).ok_or(E::InvalidIp))
                .collect::<Result<Vec<_>, _>>()?;
            ips.sort();
            ips.dedup();
        }
        Mode::BasicAuth => {
            if !plan.ips.is_empty() {
                return Err(E::MixedModes);
            }
            let name = plan.username.ok_or(E::InvalidUsername)?;
            if !valid_username(&name) {
                return Err(E::InvalidUsername);
            }
            let hash = plan.password_hash.ok_or(E::InvalidPasswordHash)?;
            if !valid_bcrypt(&hash) {
                return Err(E::InvalidPasswordHash);
            }
            username = Some(name);
            password_hash = Some(hash);
        }
    }
    Ok(Restriction {
        kind: catalog.kind,
        paths,
        mode: plan.mode,
        ips,
        username,
        password_hash,
    })
}

/// The `result` payload of a successful `ingress.applyAdminPaths` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyAdminPathsResult {
    pub domain: String,
    /// `true` when a restriction is now in force, `false` when removed.
    pub restricted: bool,
    /// `false` when the file already held this content (the ingress was still
    /// reloaded to confirm it).
    pub changed: bool,
    /// Digest of the file; absent after a removal.
    pub content_sha256: Option<ConfigHash>,
    pub applied_at_unix_secs: u64,
}

pub type ApplyAdminPathsError = LifecycleError<ApplyAdminPathsResult>;

pub fn execute(
    context: &ActivateContext<'_>,
    request: &ApplyAdminPathsRequest,
    cancellation: &CancellationToken,
) -> Result<ApplyAdminPathsResult, ApplyAdminPathsError> {
    let op_state = crate::ingress::execute::open_ingress_state(context.engine_state)
        .map_err(LifecycleError::Io)?;
    transition::run(
        context.engine_state,
        &op_state,
        APPLY_ADMIN_PATHS_OPERATION,
        request.request_id,
        request.idempotency_key.as_ref(),
        cancellation,
        || {
            let content = request.content();
            let outcome = apply_managed_file(
                context,
                &request.request_id,
                &request.file_name(),
                content.as_deref().map(str::as_bytes),
            )?;
            Ok(ApplyAdminPathsResult {
                domain: request.domain.to_string(),
                restricted: content.is_some(),
                changed: outcome.changed,
                content_sha256: content
                    .as_deref()
                    .map(|text| ConfigHash::of(text.as_bytes())),
                applied_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{
        ApplyAdminPathsError, ApplyAdminPathsRequest, ApplyAdminPathsRequestError,
        ApplyAdminPathsResult, execute,
    };
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{execute::ActivateContext, fake_docker::FakeDocker},
        process::CancellationToken,
        site::TrustedRoot,
    };

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const HASH: &str = "$2a$14$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890";

    fn good_hash() -> String {
        // 60 chars: "$2a$14$" + 53.
        format!("$2a$14${}", "a".repeat(53))
    }

    fn allowlist(domain: &str, ips: &[&str]) -> String {
        serde_json::json!({"domain": domain, "restriction": {
            "kind": "wordpress", "paths": ["admin", "login"],
            "mode": "ipAllowlist", "ips": ips}})
        .to_string()
    }

    fn basic(hash: &str) -> String {
        serde_json::json!({"domain": "a.test", "restriction": {
            "kind": "joomla", "paths": ["admin"], "mode": "basicAuth",
            "username": "editor", "passwordHash": hash}})
        .to_string()
    }

    fn parse(json: &str) -> Result<ApplyAdminPathsRequest, ApplyAdminPathsRequestError> {
        ApplyAdminPathsRequest::parse(json, ID, None)
    }

    #[test]
    fn an_allowlist_renders_a_host_scoped_403_with_public_ajax() {
        let req = parse(&allowlist(
            "a.test",
            &["203.0.113.9", "10.0.0.0/8", "203.0.113.9"],
        ))
        .unwrap();
        let content = req.content().unwrap();
        assert!(content.contains("host a.test\n"), "{content}");
        assert!(content.contains("path /wp-login.php /wp-admin /wp-admin/*\n"));
        assert!(content.contains("not path /wp-admin/admin-ajax.php /wp-admin/admin-post.php\n"));
        assert!(content.contains("not remote_ip 10.0.0.0/8 203.0.113.9\n"));
        assert!(content.contains("403\n"));
        assert!(!content.contains("basicauth"));
        assert_eq!(req.file_name(), "bans/admin-a.test.caddy");
    }

    #[test]
    fn basic_auth_writes_the_hash_but_the_header_never_carries_it() {
        let hash = good_hash();
        let content = parse(&basic(&hash)).unwrap().content().unwrap();
        assert!(content.contains(&format!("    editor {hash}\n")));
        let header = content
            .lines()
            .find(|line| line.starts_with("# wcp-admin-paths "))
            .unwrap();
        assert!(!header.contains("$2a$") && header.contains("\"username\":\"editor\""));
        assert!(content.contains("path /administrator /administrator/*\n"));
    }

    #[test]
    fn removal_has_no_content() {
        let json = serde_json::json!({"domain": "a.test", "restriction": null}).to_string();
        assert!(parse(&json).unwrap().content().is_none());
    }

    #[test]
    fn requests_that_could_inject_caddy_or_lock_everyone_out_are_refused() {
        use ApplyAdminPathsRequestError as E;
        let wp = |extra: serde_json::Value| {
            let mut restriction = serde_json::json!({"kind": "wordpress", "paths": ["login"],
                "mode": "ipAllowlist", "ips": ["1.2.3.4"]});
            for (key, value) in extra.as_object().unwrap() {
                restriction[key] = value.clone();
            }
            serde_json::json!({"domain": "a.test", "restriction": restriction}).to_string()
        };
        assert_eq!(
            parse(&wp(serde_json::json!({"ips": ["1.2.3.4 respond 200"]}))).unwrap_err(),
            E::InvalidIp
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"ips": ["1.2.3.4/33"]}))).unwrap_err(),
            E::InvalidIp
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"ips": []}))).unwrap_err(),
            E::NoIps
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"paths": ["/etc"]}))).unwrap_err(),
            E::UnknownPath
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"paths": []}))).unwrap_err(),
            E::NoPaths
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"kind": "node"}))).unwrap_err(),
            E::UnknownKind
        );
        assert_eq!(
            parse(&wp(serde_json::json!({"username": "x"}))).unwrap_err(),
            E::MixedModes
        );
        assert_eq!(
            parse(&allowlist("a.test}", &["1.2.3.4"])).unwrap_err(),
            E::InvalidDomain
        );
        assert_eq!(
            parse(&allowlist("../x", &["1.2.3.4"])).unwrap_err(),
            E::InvalidDomain
        );
        assert_eq!(
            parse(&basic("plain-password")).unwrap_err(),
            E::InvalidPasswordHash
        );
        assert_eq!(parse(&basic(HASH)).unwrap_err(), E::InvalidPasswordHash);
        let bad_user = basic(&good_hash()).replace("editor", "ed itor");
        assert_eq!(parse(&bad_user).unwrap_err(), E::InvalidUsername);
        assert_eq!(
            parse("{\"domain\":\"a.test\",\"restriction\":null,\"x\":1}").unwrap_err(),
            E::InvalidJson
        );
        assert_eq!(
            ApplyAdminPathsRequest::parse(
                "{\"domain\":\"a.test\",\"restriction\":null}",
                "nope",
                None
            )
            .unwrap_err(),
            E::InvalidRequestId
        );
    }

    struct Host {
        state_dir: tempfile::TempDir,
        ingress_dir: tempfile::TempDir,
        ingress_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(existing: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().unwrap();
        let ingress_dir = tempfile::tempdir().unwrap();
        if let Some(text) = existing {
            fs::create_dir(ingress_dir.path().join("bans")).unwrap();
            fs::write(ingress_dir.path().join("bans/admin-a.test.caddy"), text).unwrap();
        }
        Host {
            engine_state: ManagedRoot::open(&TrustedRoot::parse(state_dir.path()).unwrap())
                .unwrap(),
            ingress_root: TrustedRoot::parse(ingress_dir.path()).unwrap(),
            state_dir,
            ingress_dir,
        }
    }

    impl Host {
        fn file(&self) -> Option<String> {
            fs::read_to_string(self.ingress_dir.path().join("bans/admin-a.test.caddy")).ok()
        }

        fn leftovers(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.ingress_dir.path().join("bans"))
                .map(|dir| {
                    dir.map(|e| e.unwrap().file_name().into_string().unwrap())
                        .collect()
                })
                .unwrap_or_default();
            names.retain(|name| name != "admin-a.test.caddy");
            names
        }

        fn status(&self, id: &str) -> String {
            let path = self
                .state_dir
                .path()
                .join(format!("ingress/transactions/{id}.json"));
            let record: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
            record["status"].as_str().unwrap_or_default().to_owned()
        }
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        json: &str,
        id: &str,
    ) -> Result<ApplyAdminPathsResult, ApplyAdminPathsError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        let request = ApplyAdminPathsRequest::parse(json, id, None).unwrap();
        execute(&context, &request, &CancellationToken::default())
    }

    const REMOVE: &str = "{\"domain\":\"a.test\",\"restriction\":null}";

    #[test]
    fn apply_validates_reloads_and_leaves_one_file() {
        let host = host(None);
        let docker = FakeDocker::new();
        let result = run(&host, &docker, &allowlist("a.test", &["203.0.113.9"]), ID).unwrap();
        assert!(result.changed && result.restricted && result.content_sha256.is_some());
        assert!(host.file().unwrap().contains("not remote_ip 203.0.113.9"));
        assert_eq!(docker.calls("validate").len(), 1);
        assert_eq!(docker.calls("reload").len(), 1);
        assert_eq!(host.leftovers(), Vec::<String>::new());
        assert_eq!(host.status(ID), "COMMITTED");
    }

    #[test]
    fn removal_restores_normal_access_and_a_second_removal_changes_nothing() {
        let host = host(None);
        let docker = FakeDocker::new();
        run(&host, &docker, &allowlist("a.test", &["203.0.113.9"]), ID).unwrap();
        let removed = run(&host, &docker, REMOVE, ID2).unwrap();
        assert!(removed.changed && !removed.restricted);
        assert!(host.file().is_none());
        assert_eq!(host.leftovers(), Vec::<String>::new());
        let again = run(
            &host,
            &docker,
            REMOVE,
            "11111111-5678-4abc-9def-0123456789ab",
        )
        .unwrap();
        assert!(!again.changed);
    }

    #[test]
    fn a_rejected_validation_changes_nothing() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("validate", "all");
        let error = run(&host, &docker, &allowlist("a.test", &["203.0.113.9"]), ID).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert_eq!(host.file().as_deref(), Some("old\n"));
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }

    #[test]
    fn a_refused_reload_puts_the_previous_file_back() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("reload", "1");
        let error = run(&host, &docker, &allowlist("a.test", &["203.0.113.9"]), ID).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.file().as_deref(), Some("old\n"));
        assert_eq!(docker.calls("reload").len(), 2);
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }

    #[test]
    fn a_refused_reload_on_removal_puts_the_file_back() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("reload", "1");
        let error = run(&host, &docker, REMOVE, ID).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.file().as_deref(), Some("old\n"));
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }
}
