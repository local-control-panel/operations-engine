//! `site.probe` (milestone 075): the three checks the control panel makes by
//! writing a PHP file into a site's webroot, fetching it through the
//! runtime pool and deleting it again (`application_probe`, `php_opcache_
//! stats`, `php_opcache_reset`), as one operation with fixed contents.
//!
//! The panel's `run_php_probe` took arbitrary PHP from its caller. Here the
//! caller only picks a kind, and the engine owns the code each kind runs:
//!
//! - `applicationToken`: echoes a fresh random token; the response must be
//!   exactly that token. A wrong document root, a stale cached page or a PHP
//!   error page fails it, which a bare status check would not.
//! - `opcacheStatus`: prints `opcache_get_status(false)` as JSON (or
//!   `{"enabled": false}`).
//! - `opcacheReset`: calls `opcache_reset()` and requires `{"ok": true}`.
//!
//! The probe file is `_wcp_probe_<32 hex>.php` in the site directory, owned
//! by the directory's owner, `0644`, and removed in every outcome. It also
//! carries a 120 second deadline after which it deletes itself, and every
//! probe first sweeps stale probe files of that exact name pattern, so a
//! crash between the write and the delete cannot leave a page behind for
//! longer than that.
//!
//! The request goes through `docker compose exec -T <service> curl`, to the
//! runtime pool directly (plain HTTP with a `Host` header) or, for
//! `ingress`, to its HTTPS listener with `--resolve`, exactly as the panel
//! did. It runs under the shared `stacks/wcp` lock like every other
//! operation that talks to the stack.

use std::{
    io::{self, Write as _},
    time::{Duration, SystemTime},
};

use cap_std::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    process::CancellationToken,
    site::{Domain, SiteRelativePath, TrustedRoot},
    stack_service::{Context, Error, RequestError, Service, Stage, compose, run_admitted},
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "site.probe";

const PROBE_PREFIX: &str = "_wcp_probe_";
const PROBE_SUFFIX: &str = ".php";
/// A probe file deletes itself after this long.
const PROBE_LIFETIME_SECS: u64 = 120;
const CURL_TIMEOUT: Duration = Duration::from_secs(15);
/// `curl --max-time`, as the panel used.
const CURL_MAX_TIME_SECS: &str = "5";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    ApplicationToken,
    OpcacheStatus,
    OpcacheReset,
}

impl Kind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "applicationToken" => Some(Self::ApplicationToken),
            "opcacheStatus" => Some(Self::OpcacheStatus),
            "opcacheReset" => Some(Self::OpcacheReset),
            _ => None,
        }
    }

    /// The PHP after the deadline guard.
    fn php(self, token: &str) -> String {
        match self {
            Self::ApplicationToken => format!("echo '{token}';"),
            Self::OpcacheStatus => "$s = function_exists('opcache_get_status') ? opcache_get_status(false) : false; \
                 echo json_encode($s === false ? ['enabled' => false] : array_merge(['enabled' => true], $s));"
                .to_owned(),
            Self::OpcacheReset => {
                "$ok = function_exists('opcache_reset') && opcache_reset(); echo json_encode(['ok' => $ok]);"
                    .to_owned()
            }
        }
    }
}

#[derive(Debug)]
pub struct ProbeRequest {
    pub kind: Kind,
    pub service: Service,
    pub domain: Domain,
    pub root: String,
    content_roots: Vec<TrustedRoot>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeRequestError {
    InvalidKind,
    Request(RequestError),
}

impl ProbeRequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidKind => "kind must be applicationToken, opcacheStatus or opcacheReset",
            Self::Request(error) => error.message(),
        }
    }
}

impl ProbeRequest {
    pub fn parse(
        kind: &str,
        service: &str,
        domain: &str,
        root: &str,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, ProbeRequestError> {
        let kind = Kind::parse(kind).ok_or(ProbeRequestError::InvalidKind)?;
        let service = Service::parse(service)
            .ok_or(ProbeRequestError::Request(RequestError::InvalidService))?;
        let domain = Domain::parse(domain)
            .map_err(|_| ProbeRequestError::Request(RequestError::InvalidDomain))?;
        crate::site_identity::validate_root(root, content_roots)
            .map_err(|_| ProbeRequestError::Request(RequestError::InvalidRoot))?;
        let request_id = RequestId::parse(request_id)
            .map_err(|_| ProbeRequestError::Request(RequestError::InvalidRequestId))?;
        let idempotency_key = key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| ProbeRequestError::Request(RequestError::InvalidIdempotencyKey))?;
        Ok(Self {
            kind,
            service,
            domain,
            root: root.to_owned(),
            content_roots: content_roots.to_vec(),
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub kind: Kind,
    pub service: String,
    pub domain: String,
    /// `opcacheStatus`: the status object. Absent for the other kinds.
    pub data: Option<serde_json::Value>,
    pub completed_at_unix_secs: u64,
}

fn is_probe_file_name(name: &str) -> bool {
    name.strip_prefix(PROBE_PREFIX)
        .and_then(|rest| rest.strip_suffix(PROBE_SUFFIX))
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Removes probe files older than their own lifetime; best effort.
fn sweep_stale(dir: &ManagedRoot) {
    let Ok(names) = dir.file_names() else { return };
    for name in names.into_iter().filter(|n| is_probe_file_name(n)) {
        let Ok(path) = SiteRelativePath::parse(&name) else {
            continue;
        };
        let stale = dir
            .modified(&path)
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age.as_secs() > PROBE_LIFETIME_SECS);
        if stale {
            let _ = dir.remove_file(&path);
        }
    }
}

fn curl_argv(service: &Service, domain: &Domain, file: &str) -> Vec<String> {
    let mut argv: Vec<String> = ["exec", "-T", &service.name(), "curl"]
        .map(str::to_owned)
        .to_vec();
    if matches!(service, Service::Ingress) {
        // The ingress edge redirects :80 to :443, so dial its HTTPS listener
        // with the right SNI/Host.
        argv.extend(
            [
                "-sfk",
                "--max-time",
                CURL_MAX_TIME_SECS,
                "--resolve",
                &format!("{domain}:443:127.0.0.1"),
                &format!("https://{domain}/{file}"),
            ]
            .map(str::to_owned),
        );
    } else {
        argv.extend(
            [
                "-sf",
                "--max-time",
                CURL_MAX_TIME_SECS,
                "-H",
                &format!("Host: {domain}"),
                &format!("http://127.0.0.1/{file}"),
            ]
            .map(str::to_owned),
        );
    }
    argv
}

pub fn probe_site(
    ctx: &Context<'_>,
    req: &ProbeRequest,
    cancel: &CancellationToken,
) -> Result<ProbeResult, Error> {
    run_admitted(
        ctx,
        OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let dir = crate::site_file::open_site_directory(
                &req.content_roots,
                std::path::Path::new(&req.root),
            )
            .map_err(Error::SiteDirectory)?;
            sweep_stale(&dir);

            let token = uuid::Uuid::new_v4().simple().to_string();
            let file = format!("{PROBE_PREFIX}{token}{PROBE_SUFFIX}");
            let path = SiteRelativePath::parse(&file).expect("a generated name is one component");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            let body = format!(
                "<?php if (time() > {}) {{ @unlink(__FILE__); exit; }} {}\n",
                now + PROBE_LIFETIME_SECS,
                req.kind.php(&token)
            );
            write_probe(&dir, &path, &body).map_err(Error::Io)?;

            let fetched = compose(
                ctx,
                Stage::ApplicationProbe,
                &curl_argv(&req.service, &req.domain, &file)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                CURL_TIMEOUT,
                cancel,
            );
            // In every outcome.
            let _ = dir.remove_file(&path);
            let output = fetched?;
            interpret(req.kind, &token, &output).map(|data| ProbeResult {
                kind: req.kind,
                service: req.service.name(),
                domain: req.domain.as_str().to_owned(),
                data,
                completed_at_unix_secs: now,
            })
        },
    )
}

fn write_probe(dir: &ManagedRoot, path: &SiteRelativePath, body: &str) -> io::Result<()> {
    let owner = dir.own_metadata()?;
    let result = (|| {
        let mut file = dir.create_new_file_with_mode(path, 0o600)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        drop(file);
        dir.chown(path, owner.uid(), owner.gid())?;
        dir.set_mode(path, 0o644)
    })();
    if result.is_err() {
        let _ = dir.remove_file(path);
    }
    result
}

fn interpret(kind: Kind, token: &str, output: &str) -> Result<Option<serde_json::Value>, Error> {
    let output = output.trim();
    match kind {
        Kind::ApplicationToken if output == token => Ok(None),
        Kind::ApplicationToken => Err(Error::ProbeUnexpected(
            "the site did not return the control token; a wrong document root or a PHP error page is a likely cause",
        )),
        Kind::OpcacheStatus => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(value) if value.is_object() => Ok(Some(value)),
            _ => Err(Error::ProbeUnexpected(
                "the site did not return an OPcache status object",
            )),
        },
        Kind::OpcacheReset => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(value) if value.get("ok") == Some(&serde_json::Value::Bool(true)) => Ok(None),
            _ => Err(Error::ProbeUnexpected("OPcache could not be reset")),
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{filesystem::ManagedRoot, stack_service::HealthWait};
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const ID1: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174003";
    const TOKEN_FIXTURE: &str = "TOKEN";

    struct Fixture {
        dir: tempfile::TempDir,
        roots: Vec<TrustedRoot>,
        state: ManagedRoot,
        runtime_root: TrustedRoot,
        site_services_root: TrustedRoot,
        log_root: TrustedRoot,
        stack_dir: std::path::PathBuf,
        docker: String,
    }

    impl Fixture {
        /// `reply` is what the fake `docker compose exec ... curl` prints;
        /// the word `TOKEN` is replaced by the token of the probe file it
        /// finds in the webroot, as a real PHP would.
        fn new(reply: &str, exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            for d in [
                "www/site-a/public",
                "state",
                "runtimes",
                "services",
                "logs",
                "stack",
            ] {
                fs::create_dir_all(base.join(d)).unwrap();
            }
            let docker = base.join("docker");
            fs::write(
                &docker,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     for last; do :; done\n\
                     f=${{last##*/}}\n\
                     t=${{f#_wcp_probe_}}; t=${{t%.php}}\n\
                     printf '%s' '{reply}' | sed \"s/{TOKEN_FIXTURE}/$t/\"\n\
                     exit {exit}\n",
                    log = base.join("calls.log").display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                roots: vec![TrustedRoot::parse(base.join("www")).unwrap()],
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                runtime_root: TrustedRoot::parse(base.join("runtimes")).unwrap(),
                site_services_root: TrustedRoot::parse(base.join("services")).unwrap(),
                log_root: TrustedRoot::parse(base.join("logs")).unwrap(),
                stack_dir: base.join("stack"),
                docker: docker.to_string_lossy().into_owned(),
                dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                runtime_root: &self.runtime_root,
                site_services_root: &self.site_services_root,
                log_root: &self.log_root,
                chown_logs: false,
                stack_dir: &self.stack_dir,
                docker: &self.docker,
                health: HealthWait {
                    timeout: Duration::from_millis(100),
                    interval: Duration::from_millis(10),
                },
            }
        }

        fn webroot(&self) -> std::path::PathBuf {
            self.dir.path().join("www/site-a/public")
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }

        fn request(&self, kind: &str, service: &str, id: &str) -> ProbeRequest {
            ProbeRequest::parse(
                kind,
                service,
                "site-a.test",
                self.webroot().to_str().unwrap(),
                &self.roots,
                id,
                None,
            )
            .unwrap()
        }

        fn probe_files(&self) -> Vec<String> {
            fs::read_dir(self.webroot())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("_wcp_probe_"))
                .collect()
        }
    }

    fn run(f: &Fixture, req: &ProbeRequest) -> Result<ProbeResult, Error> {
        probe_site(&f.ctx(), req, &CancellationToken::default())
    }

    #[test]
    fn request_validation() {
        let base = tempfile::tempdir().unwrap();
        let roots = vec![TrustedRoot::parse(base.path()).unwrap()];
        let root = base.path().join("site-a/public");
        let parse = |kind: &str, service: &str, domain: &str, root: &str| {
            ProbeRequest::parse(kind, service, domain, root, &roots, ID1, None).map(|_| ())
        };
        let ok_root = root.to_str().unwrap();
        assert_eq!(
            parse("applicationToken", "runtime-fp1-php83", "a.test", ok_root),
            Ok(())
        );
        assert_eq!(parse("opcacheStatus", "ingress", "a.test", ok_root), Ok(()));
        assert_eq!(parse("opcacheReset", "ingress", "a.test", ok_root), Ok(()));
        assert_eq!(
            parse("phpinfo", "ingress", "a.test", ok_root),
            Err(ProbeRequestError::InvalidKind)
        );
        assert_eq!(
            parse("opcacheReset", "mariadb", "a.test", ok_root),
            Err(ProbeRequestError::Request(RequestError::InvalidService))
        );
        assert_eq!(
            parse("opcacheReset", "ingress", "A b", ok_root),
            Err(ProbeRequestError::Request(RequestError::InvalidDomain))
        );
        assert_eq!(
            parse("opcacheReset", "ingress", "a.test", "/etc"),
            Err(ProbeRequestError::Request(RequestError::InvalidRoot))
        );
        assert!(is_probe_file_name(&format!(
            "_wcp_probe_{}.php",
            "a".repeat(32)
        )));
        assert!(!is_probe_file_name("_wcp_probe_x.php"));
        assert!(!is_probe_file_name(&format!(
            "_wcp_probe_{}.php.bak",
            "a".repeat(32)
        )));
    }

    #[test]
    fn the_application_token_must_come_back_and_the_file_is_removed() {
        let f = Fixture::new("TOKEN\n", 0);
        let done = run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap();
        assert_eq!(done.kind, Kind::ApplicationToken);
        assert_eq!(done.data, None);
        assert!(f.probe_files().is_empty(), "the probe file is removed");
        let calls = f.calls();
        assert!(calls.contains("exec -T runtime-fp1-php83 curl -sf --max-time 5 -H Host: site-a.test http://127.0.0.1/_wcp_probe_"), "{calls}");
        assert!(calls.contains("-p wcp"), "{calls}");
    }

    #[test]
    fn ingress_probes_dial_the_https_listener() {
        let f = Fixture::new("TOKEN", 0);
        run(&f, &f.request("applicationToken", "ingress", ID1)).unwrap();
        let calls = f.calls();
        assert!(calls.contains("exec -T ingress curl -sfk --max-time 5 --resolve site-a.test:443:127.0.0.1 https://site-a.test/_wcp_probe_"), "{calls}");
    }

    #[test]
    fn a_wrong_answer_fails_and_still_removes_the_file() {
        let f = Fixture::new("<html>500</html>", 0);
        let err = run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap_err();
        assert!(matches!(err, Error::ProbeUnexpected(_)));
        assert_eq!(err.protocol().0, crate::error::ErrorCode::SubprocessFailed);
        assert!(f.probe_files().is_empty());
    }

    #[test]
    fn a_failed_request_still_removes_the_file() {
        let f = Fixture::new("", 22);
        let err = run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap_err();
        assert!(matches!(err, Error::Rejected(Stage::ApplicationProbe, _)));
        assert!(f.probe_files().is_empty());
    }

    #[test]
    fn opcache_status_returns_the_object_and_reset_requires_ok() {
        let f = Fixture::new(r#"{"enabled":true,"opcache_enabled":true}"#, 0);
        let done = run(&f, &f.request("opcacheStatus", "runtime-fp1-php83", ID1)).unwrap();
        assert_eq!(done.data.unwrap()["enabled"], true);

        let f = Fixture::new("not json", 0);
        assert!(matches!(
            run(&f, &f.request("opcacheStatus", "runtime-fp1-php83", ID2)).unwrap_err(),
            Error::ProbeUnexpected(_)
        ));

        let f = Fixture::new(r#"{"ok":true}"#, 0);
        run(&f, &f.request("opcacheReset", "runtime-fp1-php83", ID3)).unwrap();
        let f = Fixture::new(r#"{"ok":false}"#, 0);
        assert!(matches!(
            run(&f, &f.request("opcacheReset", "runtime-fp1-php83", ID1)).unwrap_err(),
            Error::ProbeUnexpected("OPcache could not be reset")
        ));
    }

    #[test]
    fn the_probe_file_is_fixed_php_with_its_own_deadline() {
        // The fake docker records the file it sees.
        let f = Fixture::new("TOKEN", 0);
        let www = f.webroot();
        let docker = Path::new(&f.docker);
        let script = fs::read_to_string(docker).unwrap().replace(
            "exit 0",
            &format!(
                "cp \"{}/$f\" '{}/seen.php' 2>/dev/null\nexit 0",
                www.display(),
                f.dir.path().display()
            ),
        );
        fs::write(docker, script).unwrap();
        run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap();
        let seen = fs::read_to_string(f.dir.path().join("seen.php")).unwrap();
        assert!(seen.starts_with("<?php if (time() > "), "{seen}");
        assert!(seen.contains("@unlink(__FILE__); exit; }"), "{seen}");
        assert!(seen.contains("echo '"), "{seen}");
    }

    #[test]
    fn stale_probe_files_are_swept_and_fresh_ones_are_left() {
        let f = Fixture::new("TOKEN", 0);
        let stale = f
            .webroot()
            .join(format!("_wcp_probe_{}.php", "a".repeat(32)));
        let fresh = f
            .webroot()
            .join(format!("_wcp_probe_{}.php", "b".repeat(32)));
        let other = f.webroot().join("_wcp_probe_notes.php");
        for p in [&stale, &fresh, &other] {
            fs::write(p, "x").unwrap();
        }
        let old = std::time::SystemTime::now() - Duration::from_secs(PROBE_LIFETIME_SECS + 60);
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap();
        assert!(!stale.exists());
        assert!(fresh.exists() && other.exists());
    }

    #[test]
    fn an_unsafe_site_directory_is_refused_without_running_anything() {
        let f = Fixture::new("TOKEN", 0);
        let target = f.dir.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        fs::remove_dir_all(f.dir.path().join("www/site-a")).unwrap();
        std::os::unix::fs::symlink(&target, f.dir.path().join("www/site-a")).unwrap();
        let req = ProbeRequest::parse(
            "applicationToken",
            "runtime-fp1-php83",
            "site-a.test",
            f.dir.path().join("www/site-a/public").to_str().unwrap(),
            &f.roots,
            ID1,
            None,
        )
        .unwrap();
        let err = run(&f, &req).unwrap_err();
        assert!(matches!(err, Error::SiteDirectory(_)));
        assert_eq!(err.protocol().0, crate::error::ErrorCode::InvalidInput);
        assert!(f.calls().is_empty());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn a_busy_stack_is_a_conflict() {
        let f = Fixture::new("TOKEN", 0);
        let scope = crate::stack_deploy::open_scope(&f.state).unwrap();
        let held = crate::stack_deploy::acquire_stack_lock(&scope, RequestId::parse(ID3).unwrap())
            .map_err(|_| ())
            .unwrap();
        let err = run(&f, &f.request("applicationToken", "runtime-fp1-php83", ID1)).unwrap_err();
        assert!(matches!(err, Error::StackBusy));
        assert!(f.probe_files().is_empty() && f.calls().is_empty());
        drop(held);
    }
}
