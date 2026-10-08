//! `site.setErrorPages` (milestone 076): the two HTML files a site serves for
//! a 404 and for a 5xx, and the `intercept` block in its process `Caddyfile`
//! that serves them, as one operation with one rollback.
//!
//! The control panel used to do this with `sudo mkdir`, base64 `tee`, `cp -p`
//! and `mv -f` over SSH, then activate the config, and put the files back from
//! its own backups if the activation failed. Here the caller sends the HTML
//! in a root-owned request file (never argv) and the engine does everything
//! under the shared `stacks/wcp` lock:
//!
//! 1. reads the site's current `Caddyfile` and builds the new one by adding
//!    (`enabled`) or removing the marked error-pages block, so the edit and
//!    the hash guard of the activation no longer depend on what the caller
//!    read earlier;
//! 2. with `enabled`, installs `<root>/.wcp-errors/404.html` and `5xx.html`
//!    (below);
//! 3. activates the config with the same validate, swap, restart, probe and
//!    roll back sequence as `stack.activateSiteConfig`;
//! 4. if step 3 fails for any reason, puts the files back exactly as they
//!    were (or removes the ones that did not exist, and the directory this
//!    request created).
//!
//! `enabled: false` only removes the block; the pages stay on disk so enabling
//! again does not lose the operator's HTML.
//!
//! # Files
//!
//! The document root is opened with the `O_NOFOLLOW` walk of `site_file`
//! (including its one exception, the engine's own `current` release link), so
//! a symlink a tenant planted is refused. `.wcp-errors` must be a directory
//! and each page a regular file or absent; a symlink in either place is
//! refused before anything is written. The pages are written through a
//! same-directory temp file and a rename, so a reader never sees half a page,
//! and are handed to the owner of the site directory with mode `0644` (the
//! directory `0755`). Each page is at most 128 KiB.

use std::io::{self, Write as _};

use cap_std::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    ingress::{ConfigHash, HashGuard},
    process::CancellationToken,
    site::{Domain, RuntimeId, SiteRelativePath, TrustedRoot},
    site_root::Error as RootError,
    stack_service::{
        Context, Error, RequestError, SiteActivation, activate_locked, read_site_caddyfile,
        run_admitted,
    },
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "site.setErrorPages";

const ERROR_PAGES_BEGIN: &str = "# wcp-error-pages-begin";
const ERROR_PAGES_END: &str = "# wcp-error-pages-end";
const PAGES_DIR: &str = ".wcp-errors";
const NOT_FOUND_FILE: &str = "404.html";
const SERVER_ERROR_FILE: &str = "5xx.html";
pub const MAX_PAGE_BYTES: usize = 128 * 1024;
/// A page that is already on disk is read back for the rollback; a larger
/// one is not something this operation ever wrote.
const MAX_PRIOR_PAGE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestParseError {
    InvalidRequest,
    InvalidHtml,
    Request(RequestError),
}

impl RequestParseError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "the request file is not a valid setErrorPages request",
            Self::InvalidHtml => {
                "error pages must be non-empty, at most 128 KiB each and contain no NUL"
            }
            Self::Request(error) => error.message(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRequest {
    runtime_id: String,
    domain: String,
    port: u16,
    root: String,
    enabled: bool,
    not_found_html: String,
    server_error_html: String,
}

#[derive(Debug)]
pub struct SetErrorPagesRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub port: u16,
    pub root: String,
    pub enabled: bool,
    not_found_html: String,
    server_error_html: String,
    content_roots: Vec<TrustedRoot>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

fn valid_html(html: &str) -> bool {
    !html.trim().is_empty() && html.len() <= MAX_PAGE_BYTES && !html.contains('\0')
}

impl SetErrorPagesRequest {
    pub fn parse(
        json: &str,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestParseError> {
        let raw: RawRequest =
            serde_json::from_str(json).map_err(|_| RequestParseError::InvalidRequest)?;
        let request = |error| RequestParseError::Request(error);
        let runtime_id = RuntimeId::parse(&raw.runtime_id)
            .map_err(|_| request(RequestError::InvalidRuntimeId))?;
        let domain =
            Domain::parse(&raw.domain).map_err(|_| request(RequestError::InvalidDomain))?;
        if raw.port == 0 {
            return Err(request(RequestError::InvalidPort));
        }
        crate::site_identity::validate_root(&raw.root, content_roots)
            .map_err(|_| request(RequestError::InvalidRoot))?;
        // A disabled request ignores the HTML, as the panel always has.
        if raw.enabled && !(valid_html(&raw.not_found_html) && valid_html(&raw.server_error_html)) {
            return Err(RequestParseError::InvalidHtml);
        }
        let request_id =
            RequestId::parse(request_id).map_err(|_| request(RequestError::InvalidRequestId))?;
        let idempotency_key = key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| request(RequestError::InvalidIdempotencyKey))?;
        Ok(Self {
            runtime_id,
            domain,
            port: raw.port,
            root: raw.root,
            enabled: raw.enabled,
            not_found_html: raw.not_found_html,
            server_error_html: raw.server_error_html,
            content_roots: content_roots.to_vec(),
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetErrorPagesResult {
    pub runtime_id: String,
    pub domain: String,
    pub enabled: bool,
    /// Page files written: 2 when enabled, 0 when only the block was removed.
    pub files_written: u32,
    pub completed_at_unix_secs: u64,
}

// ---- Caddyfile block ------------------------------------------------------
//
// Ported from the panel's `runtime_policies.rs` so the engine, not the panel,
// is the single editor of this block.

fn remove_marked_block(raw: &str) -> Result<String, Error> {
    let malformed = Error::ConfigMalformed("the site's error pages block is malformed");
    let mut result = Vec::new();
    let mut inside = false;
    for line in raw.lines() {
        match line.trim() {
            marker if marker == ERROR_PAGES_BEGIN && inside => return Err(malformed),
            marker if marker == ERROR_PAGES_BEGIN => inside = true,
            marker if marker == ERROR_PAGES_END && !inside => return Err(malformed),
            marker if marker == ERROR_PAGES_END => inside = false,
            _ if !inside => result.push(line),
            _ => {}
        }
    }
    if inside {
        return Err(malformed);
    }
    let joined = result.join("\n");
    Ok(if raw.ends_with('\n') {
        format!("{joined}\n")
    } else {
        joined
    })
}

fn replace_error_pages_block(raw: &str, enabled: bool) -> Result<String, Error> {
    let stripped = remove_marked_block(raw)?;
    if !enabled {
        return Ok(stripped);
    }
    let mut lines: Vec<String> = stripped.lines().map(str::to_owned).collect();
    let site_block = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim();
            trimmed != "{" && trimmed.ends_with('{') && !trimmed.starts_with('#')
        })
        .ok_or(Error::ConfigMalformed(
            "the site's Caddyfile has no site block",
        ))?;
    lines.splice(
        site_block + 1..site_block + 1,
        [
            format!("    {ERROR_PAGES_BEGIN}"),
            "    intercept {".to_owned(),
            "        @wcp_not_found status 404".to_owned(),
            "        handle_response @wcp_not_found {".to_owned(),
            format!("            rewrite * /{PAGES_DIR}/{NOT_FOUND_FILE}"),
            "            file_server".to_owned(),
            "        }".to_owned(),
            "        @wcp_server_error status 5xx".to_owned(),
            "        handle_response @wcp_server_error {".to_owned(),
            format!("            rewrite * /{PAGES_DIR}/{SERVER_ERROR_FILE}"),
            "            file_server".to_owned(),
            "        }".to_owned(),
            "    }".to_owned(),
            format!("    {ERROR_PAGES_END}"),
        ],
    );
    let joined = lines.join("\n");
    Ok(if stripped.ends_with('\n') {
        format!("{joined}\n")
    } else {
        joined
    })
}

// ---- Files ----------------------------------------------------------------

struct Prior {
    bytes: Vec<u8>,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// The two pages as installed by this request, with what is needed to take
/// them back out.
struct Installed {
    dir: ManagedRoot,
    pages: ManagedRoot,
    dir_name: SiteRelativePath,
    created_dir: bool,
    /// Pages already replaced, with what was there before.
    replaced: Vec<(SiteRelativePath, Option<Prior>)>,
}

fn name(value: &str) -> SiteRelativePath {
    SiteRelativePath::parse(value).expect("a fixed or generated name is one component")
}

/// A new `0600` temp file with `bytes`, handed to `uid:gid` with `mode`.
fn stage(
    pages: &ManagedRoot,
    temp: &SiteRelativePath,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> io::Result<()> {
    let result = (|| {
        let mut file = pages.create_new_file_with_mode(temp, 0o600)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        pages.chown(temp, uid, gid)?;
        pages.set_mode(temp, mode)
    })();
    if result.is_err() {
        let _ = pages.remove_file(temp);
    }
    result
}

fn unsafe_dir() -> Error {
    Error::SiteDirectory(RootError::UnsafePath)
}

impl Installed {
    /// Checks both targets, then writes both pages. Either both are in place
    /// or nothing this call did remains.
    fn install(dir: ManagedRoot, req: &SetErrorPagesRequest) -> Result<Self, Error> {
        let owner = dir.own_metadata().map_err(Error::Io)?;
        let (uid, gid) = (owner.uid(), owner.gid());
        let dir_name = name(PAGES_DIR);

        let created_dir = match dir.symlink_metadata(&dir_name) {
            Ok(metadata) if metadata.is_dir() => false,
            Ok(_) => return Err(unsafe_dir()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(Error::Io(error)),
        };
        // Look at both pages before anything is created.
        let targets = [
            (name(NOT_FOUND_FILE), &req.not_found_html),
            (name(SERVER_ERROR_FILE), &req.server_error_html),
        ];
        let mut priors = Vec::new();
        if !created_dir {
            let pages = dir.open_child_dir_nofollow(&dir_name).map_err(open_error)?;
            for (file, _) in &targets {
                priors.push(read_prior(&pages, file)?);
            }
        } else {
            priors.extend(targets.iter().map(|_| None));
        }

        if created_dir {
            dir.create_dir(&dir_name).map_err(Error::Io)?;
            if let Err(error) = dir
                .chown(&dir_name, uid, gid)
                .and_then(|()| dir.set_mode(&dir_name, 0o755))
            {
                let _ = dir.remove_dir(&dir_name);
                return Err(Error::Io(error));
            }
        } else {
            dir.set_mode(&dir_name, 0o755).map_err(Error::Io)?;
        }
        let pages = match dir.open_child_dir_nofollow(&dir_name) {
            Ok(pages) => pages,
            Err(error) => {
                if created_dir {
                    let _ = dir.remove_dir(&dir_name);
                }
                return Err(open_error(error));
            }
        };

        let mut installed = Self {
            dir,
            pages,
            dir_name,
            created_dir,
            replaced: Vec::new(),
        };
        let temps: Vec<SiteRelativePath> = targets
            .iter()
            .map(|(file, _)| {
                name(&format!(
                    ".{}.wcp-{}.tmp",
                    file.as_path().to_string_lossy(),
                    req.request_id
                ))
            })
            .collect();
        for ((_, html), temp) in targets.iter().zip(&temps) {
            if let Err(error) = stage(&installed.pages, temp, html.as_bytes(), uid, gid, 0o644) {
                installed.discard(&temps);
                return Err(Error::Io(error));
            }
        }
        for (((file, _), temp), prior) in targets.into_iter().zip(&temps).zip(priors) {
            if let Err(error) = installed.pages.rename(temp, &file) {
                installed.discard(&temps);
                if installed.rollback().is_err() {
                    return Err(Error::PagesRecoveryFailed);
                }
                return Err(Error::Io(error));
            }
            installed.replaced.push((file, prior));
        }
        Ok(installed)
    }

    fn discard(&self, temps: &[SiteRelativePath]) {
        for temp in temps {
            let _ = self.pages.remove_file(temp);
        }
        if self.replaced.is_empty() && self.created_dir {
            let _ = self.dir.remove_dir(&self.dir_name);
        }
    }

    /// Puts every replaced page back as it was, removes the ones that were
    /// not there, and the directory if this request created it.
    fn rollback(&self) -> io::Result<()> {
        let mut result = Ok(());
        for (file, prior) in &self.replaced {
            let restored = match prior {
                Some(prior) => {
                    let temp = name(&format!(".{}.wcp-restore.tmp", file.as_path().display()));
                    stage(
                        &self.pages,
                        &temp,
                        &prior.bytes,
                        prior.uid,
                        prior.gid,
                        prior.mode,
                    )
                    .and_then(|()| self.pages.rename(&temp, file))
                }
                None => match self.pages.remove_file(file) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                    _ => Ok(()),
                },
            };
            if let Err(error) = restored {
                result = Err(error);
            }
        }
        if result.is_ok() && self.created_dir {
            // Best effort: a tenant may have put something in it meanwhile.
            let _ = self.dir.remove_dir(&self.dir_name);
        }
        result
    }
}

fn open_error(error: io::Error) -> Error {
    Error::SiteDirectory(crate::site_root::open_error(error))
}

fn read_prior(pages: &ManagedRoot, file: &SiteRelativePath) -> Result<Option<Prior>, Error> {
    match pages.symlink_metadata(file) {
        Ok(metadata) if metadata.is_file() => {
            if metadata.size() > MAX_PRIOR_PAGE_BYTES {
                return Err(Error::SiteDirectory(RootError::FileTooLarge));
            }
            Ok(Some(Prior {
                bytes: pages.read_bytes(file).map_err(Error::Io)?,
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o777,
            }))
        }
        Ok(metadata) if metadata.file_type().is_symlink() => Err(unsafe_dir()),
        Ok(_) => Err(Error::SiteDirectory(RootError::NotRegularFile)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

pub fn set_error_pages(
    ctx: &Context<'_>,
    req: &SetErrorPagesRequest,
    cancel: &CancellationToken,
) -> Result<SetErrorPagesResult, Error> {
    run_admitted(
        ctx,
        OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let prior = read_site_caddyfile(ctx, &req.runtime_id, &req.domain)?
                .ok_or(Error::SiteConfigMissing)?;
            let text = std::str::from_utf8(&prior)
                .map_err(|_| Error::ConfigMalformed("the site's Caddyfile is not UTF-8"))?;
            let updated = replace_error_pages_block(text, req.enabled)?;

            let installed = if req.enabled {
                let dir = crate::site_file::open_site_directory(
                    &req.content_roots,
                    std::path::Path::new(&req.root),
                )
                .map_err(Error::SiteDirectory)?;
                Some(Installed::install(dir, req)?)
            } else {
                None
            };

            let guard = HashGuard::Sha256(ConfigHash::of(&prior));
            let activated = activate_locked(
                ctx,
                &SiteActivation {
                    runtime_id: &req.runtime_id,
                    domain: &req.domain,
                    port: req.port,
                    root: &req.root,
                    caddyfile: &updated,
                    guard: &guard,
                },
                cancel,
            );
            match activated {
                Ok(done) => Ok(SetErrorPagesResult {
                    runtime_id: done.runtime_id,
                    domain: done.domain,
                    enabled: req.enabled,
                    files_written: if installed.is_some() { 2 } else { 0 },
                    completed_at_unix_secs: done.completed_at_unix_secs,
                }),
                Err(error) => {
                    if let Some(installed) = installed {
                        if installed.rollback().is_err() {
                            return Err(Error::PagesRecoveryFailed);
                        }
                    }
                    Err(error)
                }
            }
        },
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::stack_service::HealthWait;
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::PathBuf,
        sync::Mutex,
        time::Duration,
    };

    const ID1: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174003";
    const NOT_FOUND: &str = "<html>custom 404</html>";
    const SERVER_ERROR: &str = "<html>custom 5xx</html>";

    /// Fork-heavy fixture tests share flock state with forked children.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        dir: tempfile::TempDir,
        roots: Vec<TrustedRoot>,
        state: ManagedRoot,
        runtime_root: TrustedRoot,
        site_services_root: TrustedRoot,
        log_root: TrustedRoot,
        stack_dir: PathBuf,
        docker: String,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            for d in [
                "www/site-a/public",
                "state",
                "runtimes",
                "services/fp1-php83/site-a.test",
                "logs",
                "stack",
            ] {
                fs::create_dir_all(base.join(d)).unwrap();
            }
            fs::write(
                base.join("services/fp1-php83/site-a.test/Caddyfile"),
                format!(
                    "{{\n    admin off\n}}\n\nhttp://127.0.0.1:9000 {{\n    root * {}\n    php_server\n}}\n",
                    base.join("www/site-a/public").display()
                ),
            )
            .unwrap();
            let docker = base.join("docker");
            fs::write(
                &docker,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     m=$(cat '{fail}' 2>/dev/null || echo __none__)\n\
                     case \"$*\" in *\"$m\"*) exit 1 ;; esac\nexit 0\n",
                    log = base.join("calls.log").display(),
                    fail = base.join("fail").display(),
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

        fn webroot(&self) -> PathBuf {
            self.dir.path().join("www/site-a/public")
        }

        fn pages_dir(&self) -> PathBuf {
            self.webroot().join(".wcp-errors")
        }

        fn caddyfile_path(&self) -> PathBuf {
            self.dir
                .path()
                .join("services/fp1-php83/site-a.test/Caddyfile")
        }

        fn caddyfile(&self) -> String {
            fs::read_to_string(self.caddyfile_path()).unwrap()
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }

        /// Makes the fake `docker` fail on any call containing `marker`.
        fn fail_on(&self, marker: &str) {
            fs::write(self.dir.path().join("fail"), marker).unwrap();
        }

        fn json(&self, enabled: bool, not_found: &str, server_error: &str) -> String {
            serde_json::json!({
                "runtimeId": "fp1-php83",
                "domain": "site-a.test",
                "port": 9000,
                "root": self.webroot().to_str().unwrap(),
                "enabled": enabled,
                "notFoundHtml": not_found,
                "serverErrorHtml": server_error,
            })
            .to_string()
        }

        fn request(&self, enabled: bool, id: &str, key: Option<&str>) -> SetErrorPagesRequest {
            SetErrorPagesRequest::parse(
                &self.json(enabled, NOT_FOUND, SERVER_ERROR),
                &self.roots,
                id,
                key,
            )
            .unwrap()
        }

        fn run(&self, req: &SetErrorPagesRequest) -> Result<SetErrorPagesResult, Error> {
            set_error_pages(&self.ctx(), req, &CancellationToken::default())
        }

        fn leftovers(&self) -> Vec<String> {
            fs::read_dir(self.pages_dir())
                .map(|entries| {
                    entries
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .filter(|n| n.ends_with(".tmp"))
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    #[test]
    fn request_validation() {
        let f = Fixture::new();
        let parse = |json: String| SetErrorPagesRequest::parse(&json, &f.roots, ID1, None);
        assert!(parse(f.json(true, NOT_FOUND, SERVER_ERROR)).is_ok());
        // Disabled ignores the HTML.
        assert!(parse(f.json(false, "", "")).is_ok());
        for bad in ["", "  \n", "a\0b", &"x".repeat(MAX_PAGE_BYTES + 1)] {
            assert_eq!(
                parse(f.json(true, bad, SERVER_ERROR)).unwrap_err(),
                RequestParseError::InvalidHtml
            );
            assert_eq!(
                parse(f.json(true, NOT_FOUND, bad)).unwrap_err(),
                RequestParseError::InvalidHtml
            );
        }
        assert!(parse(f.json(true, &"x".repeat(MAX_PAGE_BYTES), SERVER_ERROR)).is_ok());
        assert_eq!(
            parse("{}".into()).unwrap_err(),
            RequestParseError::InvalidRequest
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&f.json(true, NOT_FOUND, SERVER_ERROR)).unwrap();
        value["extra"] = true.into();
        assert_eq!(
            parse(value.to_string()).unwrap_err(),
            RequestParseError::InvalidRequest
        );
        for (field, bad, error) in [
            ("domain", "A b", RequestError::InvalidDomain),
            ("runtimeId", "../x", RequestError::InvalidRuntimeId),
            ("root", "/etc", RequestError::InvalidRoot),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&f.json(true, NOT_FOUND, SERVER_ERROR)).unwrap();
            value[field] = bad.into();
            assert_eq!(
                parse(value.to_string()).unwrap_err(),
                RequestParseError::Request(error)
            );
        }
        let mut value: serde_json::Value =
            serde_json::from_str(&f.json(true, NOT_FOUND, SERVER_ERROR)).unwrap();
        value["port"] = 0.into();
        assert_eq!(
            parse(value.to_string()).unwrap_err(),
            RequestParseError::Request(RequestError::InvalidPort)
        );
    }

    #[test]
    fn the_block_is_added_once_replaced_and_removed() {
        let base = "{\n    admin off\n}\n\nhttp://127.0.0.1:9000 {\n    root * /var/www/a\n    php_server\n}\n";
        let enabled = replace_error_pages_block(base, true).unwrap();
        assert!(enabled.contains(ERROR_PAGES_BEGIN) && enabled.contains(ERROR_PAGES_END));
        assert!(enabled.contains("rewrite * /.wcp-errors/404.html"));
        assert!(enabled.contains("rewrite * /.wcp-errors/5xx.html"));
        // After the site's opening line, not the global block's.
        assert!(
            enabled.find("http://127.0.0.1:9000 {").unwrap()
                < enabled.find(ERROR_PAGES_BEGIN).unwrap()
        );
        assert_eq!(replace_error_pages_block(&enabled, true).unwrap(), enabled);
        assert_eq!(enabled.matches(ERROR_PAGES_BEGIN).count(), 1);
        assert_eq!(replace_error_pages_block(&enabled, false).unwrap(), base);
        assert_eq!(replace_error_pages_block(base, false).unwrap(), base);
    }

    #[test]
    fn a_malformed_block_or_missing_site_block_is_refused() {
        let site = "http://127.0.0.1:9000 {\n    php_server\n}\n";
        for broken in [
            format!("{site}# wcp-error-pages-end\n"),
            format!("# wcp-error-pages-begin\n{site}"),
            format!(
                "# wcp-error-pages-begin\n# wcp-error-pages-begin\n# wcp-error-pages-end\n{site}"
            ),
        ] {
            assert!(matches!(
                replace_error_pages_block(&broken, true),
                Err(Error::ConfigMalformed(_))
            ));
        }
        assert!(matches!(
            replace_error_pages_block("admin off\n", true),
            Err(Error::ConfigMalformed(_))
        ));
    }

    #[test]
    fn enabling_installs_both_pages_and_the_block() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        let done = f.run(&f.request(true, ID1, None)).unwrap();
        assert!(done.enabled);
        assert_eq!(done.files_written, 2);
        assert_eq!(
            fs::read_to_string(f.pages_dir().join("404.html")).unwrap(),
            NOT_FOUND
        );
        assert_eq!(
            fs::read_to_string(f.pages_dir().join("5xx.html")).unwrap(),
            SERVER_ERROR
        );
        let me = fs::metadata(f.webroot()).unwrap();
        for file in ["404.html", "5xx.html"] {
            let m = fs::metadata(f.pages_dir().join(file)).unwrap();
            assert_eq!((m.uid(), m.gid()), (me.uid(), me.gid()));
            assert_eq!(m.mode() & 0o777, 0o644);
        }
        assert_eq!(fs::metadata(f.pages_dir()).unwrap().mode() & 0o777, 0o755);
        assert!(f.leftovers().is_empty());
        assert!(f.caddyfile().contains(ERROR_PAGES_BEGIN));
        let calls = f.calls();
        assert!(calls.contains("caddy validate"), "{calls}");
        assert!(calls.contains("s6-svc -r"), "{calls}");
    }

    #[test]
    fn a_retried_request_replays_without_touching_anything_again() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.run(&f.request(true, ID1, Some("ep-1"))).unwrap();
        let calls = f.calls();
        f.run(&f.request(true, ID1, Some("ep-1"))).unwrap();
        assert_eq!(f.calls(), calls);
    }

    #[test]
    fn a_failed_activation_restores_existing_pages_byte_for_byte() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        fs::create_dir_all(f.pages_dir()).unwrap();
        fs::write(f.pages_dir().join("404.html"), "old 404").unwrap();
        fs::write(f.pages_dir().join("5xx.html"), "old 5xx").unwrap();
        fs::set_permissions(
            f.pages_dir().join("404.html"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let caddy_before = f.caddyfile();

        // The readiness probe fails, so the new config is rolled back.
        f.fail_on("curl");
        let err = f.run(&f.request(true, ID1, None)).unwrap_err();
        assert!(matches!(err, Error::SiteRolledBack), "{err:?}");

        assert_eq!(
            fs::read_to_string(f.pages_dir().join("404.html")).unwrap(),
            "old 404"
        );
        assert_eq!(
            fs::read_to_string(f.pages_dir().join("5xx.html")).unwrap(),
            "old 5xx"
        );
        assert_eq!(
            fs::metadata(f.pages_dir().join("404.html")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(f.caddyfile(), caddy_before);
        assert!(f.leftovers().is_empty());
    }

    #[test]
    fn a_failed_activation_removes_pages_and_directory_it_created() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.fail_on("caddy validate");
        let err = f.run(&f.request(true, ID1, None)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Rejected(crate::stack_service::Stage::ValidateConfig, _)
            ),
            "{err:?}"
        );
        assert!(!f.pages_dir().exists(), "the directory is taken back out");
        assert!(!f.caddyfile().contains(ERROR_PAGES_BEGIN));
    }

    #[test]
    fn a_failed_activation_keeps_a_directory_that_already_existed() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        fs::create_dir_all(f.pages_dir()).unwrap();
        fs::write(f.pages_dir().join("other.txt"), "keep").unwrap();
        f.fail_on("caddy validate");
        f.run(&f.request(true, ID1, None)).unwrap_err();
        assert!(f.pages_dir().join("other.txt").exists());
        assert!(!f.pages_dir().join("404.html").exists());
        assert!(!f.pages_dir().join("5xx.html").exists());
    }

    #[test]
    fn disabling_removes_only_the_block_and_keeps_the_pages() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.run(&f.request(true, ID1, None)).unwrap();
        let done = f.run(&f.request(false, ID2, None)).unwrap();
        assert!(!done.enabled);
        assert_eq!(done.files_written, 0);
        assert!(!f.caddyfile().contains(ERROR_PAGES_BEGIN));
        assert_eq!(
            fs::read_to_string(f.pages_dir().join("404.html")).unwrap(),
            NOT_FOUND
        );
    }

    #[test]
    fn a_symlinked_pages_directory_or_page_is_refused_before_any_write() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        let outside = f.dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();

        std::os::unix::fs::symlink(&outside, f.pages_dir()).unwrap();
        let err = f.run(&f.request(true, ID1, None)).unwrap_err();
        assert!(
            matches!(err, Error::SiteDirectory(RootError::UnsafePath)),
            "{err:?}"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        fs::remove_file(f.pages_dir()).unwrap();

        fs::create_dir_all(f.pages_dir()).unwrap();
        fs::write(outside.join("target"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.join("target"), f.pages_dir().join("404.html")).unwrap();
        let err = f.run(&f.request(true, ID2, None)).unwrap_err();
        assert!(
            matches!(err, Error::SiteDirectory(RootError::UnsafePath)),
            "{err:?}"
        );
        assert_eq!(
            fs::read_to_string(outside.join("target")).unwrap(),
            "secret"
        );
        assert!(!f.pages_dir().join("5xx.html").exists());
        assert_eq!(f.calls(), "", "no docker call was made");
        assert!(!f.caddyfile().contains(ERROR_PAGES_BEGIN));
    }

    #[test]
    fn a_site_without_a_process_config_or_with_a_bad_one_changes_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        fs::write(
            f.caddyfile_path(),
            "# wcp-error-pages-begin\nhttp://x {\n}\n",
        )
        .unwrap();
        let err = f.run(&f.request(true, ID1, None)).unwrap_err();
        assert!(matches!(err, Error::ConfigMalformed(_)), "{err:?}");
        assert!(!f.pages_dir().exists());

        fs::remove_file(f.caddyfile_path()).unwrap();
        let err = f.run(&f.request(true, ID2, None)).unwrap_err();
        assert!(matches!(err, Error::SiteConfigMissing), "{err:?}");
        assert!(!f.pages_dir().exists());
        assert_eq!(f.calls(), "");
    }

    #[test]
    fn an_edit_made_outside_is_kept_by_the_next_request() {
        // The engine edits what it reads under the lock, so a hand edit made
        // between two requests is carried over, not overwritten.
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new();
        f.run(&f.request(true, ID1, None)).unwrap();
        let edited = format!("{}# edited by hand\n", f.caddyfile());
        fs::write(f.caddyfile_path(), &edited).unwrap();
        f.run(&f.request(false, ID3, None)).unwrap();
        assert!(f.caddyfile().contains("# edited by hand"));
        assert!(!f.caddyfile().contains(ERROR_PAGES_BEGIN));
    }

    #[test]
    fn errors_map_to_protocol_codes() {
        use crate::error::ErrorCode;
        assert_eq!(Error::SiteConfigMissing.protocol().0, ErrorCode::NotFound);
        assert_eq!(
            Error::ConfigMalformed("x").protocol().0,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            Error::PagesRecoveryFailed.protocol().0,
            ErrorCode::ConfigRecoveryFailed
        );
    }
}
