//! `agent.configure`: writes one agent's own configuration,
//! `$WCP_DIR/agents/<name>.conf` (E6), the file `ops-engine agent config get`
//! reads. The control panel used to have no safe way to hand an agent a
//! webhook URL or a token: every agent could read every shared `*.conf`.
//!
//! The request carries values that may be secrets, so it is a staged request
//! file (root-owned, not writable by others), never an argument. Values never
//! appear in the result, in an error, or anywhere but the `0600` file itself.
//!
//! `{"name": "my-agent", "values": {"KEY": "value", "OLD": null}, "merge": true}`
//!
//! - `values` maps keys (`[A-Za-z_][A-Za-z0-9_]{0,63}`, at most 64) to
//!   single-line strings (at most 4096 bytes, no NUL). `null` removes the key.
//! - Without `merge` the file becomes exactly `values`; with it the other keys
//!   already in the file are kept, so a panel can change one setting without
//!   holding the secrets it must not display.
//! - The agent must be installed (listed in `manifest.json`).
//! - The file is replaced atomically (temporary file, `0600`, `fsync`,
//!   `rename`) under a per-agent lock; writing what is already there changes
//!   nothing and reports `changed: false`.
//!
//! The engine does not know which keys an agent reads, so it checks syntax and
//! size, not names; the panel's form is built from the agent's declared keys.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{agent_helper::config, agent_lifecycle::valid_agent_name, agent_run, error::ErrorCode};

pub const OPERATION: &str = "agent.configure";
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_KEYS: usize = 64;
const MAX_VALUE_BYTES: usize = 4096;
const HEADER: &str =
    "# Written by the operations engine (agent.configure). KEY=VALUE, one per line.\n";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    name: String,
    values: BTreeMap<String, Option<String>>,
    #[serde(default)]
    merge: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidJson,
    InvalidName,
    InvalidKey,
    InvalidValue,
    TooMany,
    NotInstalled,
    /// Another configure of this agent is running.
    Busy,
    /// `merge` was asked for but the file already there is not `KEY=VALUE`.
    ExistingInvalid,
    Io,
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::InvalidJson => (
                ErrorCode::InvalidInput,
                "request-file is not a valid agent.configure request",
            ),
            Self::InvalidName => (
                ErrorCode::InvalidInput,
                "agent name must be lowercase letters, digits and '-' (at most 64)",
            ),
            Self::InvalidKey => (
                ErrorCode::InvalidInput,
                "a key is 1 to 64 characters of letters, digits and '_', not starting with a digit",
            ),
            Self::InvalidValue => (
                ErrorCode::InvalidInput,
                "a value must be one line of at most 4096 bytes without NUL",
            ),
            Self::TooMany => (ErrorCode::InvalidInput, "at most 64 keys"),
            Self::NotInstalled => (ErrorCode::NotFound, "this agent is not installed"),
            Self::Busy => (
                ErrorCode::Conflict,
                "another configuration change of this agent is in progress",
            ),
            Self::ExistingInvalid => (
                ErrorCode::Conflict,
                "the existing configuration is not KEY=VALUE lines; replace it instead of merging",
            ),
            Self::Io => (
                ErrorCode::Internal,
                "could not write the agent configuration",
            ),
        }
    }
}

impl Request {
    pub fn parse(json: &str) -> Result<Self, Error> {
        let request: Self = serde_json::from_str(json).map_err(|_| Error::InvalidJson)?;
        if !valid_agent_name(&request.name) {
            return Err(Error::InvalidName);
        }
        if request.values.len() > MAX_KEYS {
            return Err(Error::TooMany);
        }
        for (key, value) in &request.values {
            config::check_key(key).map_err(|_| Error::InvalidKey)?;
            if let Some(value) = value {
                if value.len() > MAX_VALUE_BYTES || value.contains(['\n', '\r', '\0']) {
                    return Err(Error::InvalidValue);
                }
            }
        }
        Ok(request)
    }
}

/// Key names only; there is deliberately no field that could hold a value.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configured {
    pub agent: String,
    pub changed: bool,
    /// Every key the file now holds.
    pub keys: Vec<String>,
    /// Keys removed by this request.
    pub removed: Vec<String>,
}

fn render(values: &BTreeMap<String, String>) -> String {
    let mut text = String::from(HEADER);
    for (key, value) in values {
        text.push_str(&format!("{key}={value}\n"));
    }
    text
}

fn sync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Applies the request below `dir` (`$WCP_DIR`). `required_uid` is the owner
/// an existing file must have (the running user).
pub fn execute(dir: &Path, required_uid: u32, request: &Request) -> Result<Configured, Error> {
    let name = &request.name;
    let agents = dir.join("agents");
    if !agent_run::installed(dir, name) {
        return Err(Error::NotInstalled);
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(agents.join(format!("{name}.conf.lock")))
        .map_err(|_| Error::Io)?;
    // SAFETY: `lock` is open for the whole function; closing it releases the lock.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(
            if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                Error::Busy
            } else {
                Error::Io
            },
        );
    }

    let existing = match config::read(dir, name, required_uid) {
        Ok(found) => found,
        Err(_) if !request.merge => None,
        Err(_) => return Err(Error::ExistingInvalid),
    };
    let mut values: BTreeMap<String, String> = if request.merge {
        existing.clone().unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let mut removed = Vec::new();
    for (key, value) in &request.values {
        match value {
            Some(value) => {
                values.insert(key.clone(), value.clone());
            }
            None => {
                if values.remove(key).is_some() {
                    removed.push(key.clone());
                }
            }
        }
    }
    if !request.merge {
        removed = existing
            .iter()
            .flat_map(|old| old.keys())
            .filter(|key| !values.contains_key(*key))
            .cloned()
            .collect();
    }
    let text = render(&values);
    let path = config::conf_path(dir, name);
    let unchanged = fs::read_to_string(&path).is_ok_and(|old| old == text)
        && fs::symlink_metadata(&path).is_ok_and(|meta| {
            meta.is_file()
                && meta.uid() == required_uid
                && meta.permissions().mode() & 0o777 == 0o600
        });
    if !unchanged {
        let temporary = agents.join(format!(".{name}.conf.{}.tmp", std::process::id()));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .and_then(|mut file| {
                file.write_all(text.as_bytes())?;
                file.sync_all()
            })
            .and_then(|()| fs::rename(&temporary, &path));
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Io);
        }
        sync_dir(&agents);
    }
    Ok(Configured {
        agent: name.clone(),
        changed: !unchanged,
        keys: values.into_keys().collect(),
        removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("agents")).unwrap();
        fs::write(
            dir.path().join("agents/manifest.json"),
            r#"{"demo":{"version":"1.0.0"}}"#,
        )
        .unwrap();
        dir
    }

    fn apply(dir: &Path, json: &str) -> Result<Configured, Error> {
        execute(dir, uid(), &Request::parse(json)?)
    }

    fn conf(dir: &Path) -> String {
        fs::read_to_string(dir.join("agents/demo.conf")).unwrap()
    }

    #[test]
    fn the_file_is_private_and_holds_exactly_the_values() {
        let dir = fixture();
        let result = apply(
            dir.path(),
            r#"{"name":"demo","values":{"WEBHOOK_URL":"https://h.example/x?a=b","B":"two words "}}"#,
        )
        .unwrap();
        assert!(result.changed);
        assert_eq!(result.keys, ["B", "WEBHOOK_URL"]);
        let path = dir.path().join("agents/demo.conf");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            conf(dir.path()),
            format!("{HEADER}B=two words \nWEBHOOK_URL=https://h.example/x?a=b\n")
        );
        // The reader the agents use sees the same values.
        let read = config::read(dir.path(), "demo", uid()).unwrap().unwrap();
        assert_eq!(read["B"], "two words ");
        assert_eq!(read["WEBHOOK_URL"], "https://h.example/x?a=b");
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("agents")).unwrap().collect();
        assert!(leftovers.iter().all(|e| {
            !e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn the_result_never_contains_a_value() {
        let dir = fixture();
        let result = apply(
            dir.path(),
            r#"{"name":"demo","values":{"TOKEN":"hunter2-secret"}}"#,
        )
        .unwrap();
        let shown = serde_json::to_string(&result).unwrap();
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("TOKEN"));
    }

    #[test]
    fn the_same_request_twice_changes_nothing_the_second_time() {
        let dir = fixture();
        let json = r#"{"name":"demo","values":{"A":"1"}}"#;
        assert!(apply(dir.path(), json).unwrap().changed);
        assert!(!apply(dir.path(), json).unwrap().changed);
    }

    #[test]
    fn replace_drops_the_old_keys_and_merge_keeps_them() {
        let dir = fixture();
        apply(
            dir.path(),
            r#"{"name":"demo","values":{"A":"1","B":"2","C":"3"}}"#,
        )
        .unwrap();
        let merged = apply(
            dir.path(),
            r#"{"name":"demo","merge":true,"values":{"B":"20","C":null,"D":"4","GONE":null}}"#,
        )
        .unwrap();
        assert_eq!(merged.keys, ["A", "B", "D"]);
        assert_eq!(merged.removed, ["C"]);
        assert!(conf(dir.path()).contains("B=20\n"));
        let replaced = apply(dir.path(), r#"{"name":"demo","values":{"X":"1"}}"#).unwrap();
        assert_eq!(replaced.keys, ["X"]);
        assert_eq!(replaced.removed, ["A", "B", "D"]);
        let empty = apply(dir.path(), r#"{"name":"demo","values":{}}"#).unwrap();
        assert!(empty.keys.is_empty());
        assert_eq!(conf(dir.path()), HEADER);
    }

    #[test]
    fn a_wider_existing_mode_is_tightened_even_when_the_content_matches() {
        let dir = fixture();
        let json = r#"{"name":"demo","values":{"A":"1"}}"#;
        apply(dir.path(), json).unwrap();
        let path = dir.path().join("agents/demo.conf");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(apply(dir.path(), json).unwrap().changed);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_symlink_in_place_of_the_file_is_replaced_not_followed() {
        let dir = fixture();
        let victim = dir.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("agents/demo.conf")).unwrap();
        apply(dir.path(), r#"{"name":"demo","values":{"A":"1"}}"#).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert!(
            !fs::symlink_metadata(dir.path().join("agents/demo.conf"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_stale_temporary_symlink_is_not_followed() {
        let dir = fixture();
        let victim = dir.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        let temporary = dir
            .path()
            .join(format!("agents/.demo.conf.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temporary).unwrap();
        assert_eq!(
            apply(dir.path(), r#"{"name":"demo","values":{"A":"1"}}"#),
            Err(Error::Io)
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[test]
    fn requests_are_validated_and_leave_no_file() {
        let dir = fixture();
        for (json, error) in [
            ("nope", Error::InvalidJson),
            (
                r#"{"name":"demo","values":{},"extra":1}"#,
                Error::InvalidJson,
            ),
            (r#"{"name":"demo","values":{"A":1}}"#, Error::InvalidJson),
            (r#"{"name":"../x","values":{}}"#, Error::InvalidName),
            (r#"{"name":"demo","values":{"a-b":"1"}}"#, Error::InvalidKey),
            (r#"{"name":"demo","values":{"1a":"1"}}"#, Error::InvalidKey),
            (
                r#"{"name":"demo","values":{"A":"x\ny"}}"#,
                Error::InvalidValue,
            ),
            (
                r#"{"name":"demo","values":{"A":"x\u0000y"}}"#,
                Error::InvalidValue,
            ),
        ] {
            assert_eq!(apply(dir.path(), json), Err(error), "{json}");
        }
        let long = "x".repeat(MAX_VALUE_BYTES + 1);
        assert_eq!(
            apply(
                dir.path(),
                &format!(r#"{{"name":"demo","values":{{"A":"{long}"}}}}"#)
            ),
            Err(Error::InvalidValue)
        );
        let many: Vec<String> = (0..=MAX_KEYS).map(|n| format!(r#""K{n}":"v""#)).collect();
        assert_eq!(
            apply(
                dir.path(),
                &format!(r#"{{"name":"demo","values":{{{}}}}}"#, many.join(","))
            ),
            Err(Error::TooMany)
        );
        assert!(!dir.path().join("agents/demo.conf").exists());
    }

    #[test]
    fn only_installed_agents_can_be_configured() {
        let dir = fixture();
        assert_eq!(
            apply(dir.path(), r#"{"name":"other","values":{"A":"1"}}"#),
            Err(Error::NotInstalled)
        );
    }

    #[test]
    fn merge_refuses_a_file_it_cannot_read_and_replace_overwrites_it() {
        let dir = fixture();
        fs::write(dir.path().join("agents/demo.conf"), "not key value\n").unwrap();
        fs::set_permissions(
            dir.path().join("agents/demo.conf"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            apply(
                dir.path(),
                r#"{"name":"demo","merge":true,"values":{"A":"1"}}"#
            ),
            Err(Error::ExistingInvalid)
        );
        assert_eq!(conf(dir.path()), "not key value\n");
        assert!(
            apply(dir.path(), r#"{"name":"demo","values":{"A":"1"}}"#)
                .unwrap()
                .changed
        );
    }

    #[test]
    fn a_concurrent_configure_is_a_conflict() {
        let dir = fixture();
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.path().join("agents/demo.conf.lock"))
            .unwrap();
        // SAFETY: `held` is open.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        assert_eq!(
            apply(dir.path(), r#"{"name":"demo","values":{"A":"1"}}"#),
            Err(Error::Busy)
        );
    }
}
