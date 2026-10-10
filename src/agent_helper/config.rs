//! `agent config get|list`: the agent's own configuration,
//! `$WCP_DIR/agents/NAME.conf`.
//!
//! The file is `KEY=VALUE` lines, `#` comments and blank lines. A value is
//! everything after the first `=`, verbatim: no quoting, no expansion, no
//! shell. It is read through `O_NOFOLLOW` and only when it is a regular file
//! owned by the user running the helper and not writable by group or others,
//! so another user cannot plant values for a root agent.
//!
//! The shared `*.conf` files that built-in agents read directly (`backup.conf`
//! and friends, JSON) are not consulted here; `agent configure` writes this
//! file.

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use super::{HelperError, check_name, io_failure};

const MAX_CONF_BYTES: u64 = 64 * 1024;
const MAX_KEY_CHARS: usize = 64;

pub fn conf_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("agents").join(format!("{name}.conf"))
}

pub fn check_key(key: &str) -> Result<(), HelperError> {
    let mut bytes = key.bytes();
    let valid = key.len() <= MAX_KEY_CHARS
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(HelperError::Invalid(
            "a config key is 1 to 64 characters of letters, digits and '_', not starting with a digit"
                .into(),
        ))
    }
}

pub fn parse(text: &str) -> Result<BTreeMap<String, String>, HelperError> {
    let mut values = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // Never echo the line: it may hold a secret.
        let bad = || HelperError::Failed(format!("line {} is not KEY=VALUE", index + 1));
        let (key, value) = line.split_once('=').ok_or_else(bad)?;
        check_key(key).map_err(|_| bad())?;
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

/// The agent's configuration, or `None` when it has no file.
pub fn read(
    dir: &Path,
    name: &str,
    required_uid: u32,
) -> Result<Option<BTreeMap<String, String>>, HelperError> {
    check_name(name)?;
    let path = conf_path(dir, name);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_failure("cannot open the agent configuration", &error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("cannot read the agent configuration", &error))?;
    if !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(HelperError::Failed(
            "the agent configuration must be a regular file owned by the running user and not writable by others"
                .into(),
        ));
    }
    if metadata.len() > MAX_CONF_BYTES {
        return Err(HelperError::Failed(
            "the agent configuration is too large".into(),
        ));
    }
    let mut text = String::new();
    (&mut file)
        .take(MAX_CONF_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| io_failure("cannot read the agent configuration", &error))?;
    parse(&text).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn put(dir: &Path, text: &str, mode: u32) {
        fs::create_dir_all(dir.join("agents")).unwrap();
        let path = conf_path(dir, "demo");
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn values_are_verbatim_after_the_first_equals_sign() {
        let values =
            parse("# comment\n\nA=1\nB=two words \nC=x=y\nD=\"q\"\nE=\r\nF=$(id)\n  # c\n")
                .unwrap();
        assert_eq!(values["A"], "1");
        assert_eq!(values["B"], "two words ");
        assert_eq!(values["C"], "x=y");
        assert_eq!(values["D"], "\"q\"");
        assert_eq!(values["E"], "");
        assert_eq!(values["F"], "$(id)");
        assert_eq!(values.len(), 6);
    }

    #[test]
    fn a_later_key_wins_and_junk_lines_fail_without_echoing_them() {
        let values = parse("A=1\nA=2\n").unwrap();
        assert_eq!(values["A"], "2");
        let error = parse("A=1\nSECRETVALUE\n").unwrap_err();
        match error {
            HelperError::Failed(message) => {
                assert!(message.contains("line 2"));
                assert!(!message.contains("SECRETVALUE"));
            }
            HelperError::Invalid(_) => panic!("expected a runtime failure"),
        }
        assert!(parse("1A=x\n").is_err());
        assert!(parse("A B=x\n").is_err());
    }

    #[test]
    fn keys_are_validated() {
        for ok in ["A", "_a", "WEBHOOK_URL", &"k".repeat(64)] {
            assert!(check_key(ok).is_ok(), "{ok}");
        }
        for bad in ["", "1a", "a-b", "a.b", "a b", &"k".repeat(65)] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_missing_file_is_none_and_a_good_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path(), "demo", uid()).unwrap(), None);
        put(dir.path(), "WEBHOOK_URL=https://h.example/x\n", 0o600);
        let values = read(dir.path(), "demo", uid()).unwrap().unwrap();
        assert_eq!(values["WEBHOOK_URL"], "https://h.example/x");
    }

    #[test]
    fn a_file_others_can_write_or_another_user_owns_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "A=1\n", 0o666);
        assert!(read(dir.path(), "demo", uid()).is_err());
        put(dir.path(), "A=1\n", 0o620);
        assert!(read(dir.path(), "demo", uid()).is_err());
        put(dir.path(), "A=1\n", 0o644);
        assert!(read(dir.path(), "demo", uid()).is_ok());
        assert!(read(dir.path(), "demo", uid() + 1).is_err());
    }

    #[test]
    fn a_symlinked_configuration_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("agents")).unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "A=1\n").unwrap();
        std::os::unix::fs::symlink(&target, conf_path(dir.path(), "demo")).unwrap();
        assert!(read(dir.path(), "demo", uid()).is_err());
    }

    #[test]
    fn a_bad_agent_name_is_invalid_and_oversize_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read(dir.path(), "../x", uid()),
            Err(HelperError::Invalid(_))
        ));
        put(dir.path(), &format!("A={}\n", "x".repeat(70_000)), 0o600);
        assert!(read(dir.path(), "demo", uid()).is_err());
    }
}
