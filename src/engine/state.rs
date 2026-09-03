//! Where an installed engine binary's own version bookkeeping lives:
//! `engine/install.state`, beneath the shared state root, in a new
//! `engine/` subtree parallel to `sites/<siteId>/`
//! (`mutation::preflight::open_site_state`). Tracks exactly two
//! versions — the one active now and the one `engine rollback` can
//! restore without a network call — never a longer history.

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    site::{SiteRelativePath, TrustedRoot, ValidationError},
};

/// The single subdirectory of the engine-wide state root everything in
/// this module lives under.
const ENGINE_SUBTREE: &str = "engine";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallState {
    pub active_version: String,
    pub previous_version: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    Corrupt,
}

/// `None` means no engine has ever been installed through this path yet
/// (a fresh host, or one whose current binary predates this feature).
pub fn load(engine_state: &ManagedRoot) -> Result<Option<InstallState>, Error> {
    match engine_state.read_to_string(&install_state_path()) {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|_| Error::Corrupt),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Io),
    }
}

pub fn save(engine_state: &ManagedRoot, state: &InstallState) -> Result<(), Error> {
    let bytes = serde_json::to_vec(state).map_err(|_| Error::Corrupt)?;
    engine_state
        .write_atomic(&install_state_path(), &bytes)
        .map_err(|_| Error::Io)
}

fn install_state_path() -> SiteRelativePath {
    SiteRelativePath::parse("install.state").expect("literal path is valid")
}

/// Opens (creating if necessary) the engine-wide install state beneath
/// `engine_state`'s `engine/` subtree, ensuring the
/// `locks`/`transactions`/`audit`/`versions` subdirectories
/// `mutation::preflight::run` and `install.rs`/`rollback.rs` expect
/// already exist. Mirrors `mutation::preflight::open_site_state`, but
/// there is only ever one of these per host — no per-ID scoping.
pub fn open_engine_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(ENGINE_SUBTREE).expect("literal path is valid");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit", "versions"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

/// Resolves `relative` — interpreted beneath the same `engine/` subtree
/// `open_engine_state` scopes to — to an absolute path under
/// `state_root`, verified (through `TrustedRoot::resolve_existing`) not to
/// escape it. `ManagedRoot` is a capability handle with no path of its
/// own, so this is the only way to name a file in the engine's state to
/// something outside this process. The one caller is `install::execute`,
/// which has to hand the staged binary's real path to the process runner
/// to smoke-test it before activation.
pub fn resolve_path(
    state_root: &TrustedRoot,
    relative: &SiteRelativePath,
) -> Result<PathBuf, ValidationError> {
    let beneath_engine =
        SiteRelativePath::parse(Path::new(ENGINE_SUBTREE).join(relative.as_path()))
            .map_err(|_| ValidationError::InvalidRelativePath)?;
    state_root.resolve_existing(&beneath_engine)
}

#[cfg(test)]
mod tests {
    use super::{InstallState, load, open_engine_state, resolve_path, save};
    use crate::{
        filesystem::ManagedRoot,
        site::{SiteRelativePath, TrustedRoot},
    };

    fn engine_state() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let state_root = ManagedRoot::open(&root).expect("root should open");
        let scoped = open_engine_state(&state_root).expect("engine state should open");
        (directory, scoped)
    }

    #[test]
    fn load_returns_none_before_anything_is_installed() {
        let (_directory, engine_state) = engine_state();
        assert_eq!(load(&engine_state).unwrap(), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_directory, engine_state) = engine_state();
        let state = InstallState {
            active_version: "0.5.0".to_owned(),
            previous_version: Some("0.4.0".to_owned()),
        };
        save(&engine_state, &state).expect("save should succeed");
        assert_eq!(load(&engine_state).unwrap(), Some(state));
    }

    #[test]
    fn open_engine_state_creates_every_expected_subdirectory() {
        let (directory, _engine_state) = engine_state();
        for sub in ["locks", "transactions", "audit", "versions"] {
            assert!(
                directory.path().join("engine").join(sub).is_dir(),
                "engine/{sub} should exist"
            );
        }
    }

    #[test]
    fn resolve_path_names_a_real_file_beneath_the_engine_subtree() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let state_root = ManagedRoot::open(&root).expect("root should open");
        let scoped = open_engine_state(&state_root).expect("engine state should open");
        let relative = SiteRelativePath::parse("versions/9.9.9").expect("path should be valid");
        scoped
            .create_dir_all(&relative)
            .expect("version directory should be created");

        let resolved = resolve_path(&root, &relative).expect("path should resolve");
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("engine/versions/9.9.9"));
        // A path that does not exist yet has nothing to resolve.
        let missing = SiteRelativePath::parse("versions/0.0.0").expect("path should be valid");
        assert!(resolve_path(&root, &missing).is_err());
    }

    #[test]
    fn open_engine_state_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let state_root = ManagedRoot::open(&root).expect("root should open");
        open_engine_state(&state_root).expect("first open should succeed");
        open_engine_state(&state_root).expect("second open should also succeed, not error");
        let _ = SiteRelativePath::parse("engine").expect("literal path is valid");
    }
}
