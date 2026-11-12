//! On-disk layout of one site's baselines (see the module docs).

use std::{collections::BTreeMap, io};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{SCHEMA_VERSION, scan::hex};
use crate::{filesystem::ManagedRoot, site::SiteRelativePath};

const ROOT_DIR: &str = "security-baselines";
const INDEX: &str = "index.json";
/// Upper bound for one generation file read back (50 000 paths + hashes with headroom).
const MAX_GENERATION_BYTES: u64 = 64 * 1024 * 1024;

fn rel(path: impl AsRef<std::path::Path>) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("baseline store paths are fixed and valid")
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Index {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub next_generation: u32,
    #[serde(default)]
    pub accepted: Option<u32>,
    #[serde(default)]
    pub candidate: Option<u32>,
    #[serde(default)]
    pub accepted_at_unix_secs: Option<u64>,
    #[serde(default)]
    pub generations: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitsRecord {
    pub max_files: usize,
    pub max_bytes: u64,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generation {
    pub schema_version: u32,
    pub site_id: String,
    pub subsite: Option<String>,
    pub kind: String,
    /// Canonical content root. Kept for identity checks, never sent to the UI.
    pub root: String,
    pub generation: u32,
    pub created_at_unix_secs: u64,
    pub algorithm: String,
    pub scope: String,
    pub limits: LimitsRecord,
    pub file_count: usize,
    pub bytes_read: u64,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub incomplete_path: Option<String>,
    pub digest: String,
    /// Sorted `[relative path, sha256]` pairs. Nothing else is stored.
    pub files: Vec<(String, String)>,
}

pub fn digest(files: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (path, hash) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(hash.as_bytes());
        hasher.update([b'\n']);
    }
    hex(&hasher.finalize())
}

pub fn gen_name(generation: u32) -> String {
    format!("gen-{generation:06}.json")
}

pub struct Store {
    dir: ManagedRoot,
}

impl Store {
    /// `create == false` returns `None` when the site has no directory yet.
    pub fn open(state: &ManagedRoot, site_id: &str, create: bool) -> io::Result<Option<Self>> {
        let base = rel(ROOT_DIR);
        let site = rel(format!("{ROOT_DIR}/{site_id}"));
        if create {
            state.create_dir_all(&site)?;
            state.set_mode(&base, 0o700)?;
            state.set_mode(&site, 0o700)?;
        } else if !state.exists(&site) {
            return Ok(None);
        }
        Ok(Some(Self {
            dir: state.open_managed_dir(&site)?,
        }))
    }

    pub fn load_index(&self) -> io::Result<Index> {
        let path = rel(INDEX);
        if !self.dir.exists(&path) {
            return Ok(Index::default());
        }
        let text = self.dir.read_to_string(&path)?;
        let index: Index = serde_json::from_str(&text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "baseline index is corrupt"))?;
        if index.schema_version != SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "baseline index schema is unsupported",
            ));
        }
        Ok(index)
    }

    pub fn save_index(&self, index: &Index) -> io::Result<()> {
        let mut index = index.clone();
        index.schema_version = SCHEMA_VERSION;
        self.dir.write_atomic_private(
            &rel(INDEX),
            &serde_json::to_vec(&index).map_err(io::Error::other)?,
        )
    }

    pub fn load_generation(&self, generation: u32) -> io::Result<Generation> {
        let path = rel(gen_name(generation));
        let meta = self.dir.symlink_metadata(&path)?;
        if !meta.is_file() || meta.len() > MAX_GENERATION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "baseline generation is not a regular file within bounds",
            ));
        }
        let bytes = self.dir.read_bytes(&path)?;
        let loaded: Generation = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "baseline generation is corrupt")
        })?;
        if loaded.schema_version != SCHEMA_VERSION
            || loaded.generation != generation
            || loaded.algorithm != super::ALGORITHM
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "baseline generation is unsupported",
            ));
        }
        Ok(loaded)
    }

    pub fn save_generation(&self, generation: &Generation) -> io::Result<()> {
        self.dir.write_atomic_private(
            &rel(gen_name(generation.generation)),
            &serde_json::to_vec(generation).map_err(io::Error::other)?,
        )
    }

    pub fn remove_generation(&self, generation: u32) {
        let _ = self.dir.remove_file(&rel(gen_name(generation)));
    }

    /// Removes leftovers of an interrupted write: temporary files and
    /// generation files the index does not name.
    pub fn sweep(&self, index: &Index) {
        let Ok(names) = self.dir.file_names() else {
            return;
        };
        for name in names {
            let stray = name.ends_with(".tmp")
                || name
                    .strip_prefix("gen-")
                    .and_then(|rest| rest.strip_suffix(".json"))
                    .and_then(|number| number.parse::<u32>().ok())
                    .is_some_and(|number| !index.generations.contains(&number));
            if !stray {
                continue;
            }
            if let Ok(path) = SiteRelativePath::parse(&name) {
                let _ = self.dir.remove_file(&path);
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{fs, os::unix::fs::PermissionsExt};

    const SITE: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn state(path: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(path).unwrap()).unwrap()
    }

    fn sample(n: u32) -> Generation {
        let mut files = BTreeMap::new();
        files.insert("a.php".to_owned(), "00".repeat(32));
        Generation {
            schema_version: SCHEMA_VERSION,
            site_id: SITE.into(),
            subsite: None,
            kind: "wordpress".into(),
            root: "/var/www/x".into(),
            generation: n,
            created_at_unix_secs: 1,
            algorithm: "sha256".into(),
            scope: "s".into(),
            limits: LimitsRecord {
                max_files: 1,
                max_bytes: 1,
                timeout_secs: 1,
            },
            file_count: 1,
            bytes_read: 1,
            complete: true,
            incomplete_reason: None,
            incomplete_path: None,
            digest: digest(&files),
            files: files.into_iter().collect(),
        }
    }

    #[test]
    fn creates_private_dirs_and_files_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        assert!(Store::open(&state, SITE, false).unwrap().is_none());
        let store = Store::open(&state, SITE, true).unwrap().unwrap();
        store.save_generation(&sample(1)).unwrap();
        store
            .save_index(&Index {
                next_generation: 2,
                candidate: Some(1),
                generations: vec![1],
                ..Index::default()
            })
            .unwrap();
        let mode = |p: &str| {
            fs::metadata(dir.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("security-baselines"), 0o700);
        assert_eq!(mode(&format!("security-baselines/{SITE}")), 0o700);
        assert_eq!(
            mode(&format!("security-baselines/{SITE}/gen-000001.json")),
            0o600
        );
        assert_eq!(
            mode(&format!("security-baselines/{SITE}/index.json")),
            0o600
        );
        assert_eq!(store.load_generation(1).unwrap(), sample(1));
        assert_eq!(store.load_index().unwrap().candidate, Some(1));
    }

    #[test]
    fn sweep_removes_unreferenced_generations_and_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let store = Store::open(&state, SITE, true).unwrap().unwrap();
        store.save_generation(&sample(1)).unwrap();
        store.save_generation(&sample(2)).unwrap();
        let site_dir = dir.path().join(format!("security-baselines/{SITE}"));
        fs::write(site_dir.join("gen-000003.json.tmp"), "partial").unwrap();
        store.sweep(&Index {
            generations: vec![1],
            ..Index::default()
        });
        assert!(site_dir.join("gen-000001.json").exists());
        assert!(!site_dir.join("gen-000002.json").exists());
        assert!(!site_dir.join("gen-000003.json.tmp").exists());
    }

    #[test]
    fn corrupt_index_and_generation_are_errors_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let store = Store::open(&state, SITE, true).unwrap().unwrap();
        let site_dir = dir.path().join(format!("security-baselines/{SITE}"));
        fs::write(site_dir.join("index.json"), "{").unwrap();
        assert!(store.load_index().is_err());
        fs::write(site_dir.join("gen-000001.json"), "{").unwrap();
        assert!(store.load_generation(1).is_err());
    }
}
