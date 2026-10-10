//! `site.list`: the sites on this server, read-only.
//!
//! The engine's own enrolment manifests (`<sites dir>/<siteId>.json`) come
//! first. Sites without a manifest but with a plain domain-named directory
//! under the sites root (`/var/www`) are added with no site id. Nothing is
//! written, no lock is taken, and nothing a manifest says beyond the five
//! fields below (repository URL, credential id) leaves this module.
//!
//! A manifest is trusted the way every deploy trusts it: owned by the
//! required user, not writable by group or others, named after its own site
//! id, with a valid domain. Anything else is skipped, not reported, so one
//! damaged file cannot hide the other sites.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::site::{Domain, SiteId};

pub const OPERATION: &str = "site.list";
/// Where the engine keeps its site manifests.
pub const SITES_DIR: &str = "/etc/operations-engine/sites";
/// Where site directories live by default.
pub const SITES_ROOT: &str = "/var/www";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SITES: usize = 10_000;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteEntry {
    pub site_id: Option<String>,
    pub domain: String,
    pub site_user: Option<String>,
    /// As the manifest records it (relative to the content root), or the
    /// directory for a site found only on disk.
    pub content_root: Option<String>,
    /// `manifest` or `filesystem`.
    pub source: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResult {
    pub sites: Vec<SiteEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFields {
    site_id: String,
    domain: String,
    content_root: String,
    site_user: String,
}

fn read_manifest(path: &Path, required_uid: u32) -> Option<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_MANIFEST_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn manifest_entry(dir: &Path, file_name: &str, required_uid: u32) -> Option<SiteEntry> {
    let stem = file_name.strip_suffix(".json")?;
    let id = SiteId::parse(stem).ok()?;
    let text = read_manifest(&dir.join(file_name), required_uid)?;
    let fields: ManifestFields = serde_json::from_str(&text).ok()?;
    if SiteId::parse(&fields.site_id).ok()? != id {
        return None;
    }
    let domain = Domain::parse(&fields.domain).ok()?;
    Some(SiteEntry {
        site_id: Some(id.to_string()),
        domain: domain.as_str().to_owned(),
        site_user: Some(fields.site_user),
        content_root: Some(fields.content_root),
        source: "manifest",
    })
}

/// The sites, sorted by domain. A missing directory is an empty list.
pub fn list(manifest_dir: &Path, sites_root: &Path, required_uid: u32) -> Vec<SiteEntry> {
    let mut sites: BTreeMap<String, SiteEntry> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir(manifest_dir) {
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names.into_iter().take(MAX_SITES) {
            if let Some(entry) = manifest_entry(manifest_dir, &name, required_uid) {
                sites.entry(entry.domain.clone()).or_insert(entry);
            }
        }
    }
    if let Ok(entries) = fs::read_dir(sites_root) {
        for entry in entries.filter_map(Result::ok).take(MAX_SITES) {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // `file_type` does not follow a symlink, so a link is skipped.
            let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if !is_dir || !name.contains('.') || Domain::parse(&name).is_err() {
                continue;
            }
            sites.entry(name.clone()).or_insert_with(|| SiteEntry {
                site_id: None,
                domain: name.clone(),
                site_user: None,
                content_root: Some(sites_root.join(&name).to_string_lossy().into_owned()),
                source: "filesystem",
            });
        }
    }
    sites.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn manifest(id: &str, domain: &str) -> String {
        serde_json::json!({
            "schemaVersion": 1, "siteId": id, "domain": domain,
            "contentRoot": format!("sites/{id}/current"), "siteUser": "site1",
            "repository": {"url": "https://example.test/r.git", "allowedBranches": ["main"],
                           "credentialId": id}
        })
        .to_string()
    }

    fn write(dir: &Path, name: &str, text: &str, mode: u32) {
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn manifests_and_plain_directories_are_listed_sorted_by_domain() {
        let root = tempfile::tempdir().unwrap();
        let manifests = root.path().join("m");
        let www = root.path().join("www");
        fs::create_dir_all(&manifests).unwrap();
        fs::create_dir_all(www.join("b.example.com")).unwrap();
        fs::create_dir_all(www.join("a.example.com")).unwrap();
        fs::create_dir_all(www.join("html")).unwrap();
        fs::create_dir_all(www.join("Bad.Example.com")).unwrap();
        fs::write(www.join("file.example.com"), "x").unwrap();
        write(
            &manifests,
            &format!("{A}.json"),
            &manifest(A, "a.example.com"),
            0o644,
        );
        write(
            &manifests,
            &format!("{B}.json"),
            &manifest(B, "z.example.com"),
            0o600,
        );
        let sites = list(&manifests, &www, uid());
        let domains: Vec<_> = sites.iter().map(|s| s.domain.as_str()).collect();
        assert_eq!(domains, ["a.example.com", "b.example.com", "z.example.com"]);
        assert_eq!(sites[0].source, "manifest");
        assert_eq!(sites[0].site_id.as_deref(), Some(A));
        assert_eq!(sites[0].site_user.as_deref(), Some("site1"));
        assert_eq!(sites[1].source, "filesystem");
        assert_eq!(sites[1].site_id, None);
        let json = serde_json::to_value(&sites[0]).unwrap();
        assert_eq!(json["siteId"], A);
        assert!(json.get("repository").is_none());
    }

    #[test]
    fn untrusted_manifests_are_skipped() {
        let root = tempfile::tempdir().unwrap();
        let manifests = root.path();
        let www = root.path().join("none");
        write(
            manifests,
            &format!("{A}.json"),
            &manifest(A, "ok.example.com"),
            0o644,
        );
        write(
            manifests,
            &format!("{B}.json"),
            &manifest(B, "w.example.com"),
            0o666,
        );
        let c = "33333333-3333-4333-8333-333333333333";
        write(
            manifests,
            &format!("{c}.json"),
            &manifest(A, "mismatch.example.com"),
            0o644,
        );
        let d = "44444444-4444-4444-8444-444444444444";
        write(
            manifests,
            &format!("{d}.json"),
            &manifest(d, "Bad_Domain"),
            0o644,
        );
        write(
            manifests,
            "not-a-uuid.json",
            &manifest(A, "x.example.com"),
            0o644,
        );
        write(manifests, "broken.json", "{", 0o644);
        let sites = list(manifests, &www, uid());
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].domain, "ok.example.com");
        assert!(list(manifests, &www, uid() + 1).is_empty());
    }

    #[test]
    fn a_symlinked_manifest_and_a_symlinked_directory_are_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let manifests = root.path().join("m");
        let www = root.path().join("www");
        fs::create_dir_all(&manifests).unwrap();
        fs::create_dir_all(&www).unwrap();
        write(
            root.path(),
            "real.json",
            &manifest(A, "a.example.com"),
            0o644,
        );
        std::os::unix::fs::symlink(
            root.path().join("real.json"),
            manifests.join(format!("{A}.json")),
        )
        .unwrap();
        let target = root.path().join("target");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, www.join("link.example.com")).unwrap();
        assert!(list(&manifests, &www, uid()).is_empty());
    }

    #[test]
    fn a_manifest_wins_over_a_directory_of_the_same_domain() {
        let root = tempfile::tempdir().unwrap();
        let manifests = root.path().join("m");
        let www = root.path().join("www");
        fs::create_dir_all(&manifests).unwrap();
        fs::create_dir_all(www.join("a.example.com")).unwrap();
        write(
            &manifests,
            &format!("{A}.json"),
            &manifest(A, "a.example.com"),
            0o644,
        );
        let sites = list(&manifests, &www, uid());
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].source, "manifest");
    }

    #[test]
    fn missing_directories_give_an_empty_list() {
        let root = tempfile::tempdir().unwrap();
        assert!(list(&root.path().join("a"), &root.path().join("b"), uid()).is_empty());
    }
}
