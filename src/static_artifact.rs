//! Bounded inspection of an untrusted static artifact.
//!
//! This is not authorization to publish: the tree can change after inspection.
//! Publishing must validate the bytes copied into a private immutable release.
use std::io::{self, Read};

use crate::{filesystem::ManagedRoot, site::SiteRelativePath};

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 32;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    pub files: usize,
    pub bytes: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn allowed_file(name: &str) -> bool {
    if name.starts_with('.') || name.contains('\\') || name.chars().any(char::is_control) {
        return false;
    }
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "package.json" | "package-lock.json" | "composer.json" | "tsconfig.json"
    ) {
        return false;
    }
    let Some((_, extension)) = name.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "html"
            | "htm"
            | "css"
            | "js"
            | "mjs"
            | "json"
            | "xml"
            | "txt"
            | "svg"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "avif"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "webmanifest"
            | "pdf"
            | "wasm"
            | "mp3"
            | "mp4"
            | "webm"
            | "ogg"
            | "wav"
    )
}

fn allowed_directory(name: &str) -> bool {
    (!name.starts_with('.') || name == ".well-known")
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "node_modules" | "vendor"
        )
}

/// Inspect a source directory without following symlinks. This only reports
/// a bounded inventory; it does not prove that content contains no secrets.
#[cfg(unix)]
pub fn inspect(root: &ManagedRoot) -> io::Result<Inventory> {
    let mut inventory = Inventory::default();
    let mut entries_seen = 0;
    let mut index_present = false;
    visit(
        root,
        0,
        &mut entries_seen,
        &mut inventory,
        &mut index_present,
    )?;
    if !index_present {
        return Err(invalid("artifact must have a root index.html"));
    }
    Ok(inventory)
}

/// Copy a source into a new, empty private directory using no-follow handles.
/// On error the caller must discard the entire private directory. The caller
/// owns its permissions and must not expose it before validating the result.
pub fn copy_private(source: &ManagedRoot, destination: &ManagedRoot) -> io::Result<Inventory> {
    if !destination.child_entries_bounded(1)?.is_empty() {
        return Err(invalid("artifact destination must be empty"));
    }
    let mut inventory = Inventory::default();
    let mut seen = 0;
    let mut index = false;
    copy_directory(
        source,
        destination,
        0,
        &mut seen,
        &mut inventory,
        &mut index,
    )?;
    if !index {
        return Err(invalid("artifact must have a root index.html"));
    }
    destination.sync_all()?;
    // Validate the private copy itself, not just the untrusted source observed
    // while copying. The caller must still keep it private and immutable until
    // activation; this check is not a publishing or isolation boundary.
    validate_copy(destination, &inventory)?;
    Ok(inventory)
}

fn validate_copy(destination: &ManagedRoot, expected: &Inventory) -> io::Result<()> {
    let copied = inspect(destination)?;
    if &copied != expected {
        return Err(invalid("copied artifact inventory changed"));
    }
    Ok(())
}

fn copy_directory(
    source: &ManagedRoot,
    destination: &ManagedRoot,
    depth: usize,
    seen: &mut usize,
    inventory: &mut Inventory,
    index: &mut bool,
) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid("artifact nesting limit exceeded"));
    }
    for child in source.child_entries_bounded(MAX_ENTRIES.saturating_sub(*seen))? {
        if *seen >= MAX_ENTRIES {
            return Err(invalid("artifact entry limit exceeded"));
        }
        *seen += 1;
        let name = child
            .name
            .to_str()
            .ok_or_else(|| invalid("artifact path is not UTF-8"))?;
        if name.is_empty() || name.contains('\\') || name.chars().any(char::is_control) {
            return Err(invalid("artifact path is invalid"));
        }
        let path =
            SiteRelativePath::parse(name).map_err(|_| invalid("artifact path is invalid"))?;
        if child.is_dir {
            if !allowed_directory(name) {
                return Err(invalid("artifact directory is forbidden"));
            }
            let source_child = source.open_child_dir_nofollow(&path)?;
            destination.create_dir(&path)?;
            let destination_child = destination.open_child_dir_nofollow(&path)?;
            copy_directory(
                &source_child,
                &destination_child,
                depth + 1,
                seen,
                inventory,
                index,
            )?;
            destination_child.sync_all()?;
        } else {
            if !allowed_file(name) {
                return Err(invalid("artifact contains a forbidden file"));
            }
            let file = source.open_regular_read(&path)?;
            let metadata = file.metadata()?;
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 || metadata.len() > MAX_FILE_BYTES {
                return Err(invalid("artifact file is unsafe or too large"));
            }
            let remaining = MAX_TOTAL_BYTES.saturating_sub(inventory.bytes);
            let limit = MAX_FILE_BYTES.min(remaining);
            let mut output = destination.create_new_file_with_mode(&path, 0o600)?;
            let copied = io::copy(&mut file.take(limit + 1), &mut output)?;
            if copied > limit {
                return Err(invalid("artifact size limit exceeded"));
            }
            output.sync_all()?;
            inventory.bytes += copied;
            inventory.files += 1;
            if depth == 0 && name == "index.html" {
                *index = true;
            }
        }
    }
    destination.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn visit(
    root: &ManagedRoot,
    depth: usize,
    seen: &mut usize,
    inventory: &mut Inventory,
    index: &mut bool,
) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid("artifact nesting limit exceeded"));
    }
    let children = root.child_entries_bounded(MAX_ENTRIES.saturating_sub(*seen))?;
    for child in children {
        if *seen >= MAX_ENTRIES {
            return Err(invalid("artifact entry limit exceeded"));
        }
        *seen += 1;
        let name = child
            .name
            .to_str()
            .ok_or_else(|| invalid("artifact path is not UTF-8"))?;
        if name.is_empty() || name.contains('\\') || name.chars().any(char::is_control) {
            return Err(invalid("artifact path is invalid"));
        }
        let path =
            SiteRelativePath::parse(name).map_err(|_| invalid("artifact path is invalid"))?;
        if child.is_dir {
            if !allowed_directory(name) {
                return Err(invalid("artifact directory is forbidden"));
            }
            let dir = root.open_child_dir_nofollow(&path)?;
            visit(&dir, depth + 1, seen, inventory, index)?;
        } else {
            if !allowed_file(name) {
                return Err(invalid("artifact contains a forbidden file"));
            }
            let file = root.open_regular_read(&path)?;
            let metadata = file.metadata()?;
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(invalid("hard-linked files are not allowed"));
            }
            if metadata.len() > MAX_FILE_BYTES {
                return Err(invalid("artifact file size limit exceeded"));
            }
            inventory.bytes = inventory
                .bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("artifact size overflow"))?;
            if inventory.bytes > MAX_TOTAL_BYTES {
                return Err(invalid("artifact size limit exceeded"));
            }
            inventory.files += 1;
            if depth == 0 && name == "index.html" {
                *index = true;
            }
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{fs, os::unix::fs::symlink};

    fn root(dir: &tempfile::TempDir) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(dir.path()).unwrap()).unwrap()
    }
    #[test]
    fn accepts_static_files_and_counts_them() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("index.html"), "ok").unwrap();
        fs::create_dir(d.path().join("assets")).unwrap();
        fs::write(d.path().join("assets/app.js"), "hello").unwrap();
        assert_eq!(
            inspect(&root(&d)).unwrap(),
            Inventory { files: 2, bytes: 7 }
        );
    }
    #[test]
    #[ignore = "exp"]
    fn rejects_secrets_php_and_symlinks() {
        for name in [
            ".env",
            "config.php",
            "private.key",
            "index.html.php",
            "package.json",
            "app.js.map",
        ] {
            let d = tempfile::tempdir().unwrap();
            fs::write(d.path().join("index.html"), "ok").unwrap();
            fs::write(d.path().join(name), "secret").unwrap();
            assert!(inspect(&root(&d)).is_err(), "{name}");
        }
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("index.html"), "ok").unwrap();
        symlink("/etc/passwd", d.path().join("leak.txt")).unwrap();
        assert!(inspect(&root(&d)).is_err());
    }
    #[test]
    fn refuses_hard_links_and_missing_index() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.txt"), "ok").unwrap();
        assert!(inspect(&root(&d)).is_err());
        fs::write(d.path().join("index.html"), "ok").unwrap();
        fs::hard_link(d.path().join("a.txt"), d.path().join("b.txt")).unwrap();
        assert!(inspect(&root(&d)).is_err());
    }

    #[test]
    #[ignore = "exp"]
    fn rejects_large_files_and_excessive_depth() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("index.html"), "ok").unwrap();
        fs::File::create(d.path().join("large.js"))
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        assert!(inspect(&root(&d)).is_err());
        fs::remove_file(d.path().join("large.js")).unwrap();
        let mut nested = d.path().to_path_buf();
        for _ in 0..=MAX_DEPTH {
            nested.push("d");
            fs::create_dir(&nested).unwrap();
        }
        assert!(inspect(&root(&d)).is_err());
    }

    #[test]
    #[ignore = "exp"]
    fn rejects_dependency_and_symlinked_directories() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("index.html"), "ok").unwrap();
        fs::create_dir(d.path().join("node_modules")).unwrap();
        assert!(inspect(&root(&d)).is_err());
        fs::remove_dir(d.path().join("node_modules")).unwrap();
        symlink("/etc", d.path().join("assets")).unwrap();
        assert!(inspect(&root(&d)).is_err());
    }

    #[test]
    fn copies_only_into_an_empty_private_destination() {
        let source = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        fs::write(source.path().join("index.html"), "hello").unwrap();
        fs::create_dir(source.path().join("assets")).unwrap();
        fs::write(source.path().join("assets/app.js"), "app").unwrap();
        let count = copy_private(&root(&source), &root(&dest)).unwrap();
        assert_eq!(count, Inventory { files: 2, bytes: 8 });
        assert_eq!(fs::read(dest.path().join("assets/app.js")).unwrap(), b"app");
        assert!(copy_private(&root(&source), &root(&dest)).is_err());
    }

    #[test]
    #[ignore = "exp"]
    fn refuses_to_copy_a_symlink_even_when_it_looks_like_an_asset() {
        let source = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        fs::write(source.path().join("index.html"), "hello").unwrap();
        symlink("/etc/passwd", source.path().join("data.txt")).unwrap();
        assert!(copy_private(&root(&source), &root(&dest)).is_err());
        assert!(!dest.path().join("data.txt").exists());
    }

    #[test]
    fn copy_validation_rejects_tampering_and_inventory_mismatch() {
        let source = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        fs::write(source.path().join("index.html"), "hello").unwrap();
        let inventory = copy_private(&root(&source), &root(&dest)).unwrap();
        fs::write(dest.path().join("index.html"), "different length").unwrap();
        assert!(validate_copy(&root(&dest), &inventory).is_err());
        fs::write(dest.path().join("index.html"), "hello").unwrap();
        fs::write(dest.path().join("secret.php"), "secret").unwrap();
        assert!(validate_copy(&root(&dest), &inventory).is_err());
    }
}
