pub mod capabilities;
pub mod doctor;
pub mod engine;
pub mod ingress;
pub mod runtime_config;
pub mod site;
pub mod version;

use crate::ingress::MAX_CONTENT_BYTES;

/// Why `--content-file` could not be turned into submittable content.
/// Deliberately coarse: the caller is told "unreadable" for a missing file,
/// a FIFO, a directory, a device node, and a permission error alike,
/// because which one it was is a property of the host's filesystem rather
/// than of the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentFileError {
    Unreadable,
    TooLarge,
}

/// Reads a caller-submitted host path defensively — the only field in this
/// engine's whole request surface that names an arbitrary host path
/// (`--content-file`, on both `ingress.activateConfig` and
/// `runtime.activateConfig`); everything else selects a root-owned
/// manifest or a site-relative path resolved through a trusted root
/// (`docs/site-model.md`). Shared here (rather than duplicated per
/// operation) since neither the FIFO/device-node defenses below nor the
/// size bound are specific to either operation's own request shape.
///
/// - the path must name a **regular file**. A FIFO would otherwise block
///   this root process in `read` until something on the other end wrote or
///   closed it — indefinitely; a directory or a device node (`/dev/zero`,
///   `/dev/urandom`) would be read as content.
/// - the read is **bounded at `MAX_CONTENT_BYTES + 1`**. The extra byte is
///   what distinguishes "exactly at the bound" from "over it" without ever
///   holding more than 256 KiB + 1 in memory. Each operation's own
///   `*Request::parse` enforces the same bound again, but it can only do
///   so *after* the read; an unbounded read of `/dev/zero` never reaches
///   it.
///
/// The metadata check races with the open in principle. It is done through
/// the already-open handle (`File::metadata`, i.e. `fstat` on this
/// descriptor) rather than on the path, so what is checked is exactly what
/// is read — a path swapped after the open cannot change the verdict.
///
/// The open itself is `O_NONBLOCK` (`OpenOptionsExt::custom_flags`), which
/// is the part that actually keeps a FIFO from blocking this root process:
/// a blocking `open()` of a FIFO's read end waits for a writer to show up
/// *before returning at all*, so the regular-file check below would never
/// even run. `O_NONBLOCK` has no effect on a regular file's `read`, so the
/// flag is dropped once the type check passes; nothing downstream needs to
/// know it was ever set.
///
/// What this deliberately still does *not* do is require the path to
/// resolve under a trusted root — see `ingress::commands`'s original doc
/// comment for this function (before the hoist) for why: it needs a
/// configured staging root, hence a config-schema bump and a coordinated
/// client change, recorded as a follow-up in `docs/site-model.md` rather
/// than done under this fix.
pub(crate) fn read_content_file(path: &std::path::Path) -> Result<String, ContentFileError> {
    use std::io::Read as _;

    let file = open_content_file(path).map_err(|_| ContentFileError::Unreadable)?;
    let metadata = file.metadata().map_err(|_| ContentFileError::Unreadable)?;
    if !metadata.is_file() {
        return Err(ContentFileError::Unreadable);
    }

    let mut content = String::new();
    let read = file
        .take(MAX_CONTENT_BYTES as u64 + 1)
        .read_to_string(&mut content)
        .map_err(|_| ContentFileError::Unreadable)?;
    if read > MAX_CONTENT_BYTES {
        return Err(ContentFileError::TooLarge);
    }
    Ok(content)
}

/// Opens `path` non-blocking, so a FIFO's read end returns immediately
/// instead of waiting for a writer — see `read_content_file`'s doc comment.
/// `O_NONBLOCK` is Unix-specific; every caller of `read_content_file` is
/// already rejected before reaching it on any other platform (each
/// operation's own `#[cfg(not(unix))]` arm), so a plain blocking open is
/// fine here too.
#[cfg(unix)]
fn open_content_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_content_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The single failure message every command emits when
/// `EngineConfig::load_root_owned` fails, for *any* reason — stale
/// `schemaVersion`, unparseable JSON, a config file not owned by root, or
/// one that is group/world-writable. Collapsing all four to one generic
/// `INTERNAL` message is deliberate: which of them it was is a property of
/// the host's private configuration, not something a remote caller is
/// entitled to learn.
///
/// **This exact text is a cross-repo contract, not an implementation
/// detail.** The `website-control-panel` client keys its engine-config
/// self-heal off this literal string: on seeing `INTERNAL` +
/// `"engine configuration is unavailable"` it rewrites the host's
/// `/etc/operations-engine/config.json` to the current schema and retries,
/// which is what turns a stale-schema config from an outage into a
/// self-repairing hiccup. Because the message is deliberately generic
/// there is no machine-readable discriminator behind it, so the string
/// *is* the interface.
///
/// Rewording it — even harmlessly, even to something clearer — silently
/// degrades that client back to the outage the self-heal was built to fix.
/// Nothing in this repo would fail. `commands::tests::
/// the_config_unavailable_message_is_a_pinned_cross_repo_contract` is what
/// fails instead, on purpose. If this text ever genuinely has to change,
/// the client's detection has to change first and ship first.
pub const CONFIG_UNAVAILABLE_MESSAGE: &str = "engine configuration is unavailable";

#[cfg(test)]
mod tests {
    use super::{
        CONFIG_UNAVAILABLE_MESSAGE, ContentFileError, MAX_CONTENT_BYTES, read_content_file,
    };

    /// Pins the literal, spelled out rather than compared to the constant,
    /// so editing the constant cannot silently edit its own test too.
    #[test]
    fn the_config_unavailable_message_is_a_pinned_cross_repo_contract() {
        assert_eq!(
            CONFIG_UNAVAILABLE_MESSAGE, "engine configuration is unavailable",
            "website-control-panel's engine-config self-heal matches this \
             exact string; changing it here degrades that client silently. \
             See CONFIG_UNAVAILABLE_MESSAGE's doc comment."
        );
    }

    #[test]
    fn a_regular_file_at_or_under_the_bound_is_read_verbatim() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("route.caddyfile");

        std::fs::write(&path, "example.com {\n}\n").expect("content should be written");
        assert_eq!(
            read_content_file(&path).expect("a small regular file should be read"),
            "example.com {\n}\n"
        );

        // Exactly at the bound is accepted, matching each operation's own
        // `*Request::parse` boundary: the +1 byte the read takes exists to
        // detect "over", not to reject "at".
        std::fs::write(&path, "x".repeat(MAX_CONTENT_BYTES)).expect("content should be written");
        assert_eq!(
            read_content_file(&path)
                .expect("content at exactly the bound should be read")
                .len(),
            MAX_CONTENT_BYTES
        );
    }

    /// The bound is enforced *during* the read, so one byte over is
    /// reported as too large rather than being read in full and rejected
    /// afterward.
    #[test]
    fn one_byte_over_the_bound_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("route.caddyfile");
        std::fs::write(&path, "x".repeat(MAX_CONTENT_BYTES + 1))
            .expect("content should be written");

        assert_eq!(read_content_file(&path), Err(ContentFileError::TooLarge));
    }

    #[test]
    fn a_missing_path_and_a_directory_are_both_unreadable() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");

        assert_eq!(
            read_content_file(&directory.path().join("absent.caddyfile")),
            Err(ContentFileError::Unreadable)
        );
        // A directory opens successfully on Unix; only the regular-file
        // check rejects it.
        assert_eq!(
            read_content_file(directory.path()),
            Err(ContentFileError::Unreadable)
        );
    }

    /// The two host paths a root process must never be pointed at by a
    /// remote caller: an endless character device (an unbounded read that
    /// never returns EOF) and a FIFO with no writer (a read that blocks
    /// forever). Both are rejected on the regular-file check, before a
    /// single byte is read — which is why this test can afford to name
    /// `/dev/zero` at all.
    #[cfg(unix)]
    #[test]
    fn an_endless_device_and_a_fifo_are_rejected_without_being_read() {
        let zero = std::path::Path::new("/dev/zero");
        if zero.exists() {
            assert_eq!(
                read_content_file(zero),
                Err(ContentFileError::Unreadable),
                "/dev/zero must be rejected as a non-regular file, not read"
            );
        }

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let fifo = directory.path().join("route.caddyfile");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if made {
            // No writer is ever opened. A blocking `open()` of this FIFO's
            // read end would hang right here, before a single byte is read
            // or the regular-file check runs at all — proving the open
            // itself must be non-blocking, not just the read.
            assert_eq!(read_content_file(&fifo), Err(ContentFileError::Unreadable));
        }
    }
}
