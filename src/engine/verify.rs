//! Fetches and cryptographically verifies a release's `SHA256SUMS`
//! manifest before `install.rs` trusts any checksum out of it. minisign
//! signs the whole `SHA256SUMS` file, never a single extracted line — so
//! this module always fetches and verifies the complete file itself
//! rather than accepting a pre-extracted line and signature from a
//! caller, which would not be a verifiable unit on its own.

use minisign_verify::{PublicKey, Signature};

use crate::engine::{fetch, release};

/// Generated once via `minisign -G`; see `docs/release.md`. Only the
/// public half is ever committed (`release/minisign.pub`).
// TEST-ONLY key — password is test-only-do-not-use-in-production, publicly known. Must be rotated to a real, secret-held keypair before the first real release; see docs/superpowers/sdd/... ledger.
const PUBLIC_KEY_FILE: &str = include_str!("../../release/minisign.pub");

#[derive(Debug)]
pub enum Error {
    Fetch(fetch::Error),
    InvalidPublicKey,
    InvalidSignature,
    SignatureMismatch,
    NoLineForThisArchitecture,
    MalformedManifest,
}

/// One verified line of `SHA256SUMS`: the exact asset filename this
/// build's platform must request next, and the SHA-256 it must produce.
pub struct ExpectedArtifact {
    pub filename: String,
    pub sha256_hex: String,
}

pub fn fetch_and_verify(
    base_url: &str,
    version: &release::EngineVersion,
    target_triple: &str,
) -> Result<ExpectedArtifact, Error> {
    let manifest =
        fetch::fetch_bytes(&release::sha256sums_url(base_url, version)).map_err(Error::Fetch)?;
    let signature_bytes = fetch::fetch_bytes(&release::sha256sums_minisig_url(base_url, version))
        .map_err(Error::Fetch)?;
    let signature_text = String::from_utf8(signature_bytes).map_err(|_| Error::InvalidSignature)?;

    let public_key = public_key()?;
    let signature = Signature::decode(&signature_text).map_err(|_| Error::InvalidSignature)?;
    public_key
        .verify(&manifest, &signature, false)
        .map_err(|_| Error::SignatureMismatch)?;

    let manifest_text = String::from_utf8(manifest).map_err(|_| Error::MalformedManifest)?;
    let expected_name = release::binary_asset_name(version, target_triple);
    parse_sha256sums_line(&manifest_text, &expected_name).ok_or(Error::NoLineForThisArchitecture)
}

/// `PUBLIC_KEY_FILE` is the real two-line `minisign.pub` format: an
/// `untrusted comment:` line, then the base64 key on its own line.
fn public_key() -> Result<PublicKey, Error> {
    let key_line = PUBLIC_KEY_FILE
        .lines()
        .nth(1)
        .ok_or(Error::InvalidPublicKey)?;
    PublicKey::from_base64(key_line.trim()).map_err(|_| Error::InvalidPublicKey)
}

/// Parses the standard `sha256sum` output format: `<hex>  <filename>` (two
/// spaces, filename last), returning only the line matching
/// `expected_name` exactly. Any other line is ignored, not partially
/// trusted.
fn parse_sha256sums_line(manifest: &str, expected_name: &str) -> Option<ExpectedArtifact> {
    manifest.lines().find_map(|line| {
        let (hex, name) = line.split_once("  ")?;
        if name == expected_name
            && hex.len() == 64
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            Some(ExpectedArtifact {
                filename: name.to_owned(),
                sha256_hex: hex.to_lowercase(),
            })
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::{parse_sha256sums_line, public_key};

    #[test]
    fn the_committed_public_key_parses() {
        public_key().expect("release/minisign.pub should parse as a valid minisign public key");
    }

    #[test]
    fn parse_sha256sums_line_finds_only_the_matching_line() {
        let manifest = "\
abababababababababababababababababababababababababababababab  ops-engine-0.5.0-x86_64-unknown-linux-gnu
cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd  ops-engine-0.5.0-aarch64-unknown-linux-gnu
";
        let found = parse_sha256sums_line(manifest, "ops-engine-0.5.0-aarch64-unknown-linux-gnu")
            .expect("matching line should be found");
        assert_eq!(
            found.sha256_hex,
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        );
        assert_eq!(found.filename, "ops-engine-0.5.0-aarch64-unknown-linux-gnu");

        assert!(parse_sha256sums_line(manifest, "no-such-asset").is_none());
    }

    /// End-to-end against the *real* signing/verification pair: signs a
    /// throwaway manifest with the real secret key via the `minisign` CLI
    /// (requires `MINISIGN_TEST_KEY_PASSWORD` in the environment, matching
    /// the password chosen in Task 7 Step 2 — set it locally before
    /// running this test, and as a CI secret alongside the release
    /// signing secrets), then verifies it with this module's own
    /// `PublicKey`/`Signature` usage — proving the two sides actually
    /// agree on a real signature, not just that parsing doesn't panic.
    #[test]
    fn a_signature_from_the_real_minisign_cli_verifies() {
        let Ok(password) = std::env::var("MINISIGN_TEST_KEY_PASSWORD") else {
            eprintln!("skipping: MINISIGN_TEST_KEY_PASSWORD is not set");
            return;
        };
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let manifest_path = directory.path().join("SHA256SUMS");
        std::fs::write(&manifest_path, "test manifest content\n")
            .expect("manifest should be written");

        // The real minisign CLI has no env-var/flag way to supply the secret
        // key's password non-interactively; it only reads it from stdin.
        let mut child = Command::new("minisign")
            .args(["-S", "-s", "release/minisign.key", "-m"])
            .arg(&manifest_path)
            .stdin(Stdio::piped())
            .spawn()
            .expect("minisign CLI should run");
        child
            .stdin
            .take()
            .expect("child stdin should be piped")
            .write_all(format!("{password}\n").as_bytes())
            .expect("password should be written to minisign's stdin");
        let status = child.wait().expect("minisign CLI should exit");
        assert!(status.success(), "minisign signing should succeed");

        let manifest = std::fs::read(&manifest_path).expect("manifest should be readable");
        let signature_text = std::fs::read_to_string(manifest_path.with_extension("SUMS.minisig"))
            .or_else(|_| std::fs::read_to_string(format!("{}.minisig", manifest_path.display())))
            .expect("signature file should be readable");

        let public_key = public_key().expect("public key should parse");
        let signature =
            minisign_verify::Signature::decode(&signature_text).expect("signature should decode");
        public_key.verify(&manifest, &signature, false).expect(
            "a signature from the real secret key should verify against the committed public key",
        );
    }
}
