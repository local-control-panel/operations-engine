# Cutting a release

1. Update `docs/compatibility.md` if this release changes protocol
   compatibility.
2. Tag the commit: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` builds `x86_64-unknown-linux-gnu` and
   `aarch64-unknown-linux-gnu` binaries natively (no cross-compilation),
   computes `SHA256SUMS`, signs it with the repository's minisign key,
   and publishes a GitHub Release with all four files attached.
4. Verify a downloaded artifact by hand before trusting the automation:

   ```console
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/SHA256SUMS
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/SHA256SUMS.minisig
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/ops-engine-X.Y.Z-x86_64-unknown-linux-gnu
   minisign -V -p release/minisign.pub -m SHA256SUMS
   sha256sum -c SHA256SUMS --ignore-missing
   ```

## Reproducibility

Builds use `cargo build --release --locked` against the exact toolchain
pinned in `rust-toolchain.toml`, with `SOURCE_DATE_EPOCH` set from the
tagged commit's timestamp. This is not bit-for-bit `diffoscope`-verified
reproducibility — see the design spec
(`docs/superpowers/specs/2026-09-03-release-pipeline-design.md`) for why
that level was deliberately out of scope.

## Signing key

The release signing keypair was generated once via `minisign -G`. Only
`release/minisign.pub` is committed; the secret half lives exclusively
in this repository's `MINISIGN_SECRET_KEY`/`MINISIGN_KEY_PASSWORD`
GitHub Actions secrets. Rotating it means generating a new keypair,
updating both secrets, and updating the committed `release/minisign.pub`
in the same change that cuts the first release signed with the new key
— older `ops-engine` builds with the old key compiled in will not be
able to verify releases signed with a rotated key, so a key rotation is
itself a compatibility event worth a `docs/compatibility.md` entry.

As of this writing, `release/minisign.pub` is a TEST-ONLY key (see the comment in `src/engine/verify.rs`) — a real production keypair must be generated and rotated in, with both halves updated (the committed public key and the `MINISIGN_SECRET_KEY`/`MINISIGN_KEY_PASSWORD` GitHub Actions secrets), before cutting the first real release.
