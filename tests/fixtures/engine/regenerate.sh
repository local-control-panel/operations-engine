#!/bin/sh
# Regenerates every fixture in this directory: one stand-in "engine binary"
# per (version, target triple), the SHA256SUMS manifest listing all of them,
# and the minisign signature over that manifest.
#
# The stand-ins are shell scripts, not real binaries, because
# `install::execute` now smoke-tests a staged binary by running
# `<staged> version` through the bounded process runner before activating it
# (and `engine install` on an unmanaged host probes the binary it is about to
# replace the same way). A fixture therefore has to *run* and print a
# parseable version envelope, not just hash correctly. Each one carries its
# own version and target triple in both its output and its comment, so a test
# asserting on installed bytes can tell the versions — and the architectures —
# apart.
#
# Signing needs `tests/fixtures/engine/minisign.key`, which is deliberately
# not committed (`.gitignore`), and its password
# (test-only-do-not-use-in-production, the same publicly-known password as
# `release/minisign.key` - see `src/engine/verify.rs`). This keypair is
# dedicated to signing test fixtures only - deliberately never
# `release/minisign.key`, the one that (eventually) signs real releases, so
# regenerating fixtures never needs, and can never accidentally use,
# whatever secret currently signs real releases. If this key file is ever
# lost, regenerate it with:
#
#   minisign -G -f -s tests/fixtures/engine/minisign.key \
#     -p tests/fixtures/engine/minisign.pub
#
# and update `tests/engine.rs`'s `TEST_FIXTURE_PUBLIC_KEY` reference (it
# `include_str!`s the `.pub` file directly, so nothing else needs updating).
# Run from the repository root:
#
#   sh tests/fixtures/engine/regenerate.sh
set -eu

cd "$(dirname "$0")"

VERSIONS="9.9.7 9.9.8 9.9.9"
TRIPLES="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"

# Two deliberately defective releases, published and correctly signed like
# any other, for the tests that assert an install is rejected *after*
# verification succeeds: 9.9.6 is not a runnable program at all (no
# shebang, so execve returns ENOEXEC), and 9.9.5 runs but reports a
# version other than the one it was published as.
BROKEN_VERSION="9.9.6"
MISREPORTING_VERSION="9.9.5"
MISREPORTED_AS="1.2.3"

rm -f ops-engine-* SHA256SUMS SHA256SUMS.minisig

write_stand_in() {
  version="$1"
  triple="$2"
  reported="$3"
  architecture="${triple%%-*}"
  cat > "ops-engine-${version}-${triple}" <<EOF
#!/bin/sh
# Pretend ops-engine ${version} for ${triple} — a tests/fixtures/engine
# stand-in, not a real build. Answers only the one subcommand
# engine::smoke::probe_version invokes.
[ "\$1" = "version" ] || exit 64
printf '%s\n' '{"protocolVersion":1,"operation":"version","ok":true,"result":{"engineVersion":"${reported}","protocolVersion":1,"build":{"targetOs":"linux","targetArchitecture":"${architecture}","gitCommit":null}},"warnings":[],"error":null}'
EOF
  chmod +x "ops-engine-${version}-${triple}"
}

for triple in $TRIPLES; do
  for version in $VERSIONS; do
    write_stand_in "$version" "$triple" "$version"
  done
  write_stand_in "$MISREPORTING_VERSION" "$triple" "$MISREPORTED_AS"
  printf 'not a program at all, just bytes for %s\n' \
    "ops-engine-${BROKEN_VERSION}-${triple}" > "ops-engine-${BROKEN_VERSION}-${triple}"
  chmod +x "ops-engine-${BROKEN_VERSION}-${triple}"
done

if command -v sha256sum > /dev/null 2>&1; then
  sha256sum ops-engine-* > SHA256SUMS
else
  # macOS: shasum prints the same "<hex>  <name>" shape sha256sum does.
  shasum -a 256 ops-engine-* > SHA256SUMS
fi

printf '%s\n' "test-only-do-not-use-in-production" \
  | minisign -S -s minisign.key -m SHA256SUMS

echo "Regenerated $(wc -l < SHA256SUMS | tr -d ' ') fixture binaries, SHA256SUMS, and SHA256SUMS.minisig"
