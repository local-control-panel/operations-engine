# Phase 7 — Release Pipeline Design

Status: approved (brainstorming), ready for implementation planning
Date: 2026-09-03
Scope: Operations Engine Phase 7 — "release and production hardening"
(`PLAN.md`, Current phase 7). Covers reproducible builds, checksums and
signing, pinned installation, atomic upgrade/downgrade with recovery,
compatibility matrix, log/redaction review, documentation, and opt-in
rollout. Touches both `operations-engine` (this repo) and
`website-control-panel` (the control plane).

## 1. Goal and constraints

Make installation, upgrade, downgrade, and recovery of the `ops-engine`
binary on managed servers safer than manual binary replacement, per
`PLAN.md` Phase 7's exit criteria:

- downloaded artifacts are verified before execution;
- failed upgrades retain a runnable previous binary;
- release provenance and compatibility can be audited;
- production rollout and rollback procedures have been exercised.

Constraints carried over from prior phases (do not relitigate):

- Linux-only production target; CLI-first, no persistent daemon;
- root-owned manifests, capability-based filesystem access beneath
  opened trusted roots (Phase 2);
- mutations go through `mutation::preflight` (lock, idempotency replay,
  persisted transaction state, audit) and a type-state
  `PreCommit`/`PostCommit` commit boundary (Phase 3);
- the daemonless sudo-gated privileged entry point, with subprocess
  children dropped to the site UID/GID where applicable (Phase 2/3);
- explicit, caller-supplied inputs — no ambient discovery, no
  operation advertised in `capabilities` before it is implemented and
  tested (working agreement items 4-5).

## 2. Decisions made during brainstorming

These were resolved with the user before design and are not open for
re-debate during implementation; if one turns out to be wrong, stop and
re-raise it rather than silently deviating:

1. **Reproducibility level**: `cargo build --locked` against a toolchain
   pinned to an exact version (not `channel = "stable"`) plus
   `SOURCE_DATE_EPOCH` for deterministic timestamps. Not full
   bit-for-bit `diffoscope` dual-build verification — that is
   disproportionate infrastructure for this project's current threat
   model.
2. **Single signing authority**: GitHub Actions is the only place that
   builds and signs production release artifacts. The
   `website-control-panel` local build script (`docker/test-server/build-ops-engine.sh`)
   stops building locally and instead downloads and verifies real,
   signed GitHub Releases — so it exercises the exact same trust path
   as production instead of a parallel one.
3. **Signing mechanism**: minisign (Ed25519, no OIDC/transparency-log
   infrastructure). Private key lives only in a GitHub Actions secret.
4. **Install command lives in `ops-engine` itself**: a new `engine`
   subcommand tree (`engine install`, `engine rollback`), invoked over
   the same sudo-gated privileged entry point as `site deploy` /
   `site rollback`. Not a separate companion installer binary — Linux
   lets a process safely replace its own on-disk file while running,
   so there is no self-replacement hazard to isolate a second binary
   against.
5. **Artifact transport**: the managed server (via `ops-engine engine
   install`) fetches the release asset directly from GitHub Releases
   over HTTPS. The control plane does not stage bytes over SFTP for
   this path; it only resolves and supplies the explicit, pinned
   version as a CLI argument. (Refined during spec self-review: the
   engine also fetches `SHA256SUMS`/`SHA256SUMS.minisig` itself rather
   than being handed a checksum/signature by the control plane — see
   §6. A minisign signature covers the whole `SHA256SUMS` file; a
   single extracted line and signature pair from the control plane
   would not be verifiable as a standalone unit, so the control plane
   cannot meaningfully supply one.)
6. **ARM64 builds**: native GitHub Actions ARM64 runners
   (`ubuntu-24.04-arm`), not cross-compilation. One job per
   architecture, both building natively.
7. **Downgrade**: `engine install --version <older>` is the general
   path (any previously published, signed version, fetched the same
   way as an upgrade). `engine rollback` is an additional, no-network
   fast path that swaps back to the one locally retained previous
   binary — for recovering from a bad upgrade without depending on
   GitHub being reachable at that moment.
8. **Retention depth**: exactly two binaries on disk — active and
   previous. Not an N-version history. The exit criterion asks for "a
   runnable previous binary" (singular); arbitrary-depth downgrades go
   through `engine install` against GitHub Releases, which already
   retains every published version.

## 3. Architecture overview

```
GH Actions (tag push vX.Y.Z)
  -> build ops-engine for x86_64-unknown-linux-gnu and
     aarch64-unknown-linux-gnu, each on its native runner
     (cargo build --release --locked, pinned toolchain, SOURCE_DATE_EPOCH)
  -> compute SHA256SUMS over both binaries
  -> minisign-sign SHA256SUMS -> SHA256SUMS.minisig
  -> publish GitHub Release: both binaries + SHA256SUMS + SHA256SUMS.minisig

website-control-panel (control plane)
  -> resolve the target version (explicit; from GitHub Releases API,
     never "latest") - this is the only thing it decides
  -> SSH, elevated: ops-engine engine install --version X.Y.Z

ops-engine (on the managed server, privileged path)
  -> HTTPS GET SHA256SUMS and SHA256SUMS.minisig for that release
     (URL built from a hardcoded GitHub repo + the given version,
     never a caller-supplied URL)
  -> verify SHA256SUMS.minisig against SHA256SUMS' full content, using
     a public key compiled into ops-engine itself
  -> extract the line matching this host's architecture (`uname -m`)
     to get the expected binary filename and SHA256
  -> HTTPS GET that specific binary asset
  -> verify its SHA256 against the value just extracted
  -> on success: atomically activate (same-directory write-temp-then-
     rename of /usr/local/bin/ops-engine's content — see §5), retain
     the previous binary; on any verification failure: no filesystem
     change, no partial state
```

The control plane never asserts trust on its own; it only decides
*which* version to request. `ops-engine` performs the actual
cryptographic verification — fetching the signed manifest itself
rather than trusting a value handed to it — on the machine that will
run the result, through the same privileged path already used for
`site deploy`/`site rollback`.

## 4. Build and reproducibility

- `rust-toolchain.toml` changes from `channel = "stable"` to a pinned
  `channel = "1.85.0"` (matches the existing `rust-version = "1.85"` in
  `Cargo.toml` and the CI `minimum-rust` job, so there is one
  authoritative version instead of two implicitly-hoped-to-match ones).
- New GitHub Actions workflow (or a new job set in `ci.yml` triggered
  on `v*` tags): a build matrix of
  `[x86_64-unknown-linux-gnu on ubuntu-latest, aarch64-unknown-linux-gnu on ubuntu-24.04-arm]`.
  Each job runs `cargo build --release --locked` with
  `SOURCE_DATE_EPOCH` set from the tagged commit's `git show -s --format=%ct`.
- Output binaries are named to include target triple and version, e.g.
  `ops-engine-X.Y.Z-x86_64-unknown-linux-gnu`, so a single release can
  hold both architectures unambiguously.
- A checksum job (depends on both build jobs) collects both binaries,
  writes `SHA256SUMS` (standard `sha256sum` output format, one line per
  binary), signs it with `minisign -S` using the private key from a
  repo secret, producing `SHA256SUMS.minisig`, and publishes a GitHub
  Release with all four files attached.
- The minisign **public** key is checked into this repo (e.g.
  `release/minisign.pub`) and compiled into the `ops-engine` binary as
  a constant — the verifier must not depend on fetching the public key
  from anywhere at verify time.

## 5. On-disk layout and atomic activation

```
/usr/local/bin/ops-engine                    (real file, root-owned, mode 0755 —
                                               the name every SSH invocation and
                                               the sudoers policy target; fixed by
                                               docs/site-model.md, not configurable)

<state root>/engine/                         (new subtree, parallel to sites/<siteId>/)
  versions/
    0.4.0/ops-engine        (retained copy, root-owned, mode 0755)
    0.5.0/ops-engine
  install.state              ({"active":"0.5.0","previous":"0.4.0"})
  locks/ transactions/ audit/
```

Revised during implementation planning from this section's original
symlink-based design: `/usr/local/bin` and the engine's state root are
different trusted roots, and `ManagedRoot::symlink`'s target is
deliberately typed as a same-root-relative path — there is no existing
primitive for a symlink crossing trusted roots, and adding one would be
a new, security-relevant capability this design does not otherwise
need. Activation instead writes the verified binary's bytes directly
into `/usr/local/bin/ops-engine` via a same-directory
write-temp-then-atomic-rename (the same commit-point discipline as the
site `current` symlink swap — still exactly one atomic `rename(2)`,
just of a regular file's content rather than a symlink target). There
is still never a window where `ops-engine` does not resolve to a valid,
fully-verified executable.

`install.state` is written with the existing `write_atomic` primitive
immediately after a successful activation rename. Cleanup after a
successful install removes the version that is no longer `active` or
`previous` (best-effort, same spirit as `deploy::cleanup::prune_old_releases`,
but capped at retaining exactly these two — not a configurable N).
`engine rollback` reads the retained previous version's bytes straight
out of `versions/<previous>/ops-engine` and writes them into
`/usr/local/bin/ops-engine` the same way — no symlink repointing, no
network call.

## 6. `engine install`

```
ops-engine engine install --version X.Y.Z
```

- Elevated only (same reasoning as `site deploy`/`site rollback`:
  writes under a root-owned trusted root).
- Runs through `mutation::preflight` with a dedicated operation name
  (e.g. `"engine.install"`) — same per-operation lock, idempotency-key
  replay, and persisted `TransactionState` machinery already built in
  Phase 3. Locking scope is engine-global (there is one `ops-engine`
  install per host), distinct from any per-site lock.
- Steps: build the release's asset base URL from a hardcoded repo
  constant + the given version → HTTPS GET `SHA256SUMS` and
  `SHA256SUMS.minisig` → verify the signature covers the full
  `SHA256SUMS` content, using the public key compiled into
  `ops-engine` → parse out the line matching this host's architecture
  (`uname -m`, mapped to the release's target-triple naming) to get the
  expected binary filename and its SHA256 → HTTPS GET that binary into
  a temp file under `versions/X.Y.Z/` (not yet at its final name) →
  hash it and compare to the value from the verified `SHA256SUMS` line
  → rename into place at `versions/X.Y.Z/ops-engine`, `chmod 0755`
  (retained copy) → write the same bytes into `/usr/local/bin/ops-engine`
  via a same-directory write-temp-then-rename (the actual activation
  commit point) → update `install.state` → best-effort prune of
  anything that is neither `active` nor `previous`.
- Any verification failure (missing/malformed `SHA256SUMS`, bad
  signature, no line for this architecture, checksum mismatch, HTTP
  error, already-installed version) leaves the filesystem untouched
  and returns a stable error code — new codes needed:
  `ARTIFACT_VERIFICATION_FAILED`, `ARTIFACT_FETCH_FAILED` (`INVALID_INPUT`
  already covers "requested version already active", no new code
  needed there).
- New dependencies: an HTTP client for the HTTPS GETs (blocking is
  fine, `ops-engine` has no async runtime today — pick the smallest
  synchronous client that supports HTTPS with a rustls or system TLS
  backend and follows redirects, since GitHub release assets are
  typically served via a redirect to a CDN) and an Ed25519 verifier
  compatible with minisign's signature format (either a
  minisign-specific crate or a general Ed25519 crate plus minisign's
  file-format parsing written directly, whichever is smaller — decide
  at implementation time, not in this spec).

## 7. `engine rollback`

```
ops-engine engine rollback
```

- Elevated, no network. Reads `install.state`; if there is no
  `previous`, fails closed with `INVALID_INPUT` ("no previous version
  to roll back to") rather than doing nothing silently.
- Same `mutation::preflight` machinery, operation name
  `"engine.rollback"`, same engine-global lock as `engine install` (the
  two must not race each other).
- Swaps `active`/`previous` in `install.state`, reads the retained
  previous version's bytes from `versions/<previous>/ops-engine`, and
  writes them into `/usr/local/bin/ops-engine` via the same
  write-temp-then-rename activation `engine install` uses. No
  re-verification against a signature is needed — the previous binary
  was already verified when it was installed and has sat unmodified on
  a root-owned path since.

## 8. `capabilities` and protocol

- `engine.install` and `engine.rollback` are added to the advertised
  `operations` list only once implemented and tested end-to-end,
  consistent with working agreement item 4 — this spec does not
  pre-advertise them.
- No protocol version bump is required; these are new operations
  within protocol v1's existing envelope/error/warning shape, not a
  breaking change to it.

## 9. Control plane (`website-control-panel`) changes

- A small new module resolves which published version to request —
  e.g. listing GitHub Releases via the API for an operator to pick in
  the UI, or reading a version pinned in the compatibility matrix
  (§10). This is the only new outbound network dependency on this
  side, and it never touches checksums or signatures — that
  verification happens entirely on the managed server (§6).
- New Tauri commands `opsEngine:install` and `opsEngine:rollback`,
  structured like the existing `opsEngine:deploy`/`opsEngine:rollback`
  in `commands/ops_engine.rs`: call `ops_engine::invoke(["engine",
  "install"], ...)` / `(["engine", "rollback"], ...)` with `elevated:
  true`.
- After a successful install or rollback, the caller must invoke
  `CapabilityCache::invalidate(server_id)` — the existing cache
  comment already documents this rule ("call this whenever ... a
  different ... build may now be running there"); the new commands
  must actually do it, since today nothing changes the installed
  binary out from under a live connection.
- `docker/test-server/build-ops-engine.sh` is rewritten to download and
  verify a pinned GitHub Release (both the "old" and "new" fixture
  versions used by `ops_engine_deploy_rollback.rs`'s compatibility
  tests) instead of building inside `rust:1.85-slim`. Verification
  reuses the same checksum/signature logic conceptually as production
  (a small script-level check is enough here — this is a test fixture
  loader, not `ops-engine` itself, so it does not need to reimplement
  the Rust verifier).

## 10. Compatibility matrix

`docs/compatibility.md` (new, this repo): a table of engine version,
protocol version, and minimum control-plane version known to work with
it. Purely documentation — runtime compatibility enforcement already
exists via `MIN_PROTOCOL_VERSION`/`MAX_PROTOCOL_VERSION` negotiation on
the client side (`ops_engine::mod.rs`). Updated as part of cutting each
release, not automated in this phase.

## 11. Redaction and bounded-log review

An audit pass (not new infrastructure) over:

- existing log/error paths, confirmed still consistent with the
  Definition of Done's "logs and responses do not expose secrets";
- the new install/rollback paths specifically: version strings,
  checksums, and signatures are safe to log; local filesystem paths
  outside the trusted root, and the raw HTTP response body on a failed
  fetch, are not (avoid echoing unbounded remote content into logs or
  error messages).

Findings and any resulting fixes are recorded in `PLAN.md`'s decision
log, not a separate audit document.

## 12. Documentation

- `docs/release.md` (new): how a release is cut — tag, what CI does,
  where artifacts and signatures land, how to verify one by hand with
  `minisign -V`.
- `docs/incident-recovery.md` (new): what an operator does when an
  upgrade fails or misbehaves — `engine rollback` as the no-network
  first response, when to fall back to `engine install` of a known-good
  older version instead, and the opt-in rollout procedure below.

## 13. Opt-in rollout to test servers

No new "rollout channel" feature. `engine install` already requires an
explicit version, checksum, and signature on every call — nothing
auto-updates, so every rollout is manual and per-server by
construction. The opt-in procedure is operational, documented in
`docs/incident-recovery.md`: exercise `engine install` /
`engine rollback` against the `docker/test-server` fixture first, then
against one real managed server, before wider rollout. No code is
required to enforce this beyond what already exists.

## 14. Testing

Per the repo's Definition of Done, applied to the new surface:

- unit tests for URL construction (version + arch -> expected asset
  URL), checksum comparison, and minisign verification (including
  tampered-signature and tampered-checksum failure cases) without a
  live network call;
- an integration test exercising `engine install` end-to-end against a
  local HTTP fixture server (not the real GitHub Releases) serving a
  real binary + real `SHA256SUMS`/`.minisig` signed with a test key
  pair, covering: fresh install, install-over-existing (upgrade),
  corrupted-artifact rejection (no filesystem change), and
  `engine rollback` after that;
- a website-control-panel integration test (alongside the existing
  `ops_engine_deploy_rollback.rs` workflow test) exercising
  install/rollback the same way deploy/rollback are exercised today,
  against the rewritten `build-ops-engine.sh` fixtures;
- `engine rollback` with no retained previous binary returns the
  documented error and leaves the active binary untouched.

## 15. Out of scope

- Fleet-wide/automatic rollout orchestration (batching, canarying
  across many servers) — Phase 7's exit criteria only require that
  rollout/rollback procedures have been exercised, not that they be
  automated across a fleet.
- `diffoscope`-grade bit-for-bit reproducibility verification.
- sigstore/cosign or any OIDC-based signing.
- Windows or non-Linux build targets.
- Retention of more than one previous engine binary on a managed
  server.
