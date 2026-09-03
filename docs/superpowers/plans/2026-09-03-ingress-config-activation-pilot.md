# Plan: `ingress.activateConfig` — Phase 8 pilot (atomic Caddy/site-config changes)

Status: ready for execution
Date: 2026-09-03
Milestone doc for: `PLAN.md` Phase 8, candidate "atomic Caddy and site
configuration changes"

## Why this, why now, why scoped this way

`website-control-panel`'s `src-tauri/src/commands/runtime_pool.rs` has one
function, `activate_caddyfile`/`activate_caddyfile_checked`
(`runtime_pool.rs:834-1038`), that is the write path for essentially every
site-config mutation: basic auth, redirects, security headers, access logs,
maintenance mode, domain add/remove, site rename, Cloudflare presets — **~28
call sites** across `runtime_pool.rs`, `reconciliation.rs`, and
`system2.rs`. It already does exactly what `ops-engine` is good at: write a
`.tmp` sibling, validate before it's live, atomically rename in, and on any
post-activation failure restore the exact previous file and reload it. It is
currently built out of one raw SSH string per step (`exec(...)`,
`shell_escape`), same class of risk Git deploy had before Phase 2.

**This plan moves the primitive into `ops-engine`, wired to exactly one of
those 28 call sites — `disable_basic_auth` — as the pilot.** Per the
explicit user decision when this was scoped: build the general primitive,
prove it end to end on the smallest, most self-contained caller, leave the
other ~27 on the existing raw-SSH path for a later, separate migration once
this one has run in practice. Do not touch any other call site in this
plan.

`disable_basic_auth` (`runtime_pool.rs:1221-1246`) was chosen as the pilot
because it has no side computation beyond a pure, already-tested text
transform (`remove_basic_auth_block`) before the activate call — the
cleanest possible instance of the pattern, nothing else to get wrong.

## What's new here for `ops-engine`

Two things this engine has never done before, both scoped narrowly:

1. **A second config-writable root beyond `content_roots`/site webroots.**
   Ingress route files live at a fixed, shared location
   (`/etc/wcp/ingress.d/<domain>.caddyfile`), not under any site's own
   content root. `EngineConfig` gets a new `ingress_root: TrustedRoot`
   field.
2. **Talking to Docker Compose.** Validating and reloading a config means
   running `docker compose exec -T <service> caddy validate|reload ...`
   inside the always-fixed shared "wcp" stack
   (`website-control-panel/src-tauri/src/commands/mod.rs:39-40`:
   `STACK_COMPOSE_PROJECT = "wcp"`, `STACK_REMOTE_BASE = "~/compose/wp-stack"`
   — both compiled-in constants there, never configurable at runtime; mirror
   that exactly here as compiled-in constants, not new config fields, per
   this project's existing "no ambient discovery, no configurable-when-it-
   doesn't-need-to-be" convention (see the Phase 7 final review's I2
   finding for why that convention exists and matters).

## Global Constraints

- Every subprocess call is argv-only through the existing bounded
  `process::run` (`src/process.rs`) — no shell, no string-built commands.
  `activate_caddyfile`'s current implementation builds one shell string per
  step; do not port that shape, port the *behavior*.
- `ingress_root` must be a real `TrustedRoot` (`src/site.rs`) — every path
  this operation touches resolves through it exactly like `content_roots`
  and `state_root` already do. No lexical path check as a substitute.
- The activation sequence's failure semantics must match
  `activate_caddyfile` exactly: syntax failure before anything touches the
  live path → live path untouched; reload failure after activation →
  previous file restored and reloaded, and if *that* reload also fails, say
  so explicitly rather than silently leaving a broken live config.
- Route through the same `mutation::preflight` locking/idempotency/audit
  machinery every other mutation in this engine uses
  (`src/mutation/preflight.rs`) — this is a mutation like `site.deploy`, not
  a special case.
- Hash-guard optimistic concurrency (the `expected_prior_hash` parameter in
  `activate_caddyfile_checked`) is part of the contract, not optional —
  `disable_basic_auth` uses the checked variant.
- No test in this plan may require a real Docker Compose stack running
  locally. Tests fake the `docker` binary the same way Phase 7's
  `tests/engine.rs` faked the engine binary itself (a small script/binary
  stand-in exercised through the real `process::run` path) — see Task 5.
  The *website-control-panel* side (Task 6) gets the real, Docker-backed
  end-to-end proof, against the existing `docker/test-server` SSH fixture
  stack that already runs a real ingress container.

## Task 1 — `ingress_root` in `EngineConfig`

Add `ingress_root: TrustedRoot` to `EngineConfig` (`src/config.rs`).
`CONFIG_SCHEMA_VERSION` bumps to `2` (no deployed production config exists
yet — see `PLAN.md`'s TEST-ONLY-key decision log entries — so this is a
clean bump, not a compat-breaking one worth agonizing over). `ingress_root`
must not overlap any `content_roots`/`state_root`/`credential_root`, same
`roots_overlap` check already applied to the other roots
(`config.rs:44-48`) — extend that check to include it. Update
`RawEngineConfig` and every existing config fixture/test in `config.rs` and
anywhere else a raw JSON config literal is constructed for tests
(`grep -rn schemaVersion` to find them all).

Exit: `cargo test config::` green, including a new test asserting
`ingress_root` overlapping `content_roots` is rejected.

## Task 2 — Docker Compose exec primitive

New module `src/compose.rs`:

- Compiled-in constants mirroring `website-control-panel`'s exactly:
  `COMPOSE_PROJECT = "wcp"`, `COMPOSE_BASE_DIR` — resolve `~` to the
  invoking user's actual home directory at runtime (this engine runs as
  root under `sudo`, so "the invoking user's home" needs a real answer —
  read it from `HOME` if the environment provides it, else
  `nix`/`libc` `getpwuid`; do not assume `/root`). Record whichever
  resolution strategy you pick in a doc comment; this is a real decision,
  not a formality.
- `pub fn exec(service: &str, args: &[&str], cwd: Option<&Path>) -> Result<ProcessOutput, Error>` —
  builds argv `["docker", "compose", "-p", COMPOSE_PROJECT, "--env-file",
  ".env", "-f", "stack/docker-compose.yml", "exec", "-T", service, ...args]`
  and runs it through `process::run` with `cwd` set to the resolved compose
  base dir. Bounded timeout (30s default, matching `process.rs`'s existing
  default — a `caddy validate`/`reload` call has no reason to need longer;
  if you find one, say so in your report rather than silently picking a
  bigger number).
- Unit tests using a fake `docker` executable (a small script fixture,
  `#[cfg(unix)]`, `0755`) that echoes its argv back or exits non-zero on
  request, run through the real `process::run` — same technique Task 5 and
  Phase 7's `tests/engine.rs` already use for "exercise the real subprocess
  path without a real target binary."

Exit: `cargo test compose::` green.

## Task 3 — `ingress::activate_config` operation

New module `src/ingress.rs` (or `src/engine/` sibling if you judge the
existing module layout fits better — read `src/deploy/` and `src/engine/`
first and match whichever precedent is closer; this is a mutation
operation like `deploy`, not an engine-self-update operation like
`engine/`, so `src/ingress/` following `src/deploy/`'s shape is the
likely right call).

Behavior (port from `runtime_pool.rs:948-1038`'s `activate_caddyfile`,
using `compose::exec` from Task 2 instead of shell strings):

1. Resolve `host_dest` under `ingress_root` (Task 1) via
   `TrustedRoot::resolve` — reject anything that doesn't resolve inside it.
2. If `expected_prior_hash` is `Some`, hash the current file's contents (if
   it exists) and compare; mismatch → fail closed with a stable error code
   before writing anything (mirrors `activate_caddyfile_checked`'s
   `hash_guard_check_cmd` behavior, but as a real read + compare instead of
   a remote shell one-liner).
3. Write `content` to `host_dest.tmp` via the existing atomic-write
   primitive (`ManagedRoot`/`write_atomic` — reuse, don't reimplement).
4. `compose::exec(INGRESS_SERVICE, ["caddy", "validate", "--config",
   <container path for the tmp file>, "--adapter", "caddyfile"], ...)`.
   Container-side path: same convention `activate_caddyfile` uses
   (`container_dest` mirrors `host_dest`'s relative position under the
   ingress container's own config mount — confirm the exact mount path
   from `website-control-panel`'s Docker Compose stack definition, likely
   under `docker/` or `stack/` in that repo, rather than guessing).
   Non-zero exit → remove the `.tmp` file, fail closed, nothing live
   touched.
5. If a prior file exists at `host_dest`, copy it to
   `host_dest.rollback-<random-hex>` first (reuse whatever random-suffix
   helper this engine already has, or add one matching
   `website-control-panel`'s `random_hex_suffix` in spirit). Rename `.tmp`
   over `host_dest`.
6. `compose::exec(INGRESS_SERVICE, ["caddy", "reload", "--config",
   "/etc/caddy/Caddyfile", "--adapter", "caddyfile"], ...)`. On failure:
   restore from the `.rollback-*` backup (or remove `host_dest` if there
   was no prior file), reload again, and if *that* reload also fails,
   return an error that says so explicitly (both failures), not just the
   first one.
7. On full success, remove the `.rollback-*` backup file.
8. Wire through `mutation::preflight::run` exactly like `deploy::execute`
   does (Global Constraints) — `PreCommit`/`PostCommit`, audit record,
   idempotency-key replay.

Response envelope: new `ActivateConfigResult` with at minimum `activated:
bool` and whatever the existing `DeployResult`/`RollbackResult` shape
already establishes as this project's response conventions (read
`src/engine/mod.rs`'s or `src/deploy/`'s response type before inventing a
new shape).

New stable error codes as needed (`src/error.rs`, following the existing
naming pattern) — at minimum something for "hash guard mismatch" and
something for "validate failed," distinct from each other so a client can
tell "someone else changed this" apart from "your new config is invalid."

Exit: unit tests covering — fresh activation (no prior file), successful
update with matching hash guard, rejected update with stale hash guard,
validate-failure leaves the live file untouched, reload-failure restores
and reloads the previous file, reload-failure-after-restore-also-fails
reports both. Use Task 2's fake-`docker` fixture to drive the
validate/reload outcomes deterministically.

## Task 4 — CLI wiring

`ops-engine ingress activate-config --domain <domain> --content-file <path>
--request-id <uuid> [--expected-hash <hash>] [--idempotency-key <key>]`
(or equivalent — match this project's existing CLI argument conventions in
`src/cli.rs` for `site deploy`/`engine install` exactly, don't invent a new
style). Advertise `ingress.activateConfig` through `capabilities`
(`src/commands/capabilities.rs`), same as every other operation.

Exit: `cargo test --all-features` green including a CLI-level test (see
existing `tests/cli.rs`-style coverage for `site deploy` as the pattern to
match).

## Task 5 — Engine-side integration test

`tests/ingress.rs`: exercises `ingress::activate_config` end to end against
a real filesystem trusted root and the fake-`docker` fixture from Task 2 —
fresh activation, update with hash guard, rejected stale-hash update,
validate failure (fake `docker` exits non-zero on `validate`), reload
failure with successful rollback (fake `docker` exits non-zero only on
`reload`, only once). No real Docker Compose or Caddy involved here — that
proof is Task 6's job, against the real stack.

## Task 6 — `website-control-panel`: wire `disable_basic_auth`

In `commands/ops_engine.rs`, add `ops_engine_ingress_activate_config` (or
match whatever this plan's Task 4 named the operation) mirroring the
existing `ops_engine_deploy`/`ops_engine_rollback` command shape exactly —
same envelope-parsing, same error mapping, same `CapabilityCache`
`require_operation` gate before calling.

In `runtime_pool.rs`'s `disable_basic_auth` specifically (and *only* that
one function — every other `activate_caddyfile`/`activate_caddyfile_checked`
call site in this codebase stays exactly as it is, out of scope for this
plan): branch on whether the site/server is `ops-engine`-enrolled (same
enrollment check `commands::ops_engine` already establishes elsewhere) —
enrolled → call the new `ops_engine_ingress_activate_config` path instead
of `activate_caddyfile_checked`; not enrolled → existing behavior,
untouched. This is the same additive, opt-in shape the module's own header
comment already documents (`commands/ops_engine.rs:1-7`).

Add an end-to-end integration test in `src-tauri/src/workflow_tests/`
(new file or alongside `ops_engine_deploy_rollback.rs`, whichever the
existing test harness conventions favor) that runs `disable_basic_auth`
against the real Docker SSH test stack
(`docker/test-server`) with a real `ops-engine` binary and a real ingress
Caddy container — enabling basic auth first (via the existing unmigrated
path, since `enable_basic_auth` is out of scope), then disabling it through
the new `ops-engine`-backed path, and asserting the live Caddyfile no
longer has the `basicauth` block and Caddy actually reloaded (a real HTTP
request through the fixture stack succeeds without basic-auth credentials
afterward — the same kind of live-behavior assertion
`ops_engine_deploy_and_rollback_against_the_real_engine` already makes for
deploy).

This is the test that actually proves the pilot — everything in Tasks 1-5
is unit/fixture-level; this is the one place a real Caddy container
validates and reloads a config this engine wrote.

## Out of scope for this plan

- The other ~27 `activate_caddyfile`/`activate_caddyfile_checked` call
  sites. A later plan, once this pilot has run in practice, decides whether
  and how to migrate them (possibly a shared client-side helper that
  every call site routes through, rather than repeating Task 6's
  enrolled/not-enrolled branch 27 more times — worth designing properly
  rather than copy-pasting).
- `enable_basic_auth` (needs the bcrypt-hash-via-`caddy hash-password`
  step too — its own small piece of Docker-exec design, deliberately not
  bundled into this pilot to keep Task 6 to one clean function).
- Any change to `reconciliation.rs`'s remediation paths, even though some
  of them call the same primitive — out of scope per the earlier scoping
  decision (reconciliation is coupled to `runtime_pool` in ways that need
  its own plan).
