# Plan: Engine-side maintenance-mode modeling (Operations Engine, sub-project 2 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach `operations-engine` to model `website-control-panel`'s maintenance-mode `.maintenance-backup` file, so the 6 already-migrated ingress call sites (`disable_basic_auth`, `update_raw_ingress_route`, `enable_access_log`, `set_security_headers`, `set_redirects`, `set_ip_acl`) — and `set_maintenance` itself — can go through the engine instead of falling back to legacy raw-SSH when a site is parked.

**Architecture:** Two new engine operations, `ingress.park` and `ingress.unpark`, model the park/unpark transition itself (each its own transaction/audit record). `ingress.activateConfig` gains a `target: RouteTarget` field (`Live` | `Backup`) so the 6 already-migrated call sites can write to a parked domain's backup file — hash-guarded, but with no Caddy validate/reload, since the backup file is never imported by the live Caddyfile. `website-control-panel`'s `set_maintenance` splits into an engine-or-legacy dispatcher exactly like `disable_basic_auth`/`disable_basic_auth_legacy` already does.

**Tech Stack:** Rust (both repos). `operations-engine`: `cap-std`-backed `ManagedRoot`, `compose::exec` for `docker compose exec`, existing `mutation::preflight`/`transaction::{state,audit,commit}` pipeline. `website-control-panel`: Tauri commands over SSH, existing `ops_engine::invoke` CLI-shell-out pattern.

**Spec:** No separate spec document — the design below was agreed interactively in chat (four explicit decisions, recorded here so the plan is self-contained):
1. Model park/unpark as two new first-class engine operations (`ingress.park`, `ingress.unpark`), not as a mode flag on `activateConfig`.
2. The backup file (`<domain>.maintenance-backup`) stays under the existing `ingressRoot` — no new `TrustedRoot`/schema field, no schema bump. It gets a second deterministic filename-derivation function alongside `route_path`.
3. `website-control-panel`'s `set_maintenance()` itself migrates to call the new engine operations (not just future/other consumers of the backup format) — same engine-or-legacy dispatch shape as `disable_basic_auth`.
4. `ingress.activateConfig` gains a `target: Live | Backup` field so the 6 already-migrated call sites can write to a parked domain's backup while it stays parked, instead of falling back to legacy. `Backup` skips Caddy validate/reload entirely (the backup file is inert).

## Global Constraints

- Work directly on `main` (operations-engine) / `master` (website-control-panel), no feature branches.
- Commit only when the user explicitly asks; never add a `Co-Authored-By:` trailer.
- `operations-engine`'s protocol surface (Tasks 1–6) must land and be pushed to `origin/main` (Task 6's final step) before `website-control-panel`'s client-side tasks (7–10) are built or tested against it — same sequencing the ingress-config-activation pilot used. Task 11 (`PLAN.md` sync) is back in `operations-engine`, after both repos are done.
- Every new filesystem operation on the engine side goes through `ManagedRoot`/`TrustedRoot` — never a bare `std::fs` call reachable from a request.
- No protocol response message may contain a path, subprocess output, or a config fragment (`docs/protocol.md`'s `details` allowlist — see `ActivateConfigError::protocol()` for the existing pattern to match).
- Docker-backed website-control-panel tests: an isolated single-test run against the long-lived shared fixture stack is unreliable; `cargo test --lib workflow_tests:: -- --test-threads=1` is the authoritative check on any mismatch.
- After Task 12, `operations-engine/PLAN.md`'s Phase 8 section must reflect this sub-project as shipped (it has desynced twice before in this initiative).

---

## Task 1 — `RouteTarget` and `backup_route_path` in `ingress/mod.rs`

**Files:**
- Modify: `src/ingress/mod.rs`

**Interfaces:**
- Produces: `pub enum RouteTarget { Live, Backup }` (`Clone, Copy, Debug, Eq, PartialEq`). `pub fn backup_route_path(domain: &Domain) -> SiteRelativePath`.
- Produces: `ActivateConfigRequest` gains `pub target: RouteTarget`. `ActivateConfigRequest::parse` gains a `target: RouteTarget` parameter (after `guard`, before `request_id`, matching the existing parameter order convention of "identity, content, precondition, then request bookkeeping"). No default — every caller names it explicitly, so no protocol ambiguity is possible.

Add `backup_route_path`, mirroring the existing `route_path`:

```rust
pub const BACKUP_ROUTE_EXTENSION: &str = "maintenance-backup";

pub fn backup_route_path(domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{domain}.{BACKUP_ROUTE_EXTENSION}"))
        .expect("a validated Domain always yields a single valid path component")
}
```

Add `RouteTarget` next to `HashGuard`:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteTarget {
    /// The domain's live `<domain>.caddyfile` — validated inside the
    /// ingress container and reloaded before this call reports success.
    Live,
    /// The domain's `<domain>.maintenance-backup` — never imported by the
    /// live Caddyfile, so writing it needs no validation and no reload.
    Backup,
}
```

Thread `target` through `ActivateConfigRequest` and `ActivateConfigRequest::parse` (no new validation needed — it's a plain enum, not a wire string at this layer; wire parsing happens in Task 4's CLI work).

- [ ] **Step 1: Write failing tests** in `ingress/mod.rs`'s existing `#[cfg(test)] mod tests`:
  - `backup_route_path_is_the_domains_maintenance_backup_file`: for `Domain::parse("sub.example.com")`, asserts `backup_route_path(&domain).as_path().to_str() == Some("sub.example.com.maintenance-backup")`.
  - `request_parses_all_valid_fields` (existing test) gains a `target: RouteTarget::Live` argument to its `ActivateConfigRequest::parse` call and an assertion `assert_eq!(request.target, RouteTarget::Live);`.
  - New: `request_carries_the_backup_target_when_asked`, same shape as `request_parses_all_valid_fields` but passing `RouteTarget::Backup` and asserting it round-trips.

- [ ] **Step 2: Run `cargo test --lib ingress::tests -- --test-threads=1`** — expect compile failures (every existing call to `ActivateConfigRequest::parse` in this crate is now missing the `target` argument). This is expected; Step 3 fixes call sites in this file only. Other files' call sites (`commands/ingress.rs`, its tests) are fixed in Task 4 — until then `cargo build` for the whole crate will not compile, which is fine mid-task.

- [ ] **Step 3: Implement** `RouteTarget`, `backup_route_path`, and thread `target` through `ActivateConfigRequest`/`parse`, updating every call to `ActivateConfigRequest::parse` inside `ingress/mod.rs`'s own test module to pass `RouteTarget::Live` (these tests are about request parsing, not target behavior, so `Live` is the right default there).

- [ ] **Step 4: Run `cargo test --lib ingress::tests -- --test-threads=1`** — expect PASS for this module. (The crate as a whole still won't build — `execute.rs`'s and `activate.rs`'s own test modules construct `ActivateConfigRequest`/call `activate()` too; those are fixed in Task 2.)

- [ ] **Step 5: Commit**

```bash
git add src/ingress/mod.rs
git commit -m "Add RouteTarget and backup_route_path for maintenance-mode backup files"
```

---

## Task 2 — `activate::activate` branches on `RouteTarget`

**Files:**
- Modify: `src/ingress/activate.rs`
- Modify: `src/ingress/execute.rs` (call site of `activate::activate`, and `ActivateConfigResult` construction)

**Interfaces:**
- Consumes: `RouteTarget`, `backup_route_path` (Task 1).
- Produces: `pub(crate) fn activate(ingress_root: &TrustedRoot, domain: &Domain, content: &str, guard: &HashGuard, target: RouteTarget, backup_suffix: &str, compose: &compose::Access) -> Result<Activation, Error>` — `target` inserted after `guard`, before `backup_suffix` (the suffix is meaningless for `Backup`, still required as a parameter for signature uniformity with `Live`; the `Backup` branch ignores it).

`RoutePaths::new` currently always resolves `live = super::route_path(domain)`. For `RouteTarget::Backup`, there is no `.tmp` staging, no `.rollback-*` backup-of-a-backup, no validate, no reload — those all exist to protect the *live*, Caddy-imported file across a container reload, which is meaningless for a file Caddy never reads. So `activate()` branches immediately on `target`:

- `RouteTarget::Live`: today's exact body, unchanged, operating on `route_path(domain)`.
- `RouteTarget::Backup`: a new, much shorter path operating on `backup_route_path(domain)`:
  1. `let root = ManagedRoot::open(ingress_root).map_err(Error::Io)?;`
  2. `let path = super::backup_route_path(domain);`
  3. `let current = read_optional(&root, &path)?;`
  4. `if !guard.is_satisfied_by(current.as_deref()) { return Err(Error::HashGuardMismatch); }`
  5. If `current.as_deref() == Some(content.as_bytes())`, return `Ok(Activation { activated: false })` immediately — no reload exists to converge here, so unlike the `Live` no-op case there is nothing left to do.
  6. `root.write_atomic(&path, content.as_bytes()).map_err(Error::Io)?;`
  7. `Ok(Activation { activated: true })`

  No `compose` parameter use at all in this branch — `compose` stays a parameter (the function signature is shared with `Live`) but the `Backup` branch never calls `.exec()` on it, satisfying the "target=Backup never touches Docker" requirement without needing a separate `ActivateContext` shape.

Update `execute.rs`'s call to `activate::activate` to pass `request.target`, and update its four call sites of `ActivateConfigRequest::parse`/construction inside its own test module (`request()` helper) to pass `RouteTarget::Live` (that test module is entirely about the `Live` reload/rollback pipeline; Task 3 does not touch it further, since Backup requests bypass `execute::execute`'s `Live`-only assumptions the same way — see Task 3 for why `execute()` itself needs no branching).

- [ ] **Step 1: Write failing tests** in `activate.rs`'s `#[cfg(test)] mod tests`, alongside the existing ones (which all get a `RouteTarget::Live` argument added to their `run()` helper calls — update `run()`'s signature to take `target: RouteTarget` and thread it through):
  - `a_fresh_backup_write_needs_no_validate_or_reload`: `ingress_root(None)`, `FakeDocker::new()`, call `activate(&root.trusted, &domain(), UPDATED, &HashGuard::Absent, RouteTarget::Backup, SUFFIX, &docker.access())`; assert `Ok(Activation { activated: true })`, `fs::read_to_string(root.dir.path().join("example.com.maintenance-backup"))` equals `UPDATED`, `docker.calls("validate").is_empty()`, `docker.calls("reload").is_empty()`.
  - `a_stale_backup_guard_is_rejected_before_any_write`: pre-seed `example.com.maintenance-backup` with `PREVIOUS` (write it directly via `fs::write`, not through `activate`), call with a wrong `HashGuard::Sha256`, assert `Error::HashGuardMismatch` and the file on disk is unchanged.
  - `identical_backup_content_reports_unactivated_and_writes_nothing`: pre-seed the backup with `UPDATED`, call `activate(...RouteTarget::Backup...)` with `content = UPDATED` and a matching guard; assert `Activation { activated: false }` and that no Docker calls happened (unlike the `Live` no-op case, which still reloads).
  - `a_backup_write_never_touches_the_live_route_file`: after a successful `Backup` activation, assert `root.live()` (the existing helper, which reads `example.com.caddyfile`) is still `None` — the two files are independent.

- [ ] **Step 2: Run `cargo test --lib ingress::activate::tests -- --test-threads=1`** — expect FAIL (compile error: `activate()` doesn't take a `target` parameter yet).

- [ ] **Step 3: Implement** the `target` parameter and the `Backup` branch as specified above, updating every existing call site of `activate()` in this file (production and test) to pass `RouteTarget::Live` except the four new tests.

- [ ] **Step 4: Run `cargo test --lib ingress::activate::tests -- --test-threads=1`** — expect PASS, all tests including the pre-existing `Live`-path ones (which must be byte-for-byte unaffected).

- [ ] **Step 5: Fix `execute.rs`'s call site** — pass `request.target` into `activate::activate(...)`, and update `execute.rs`'s own `request()` test helper to take a `target: RouteTarget` parameter (default all existing call sites in that file to `RouteTarget::Live`, since every existing test there exercises the `Live` reload/rollback pipeline specifically).

- [ ] **Step 6: Run `cargo test --lib ingress:: -- --test-threads=1`** — expect PASS for the whole `ingress` module (this is the first point since Task 1 where the full module compiles and passes together).

- [ ] **Step 7: Commit**

```bash
git add src/ingress/activate.rs src/ingress/execute.rs
git commit -m "Teach activate() to write maintenance-backup files without validate/reload"
```

---

## Task 3 — CLI `--target` flag on `ingress activate-config`

**Files:**
- Modify: `src/cli.rs` (the `IngressCommand::ActivateConfig` variant)
- Modify: `src/commands/ingress.rs` (`run`, `activate_config`, their tests)

**Interfaces:**
- Consumes: `RouteTarget` (Task 1).
- Produces: `IngressCommand::ActivateConfig` gains a `target: IngressTarget` field where `IngressTarget` is a small CLI-facing enum (`clap::ValueEnum`, values `live`/`backup`) that `commands/ingress.rs::activate_config` maps to `ingress::RouteTarget`. Keeping the CLI-facing enum separate from the domain `RouteTarget` follows this codebase's existing separation between wire/CLI shapes and domain types (e.g. `HashGuard` vs. the raw `Option<&str>` the CLI receives).

In `cli.rs`, add to `IngressCommand::ActivateConfig`:

```rust
/// Which of this domain's two route files to write: `live` (the
/// imported, Caddy-validated Caddyfile — today's only behavior) or
/// `backup` (the inert `.maintenance-backup` file a parked domain's
/// pre-maintenance config is kept in; no validation or reload).
#[arg(long, value_enum, default_value_t = IngressTarget::Live)]
target: IngressTarget,
```

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum IngressTarget {
    Live,
    Backup,
}
```

`default_value_t = IngressTarget::Live` keeps every existing invocation (and every existing test in `tests/cli.rs`) working unchanged.

In `commands/ingress.rs`:
- `run()` passes `target` through to `activate_config`.
- `activate_config` gains a `target: IngressTarget` parameter, maps it to `ingress::RouteTarget` (`IngressTarget::Live => RouteTarget::Live`, `IngressTarget::Backup => RouteTarget::Backup`), and passes it to `ActivateConfigRequest::parse` (Task 1's new parameter) and nowhere else — `run_activate_config`/`execute_activate_config` need no signature change, since `target` now lives on the `ActivateConfigRequest` itself.

- [ ] **Step 1: Write a failing test** in `commands/ingress.rs`'s test module (or `tests/cli.rs` if that's where CLI-argument-level tests for this command already live — check both, follow whichever file `ActivateConfig`'s existing `--expected-hash`/`--idempotency-key` argument tests are in): a test that parses CLI args including `--target backup` and asserts the resulting `ActivateConfigRequest.target == RouteTarget::Backup`; a second test that omits `--target` entirely and asserts it defaults to `RouteTarget::Live`.

- [ ] **Step 2: Run the relevant test binary** (`cargo test --test cli` or `cargo test --lib commands::ingress::tests`, whichever file Step 1 landed in) — expect FAIL (field doesn't exist yet).

- [ ] **Step 3: Implement** `IngressTarget`, the CLI flag, and the `activate_config` plumbing as specified above.

- [ ] **Step 4: Run `cargo test --all-features`** for the whole crate — expect PASS. This is the first point since Task 1 where the entire crate (lib + CLI + all existing tests) compiles and passes with the new `target` field fully wired end to end for `activateConfig`.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/commands/ingress.rs
git commit -m "Add --target live|backup to ops-engine ingress activate-config"
```

---

## Task 4 — `ingress::park` operation

**Files:**
- Create: `src/ingress/park.rs`
- Modify: `src/ingress/mod.rs` (add `pub mod park;`, the new `OPERATION` constant, and result/error types if colocated per this crate's convention — check whether `ActivateConfigResult`/`ActivateConfigError` living in `mod.rs` vs. `execute.rs` is the pattern to match; `ActivateConfigResult` is in `mod.rs`, `ActivateConfigError` is in `execute.rs` — follow that same split: `ParkResult`/`ParkRequest` in `mod.rs`, `ParkError` in `park.rs`)
- Test: inline `#[cfg(all(test, unix))] mod tests` in `park.rs`, using `fake_docker::FakeDocker` exactly as `execute.rs`'s tests do.

**Interfaces:**
- Consumes: `RouteTarget`, `backup_route_path`, `route_path` (Task 1); `activate::activate` including its `Backup` branch (Task 2); `mutation::preflight`, `transaction::{state, audit, commit}` (already used by `execute.rs` — reuse the same imports and `open_ingress_state`/`state_path_for`/`audit_log_path` helpers by making them `pub(crate)` in `execute.rs` if not already, rather than duplicating them).
- Produces:
  - `pub const PARK_OPERATION: &str = "ingress.park";` in `ingress/mod.rs`, alongside the existing `pub const OPERATION` (which stays exactly as-is, still meaning `activateConfig` — no rename, no changes to its existing importers in `execute.rs`/`commands/ingress.rs`, since `OPERATION`/`PARK_OPERATION`/`UNPARK_OPERATION` are three distinct names with no collision).
  - `pub struct ParkRequest { pub domain: Domain, pub maintenance_content: String, pub request_id: RequestId, pub idempotency_key: Option<IdempotencyKey> }` with a `ParkRequest::parse(domain: &str, maintenance_content: impl Into<String>, request_id: &str, idempotency_key: Option<&str>) -> Result<Self, ParkRequestError>` constructor mirroring `ActivateConfigRequest::parse` (same `ContentTooLarge`/`InvalidDomain`/`InvalidRequestId`/`InvalidIdempotencyKey` error shape — no hash guard on the request itself, since `park` derives its own guard internally from whatever is live right now; see below for why that is safe).
  - `pub struct ParkResult { pub domain: String, pub already_parked: bool, pub backup_sha256: ConfigHash, pub activated_at_unix_secs: u64 }` (`already_parked: true` when a backup already existed, so this call only re-activated the maintenance page — mirrors `ActivateConfigResult.activated`'s "tell the caller whether anything actually changed" role).
  - `pub fn execute(context: &ActivateContext<'_>, request: &ParkRequest, cancellation: &CancellationToken) -> Result<ParkResult, ParkError>` in `park.rs`, reusing `execute::ActivateContext` unchanged (same three fields: `ingress_root`, `engine_state`, `compose`).

Behavior of `park::execute`, inside **one** `mutation::preflight::run`/`PreCommit`/audit cycle (do not call `ingress::execute::execute` internally — that would record a second, separate `ingress.activateConfig` transaction for the live write, which the agreed design explicitly rules out):

1. `preflight::run` exactly as `execute::execute` does, with `operation = PARK_OPERATION`, replaying via the same `TransactionStatus` matching if the idempotency key was already claimed.
2. `PreCommit` cancellation check, exactly as `execute::execute` does.
3. Open `ManagedRoot::open(context.ingress_root)` and read the current live content: `read_optional`-equivalent on `route_path(&request.domain)` (reuse `activate::activate`'s private `read_optional` by making it `pub(crate)`, rather than reimplementing file-optional-read).
4. If no live file exists at all, fail with `ParkError::NothingLive` (parking a domain with no live route is not a state this operation should silently paper over — the caller read something, or should have).
5. If `backup_route_path(&request.domain)` does **not** yet exist: call `activate::activate(ingress_root, &domain, &live_content, &HashGuard::Absent, RouteTarget::Backup, backup_suffix, compose)` to snapshot it. `already_parked = false`.
   If it **does** already exist: skip the snapshot entirely — a second `park` call (e.g. changing the maintenance reason while already parked) must not overwrite the real pre-maintenance config with whatever is live right now (which is already the maintenance page). `already_parked = true`.
6. Call `activate::activate(ingress_root, &domain, &request.maintenance_content, &HashGuard::Sha256(ConfigHash::of(&live_content)), RouteTarget::Live, backup_suffix, compose)` to put the maintenance page live. The hash guard here is exactly the content this call itself just read in step 3 — not caller-supplied — which is what makes `ParkRequest` need no guard field at all: this operation owns the "read, then guard on what you read" invariant end to end, unlike `activateConfig`, where the caller does its own read.
7. On success, same commit/state/audit sequence as `execute::execute`'s tail: `pre_commit.commit()`, drop the lock, build `ParkResult`, `state.mark_committed(...)`, `state::save(...)`, `audit::append(...)`.
8. On failure at any step, same `fail()` helper shape as `execute.rs` (reuse it — make it generic over the error's `.protocol()` method, or duplicate the ~15 lines if genericizing is awkward; check whether `execute.rs`'s `fail()` is easy to parametrize over `TransactionState`/`ActivateConfigError` vs. `ParkError` before deciding).

`ParkError` variants: `Io(io::Error)`, `Preflight(preflight::Error)`, `ReplayInProgress`, `NothingLive`, `Activate(activate::Error)` (covers both the snapshot and the live-write steps — a caller doesn't need to distinguish which internal write failed, only that parking didn't complete), `State(state::StateError)`, `Cancelled`, `PostCommitRecordFailed { result: ParkResult, cause: state::StateError }`, `Replayed { code: ErrorCode, message: String }`. Its `.protocol()` method mirrors `ActivateConfigError::protocol()`'s mapping (reuse `compose_failure_code`/`timed_out` by making them `pub(crate)` in `execute.rs` rather than duplicating); add one new message for `NothingLive`: `(ErrorCode::InvalidInput, "no live configuration exists for this domain to park".to_owned())`.

- [ ] **Step 1: Write failing tests** in `park.rs`, following `execute.rs`'s test harness shape (`Host`, `host()`, but this file's own copy — or factor `Host`/`host()` out to a shared `#[cfg(test)] mod test_support` under `src/ingress/` if `unpark.rs` in Task 5 would otherwise duplicate it verbatim; decide once Task 5's tests are drafted, not preemptively):
  - `a_first_park_snapshots_live_and_activates_the_maintenance_page`: seed live content, call `park::execute` with fresh `maintenance_content`; assert the live file now holds `maintenance_content`, the backup file holds the original live content, `result.already_parked == false`, one transaction record with `operation == "ingress.park"` and `status == "COMMITTED"`.
  - `parking_an_already_parked_domain_reactivates_the_maintenance_page_without_touching_the_backup`: seed live = maintenance page A, backup = original config; call `park::execute` with maintenance content B; assert live now holds B, backup is **unchanged** (still the original config, not maintenance page A), `result.already_parked == true`.
  - `parking_a_domain_with_no_live_config_fails_closed`: empty ingress root, call `park::execute`; assert `ParkError::NothingLive`, no files created, no transaction committed (a failed transaction record is fine/expected — assert it's `FAILED`, not absent).
  - `a_retried_idempotency_key_replays_without_re_parking`: same replay pattern as `execute.rs`'s `a_retried_idempotency_key_replays_the_original_result_without_reactivating`.
  - `a_reload_failure_during_the_live_write_leaves_no_backup_orphaned`: `FakeDocker::new().failing("reload", "1")` on a first-time park; assert the whole operation fails, the live file is restored to its original content (via `activate::activate`'s own rollback, which `park` inherits for free), and — this is the case worth a dedicated assertion — the backup file written in step 5 before the failing step 6 is **not** left behind as an orphan implying "parked" when the domain is actually still live. Decide during implementation whether `park::execute` deletes that backup on this specific failure path or whether leaving it is acceptable because a later successful `park` retry's "does backup already exist" check would then wrongly see `already_parked = true` for a domain that was never really parked — if leaving it is unsafe (it looks unsafe: the retry would skip re-snapshotting a live config that was never actually replaced), have this test assert the backup is cleaned up, and implement that cleanup as a best-effort `discard`-style removal on this specific failure branch.

- [ ] **Step 2: Run `cargo test --lib ingress::park -- --test-threads=1`** — expect FAIL (module doesn't exist).

- [ ] **Step 3: Implement** `park.rs` and the `mod.rs`/`execute.rs` visibility changes (`pub(crate)` on `read_optional`, `compose_failure_code`, `timed_out`, `open_ingress_state`, `state_path_for`, `audit_log_path`, and `fail` or its generalized replacement) needed to reuse them without duplication.

- [ ] **Step 4: Run `cargo test --lib ingress:: -- --test-threads=1`** — expect PASS for the whole module, including the orphaned-backup case from Step 1. If that case reveals the cleanup is more involved than a best-effort removal (e.g. it needs to be part of the same commit/rollback transaction as the live-file restore), treat that as a real finding and resolve it before moving on — don't defer it.

- [ ] **Step 5: Commit**

```bash
git add src/ingress/park.rs src/ingress/mod.rs src/ingress/execute.rs
git commit -m "Add the ingress.park operation"
```

---

## Task 5 — `ingress::unpark` operation

**Files:**
- Create: `src/ingress/unpark.rs`
- Modify: `src/ingress/mod.rs` (`pub mod unpark;`, `UNPARK_OPERATION`, `UnparkRequest`, `UnparkResult`)

**Interfaces:**
- Consumes: everything Task 4 exposed/made `pub(crate)`, plus `park.rs`'s shared test support module if one was factored out.
- Produces:
  - `pub const UNPARK_OPERATION: &str = "ingress.unpark";`
  - `pub struct UnparkRequest { pub domain: Domain, pub request_id: RequestId, pub idempotency_key: Option<IdempotencyKey> }`, `UnparkRequest::parse(domain: &str, request_id: &str, idempotency_key: Option<&str>) -> Result<Self, UnparkRequestError>` — no content field at all: unpark's content comes from the backup file itself, never from the caller.
  - `pub struct UnparkResult { pub domain: String, pub content_sha256: ConfigHash, pub activated_at_unix_secs: u64 }`.
  - `pub fn execute(context: &ActivateContext<'_>, request: &UnparkRequest, cancellation: &CancellationToken) -> Result<UnparkResult, UnparkError>`.

Behavior, inside one preflight/commit/audit cycle exactly as Task 4:

1. `preflight::run` with `operation = UNPARK_OPERATION`.
2. `PreCommit` cancellation check.
3. Read `backup_route_path(&request.domain)`. If it does not exist, fail with `UnparkError::NotParked` — a new `ErrorCode` variant is warranted here (add `ErrorCode::IngressNotParked` to `src/error.rs`'s `ErrorCode` enum and its `as_str` match, following the existing naming/`SCREAMING_SNAKE_CASE` pattern next to `ConfigHashMismatch`), since a client needs to tell "you asked me to unpark something that isn't parked" apart from every other failure mode, and it is not a config-content problem the existing `Config*` codes describe.
4. Read the current live content (for the hash guard on the write below).
5. `activate::activate(ingress_root, &domain, &backup_content, &HashGuard::Sha256(ConfigHash::of(&live_content)), RouteTarget::Live, backup_suffix, compose)` to restore it.
6. On success, delete the backup file (`root.remove_file(&backup_route_path(&domain))`, best-effort — matches `set_maintenance`'s existing legacy behavior of `sudo rm -f ... .ok()`, so a leftover backup after a successful unpark is a known, already-accepted failure mode being ported faithfully, not a new one).
7. Commit/state/audit tail identical in shape to Task 4's.

`UnparkError` variants: `Io`, `Preflight`, `ReplayInProgress`, `NotParked`, `Activate(activate::Error)`, `State`, `Cancelled`, `PostCommitRecordFailed { result: UnparkResult, cause: state::StateError }`, `Replayed { code, message }`. `.protocol()` maps `NotParked => (ErrorCode::IngressNotParked, "this domain is not currently parked".to_owned())`, everything else mirrors `ParkError`'s mapping.

- [ ] **Step 1: Write failing tests** in `unpark.rs`:
  - `unparking_restores_the_backup_to_live_and_deletes_it`: seed live = maintenance page, backup = original config; call `unpark::execute`; assert live now holds the original config, the backup file no longer exists, `result.content_sha256 == ConfigHash::of(original)`, one `COMMITTED` transaction with `operation == "ingress.unpark"`.
  - `unparking_a_domain_with_no_backup_fails_closed`: no backup file present; call `unpark::execute`; assert `UnparkError::NotParked`, live file (if any) untouched, transaction recorded as `FAILED` with `errorCode == "INGRESS_NOT_PARKED"`.
  - `a_reload_failure_during_unpark_leaves_the_maintenance_page_live`: `FakeDocker::new().failing("reload", "all")`; assert the maintenance page is still live (restored via `activate::activate`'s own rollback) **and the backup file still exists** (step 6's delete must not run on a failed activation — assert this explicitly, since a bug here would strand a site parked forever with its own recovery record gone).
  - `a_retried_idempotency_key_replays_without_re_unparking`.

- [ ] **Step 2: Run `cargo test --lib ingress::unpark -- --test-threads=1`** — expect FAIL.

- [ ] **Step 3: Implement** `unpark.rs` and the new `ErrorCode::IngressNotParked` variant in `src/error.rs`.

- [ ] **Step 4: Run `cargo test --lib ingress:: -- --test-threads=1`** — expect PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ingress/unpark.rs src/ingress/mod.rs src/error.rs
git commit -m "Add the ingress.unpark operation"
```

---

## Task 6 — CLI wiring and capabilities advertisement for park/unpark

**Files:**
- Modify: `src/cli.rs` (`IngressCommand::Park`, `IngressCommand::Unpark` variants)
- Modify: `src/commands/ingress.rs` (`run()` match arms, `park`/`unpark` command functions mirroring `activate_config`/`run_activate_config`)
- Modify: `src/commands/capabilities.rs` (`operations` array)

**Interfaces:**
- Consumes: `ParkRequest`/`ParkResult`/`park::execute` (Task 4), `UnparkRequest`/`UnparkResult`/`unpark::execute` (Task 5).

CLI:

```rust
/// Snapshots a domain's live route file to its maintenance-backup and
/// activates a maintenance page in its place.
Park {
    #[arg(long)]
    domain: String,
    #[arg(long = "content-file")]
    content_file: PathBuf,
    #[arg(long = "request-id")]
    request_id: String,
    #[arg(long = "idempotency-key")]
    idempotency_key: Option<String>,
},
/// Restores a parked domain's route file from its maintenance-backup and
/// removes the backup.
Unpark {
    #[arg(long)]
    domain: String,
    #[arg(long = "request-id")]
    request_id: String,
    #[arg(long = "idempotency-key")]
    idempotency_key: Option<String>,
},
```

Extend `IngressCommand::operation()`'s match with `Self::Park { .. } => "ingress.park"` and `Self::Unpark { .. } => "ingress.unpark"`.

`commands/ingress.rs::run()` dispatches the two new variants to new `park()`/`unpark()` functions, each following `activate_config`'s exact shape: validate cheap fields, read `--content-file` for `park` (reuse `read_content_file`/`ContentFileError` unchanged — `park`'s maintenance content has the same size bound and FIFO/device concerns as `activateConfig`'s content), build the request, load `EngineConfig`/`ManagedRoot`/`compose::Access` the same way `run_activate_config` does, call `park::execute`/`unpark::execute`, map results/errors to `Response::success`/`Response::failure` the same way (including the `PostCommitRecordFailed` warning-response shape).

`capabilities.rs`: `operations` grows from `[&'static str; 8]` to `[&'static str; 10]`, appending `"ingress.park"` and `"ingress.unpark"`.

- [ ] **Step 1: Write failing tests**: a `tests/cli.rs`-level test (matching whatever pattern that file uses for `ActivateConfig`) that runs `ops-engine ingress park --domain ... --content-file ... --request-id ...` end to end against a fake/temp environment and asserts a successful `ingress.park` response envelope; same for `unpark` (no `--content-file`); a `capabilities.rs` test asserting `"ingress.park"` and `"ingress.unpark"` are both present in the advertised `operations` list.

- [ ] **Step 2: Run the relevant test binaries** — expect FAIL (commands/fields don't exist).

- [ ] **Step 3: Implement** the CLI variants, command functions, and capabilities update.

- [ ] **Step 4: Run `cargo test --all-features`** for the whole crate — expect PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/commands/ingress.rs src/commands/capabilities.rs
git commit -m "Wire ingress.park/ingress.unpark into the CLI and capabilities"
```

- [ ] **Step 6: Push** `operations-engine`'s `main` to `origin/main` (after confirming with the user, per this repo's standing convention of working directly on `main` — push is still an action visible to a shared remote, confirm before running `git push`). This is the point Global Constraints requires before starting Task 7.

---

## Task 7 — `website-control-panel`: target-aware backup writes for the 6 migrated call sites

**Files:**
- Modify: `src-tauri/src/commands/runtime_pool.rs` (`activate_ingress_route_via_engine_or`, its call to `ops_engine_activate_ingress_config_inner`)
- Modify: `src-tauri/src/commands/ops_engine.rs` (`ops_engine_activate_ingress_config_inner` and its Tauri-facing wrapper, `run_activate_ingress_config`)

**Interfaces:**
- Consumes: `operations-engine`'s new `--target live|backup` flag (Task 3), now available on `origin/main`.
- Produces: `ops_engine_activate_ingress_config_inner` gains a `target: RouteTarget` parameter (a new small client-side enum in `runtime_pool.rs` or `ops_engine.rs` — check which module already owns `ActivateConfigResult`'s client-side deserialization type and colocate there), which `run_activate_ingress_config` maps to a `("--target", "live"|"backup")` CLI arg (omit the arg entirely when `Live`, matching the engine's own `default_value_t`, so no behavior changes for any caller that doesn't yet know about `target`).

`activate_ingress_route_via_engine_or` (`runtime_pool.rs:1338`) currently does, when `ingress_activation_available` is true:

```rust
if path == live_ingress_route_path(&domain) {
    // ... engine write to Live ...
}
// Parked site (detail 2 above) - fall through to the legacy path.
legacy().await
```

Change the fall-through: when `path != live_ingress_route_path(&domain)`, check whether `path == maintenance_backup_path(&domain)` (the existing helper at `runtime_pool.rs:77`). If so, attempt the engine write with `target: RouteTarget::Backup` instead of falling through to `legacy()`. If the path matches neither (some third state this codebase doesn't otherwise produce today), fall through to `legacy()` unchanged — do not widen this function's behavior beyond the two known route-file identities.

- [ ] **Step 1: Write a failing test** in `runtime_pool.rs`'s test module (or wherever `activate_ingress_route_via_engine_or`'s existing tests for the "parked site falls back to legacy" behavior live — find and read them first) that asserts: given a domain whose `read_logical_ingress_route` resolves to the `.maintenance-backup` path, and an engine that reports `ingress_activation_available == true`, the call goes through the engine with `target: RouteTarget::Backup` rather than calling `legacy()`. (This will likely need a fake/mock at whatever seam the existing tests already use for `ops_engine_activate_ingress_config_inner` — follow that seam rather than introducing a new one.)

- [ ] **Step 2: Run the relevant test file** — expect FAIL.

- [ ] **Step 3: Implement** the `target` threading through both files as specified.

- [ ] **Step 4: Run `cargo test --lib` for `runtime_pool` and `ops_engine`** — expect PASS, including every pre-existing test for the 6 already-migrated call sites (they must be unaffected for non-parked domains, where `path == live_ingress_route_path` still takes the unchanged `Live` branch).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands/runtime_pool.rs src-tauri/src/commands/ops_engine.rs
git commit -m "Let the 6 migrated ingress call sites write to a parked domain's backup via the engine"
```

---

## Task 8 — Tauri/CLI wiring for `ops-engine ingress park`/`unpark`

**Files:**
- Modify: `src-tauri/src/commands/ops_engine.rs`

**Interfaces:**
- Consumes: `operations-engine`'s `ingress park`/`ingress unpark` CLI commands (Task 6).
- Produces: `pub(crate) async fn ops_engine_park_inner<R: tauri::Runtime>(server_id, domain, maintenance_content, idempotency_key, app_handle, pool, settings, cache) -> Result<ParkResult, GuiError>` and `pub(crate) async fn ops_engine_unpark_inner<R: tauri::Runtime>(server_id, domain, idempotency_key, app_handle, pool, settings, cache) -> Result<UnparkResult, GuiError>`, plus their `#[tauri::command]`-wrapped public counterparts (`ops_engine_park`/`ops_engine_unpark`), following `ops_engine_activate_ingress_config`/`_inner`'s exact shape (same enrollment check via `site_id_for`, same `require_operation` capability check against new operation-name constants `INGRESS_PARK_OPERATION = "ingress.park"` / `INGRESS_UNPARK_OPERATION = "ingress.unpark"`, same `with_domain_lock!` wrapping, same staging-file dance for `park`'s content via `stage_ingress_content`/`staged_content_path`/`discard_staged_content` — `unpark` needs no staged content file at all, since its CLI command takes no `--content-file`).

Client-side result types: define `ParkResult { domain: String, already_parked: bool, backup_sha256: String, activated_at_unix_secs: u64 }` and `UnparkResult { domain: String, content_sha256: String, activated_at_unix_secs: u64 }` matching the engine's camelCase JSON output (same pattern as the existing `ActivateConfigResult` client-side type — find and mirror it exactly, including its `#[derive(Deserialize)]`/`#[serde(rename_all = "camelCase")]` attributes).

Add `ingress_park_available`/reuse `ingress_activation_available`'s shape — actually, simplest: extend `ingress_activation_available` to take the operation name as a parameter (`operation: &str`) rather than hard-coding `INGRESS_ACTIVATE_CONFIG_OPERATION`, since `set_maintenance` (Task 10) needs the identical enrolled+capability check against `ingress.park`/`ingress.unpark` instead. Update its one existing call site accordingly.

- [ ] **Step 1: Write failing tests** covering: `staged_content_path`-equivalent uniqueness for park's staging file (mirror the existing `staged_content_path_is_unique_per_request_and_root_owned_dir` test); a test that `ops_engine_park_inner`/`ops_engine_unpark_inner` call `ops_engine::invoke` with `&["ingress", "park"]`/`&["ingress", "unpark"]` and the right argv shape (mirror `run_activate_ingress_config`'s existing test coverage, if any — if that function has none, write these as the first coverage for both).

- [ ] **Step 2: Run the relevant test file** — expect FAIL.

- [ ] **Step 3: Implement** the two Tauri commands, their `_inner` functions, result types, and the `ingress_activation_available` generalization.

- [ ] **Step 4: Run `cargo test --lib ops_engine`** — expect PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands/ops_engine.rs
git commit -m "Add Tauri wiring for ops-engine ingress park/unpark"
```

---

## Task 9 — Split `set_maintenance` into engine-or-legacy

**Files:**
- Modify: `src-tauri/src/commands/runtime_pool.rs` (`set_maintenance`, new `set_maintenance_legacy`)
- Modify: `src-tauri/src/commands/sites.rs` (`sites_maintenance` Tauri command)

**Interfaces:**
- Consumes: `ops_engine_park_inner`/`ops_engine_unpark_inner` (Task 8), generalized `ingress_activation_available` (Task 8).
- Produces: `set_maintenance`'s current body (verbatim) becomes `set_maintenance_legacy` (same parameters, `pub(crate) async fn`, `async` body unchanged). A new `set_maintenance` dispatches:

```rust
pub(crate) async fn set_maintenance<R: tauri::Runtime>(
    server_id: i64,
    filename: &str,
    domain: &str,
    enable: bool,
    reason: Option<&str>,
    contact_email: Option<&str>,
    app_handle: tauri::AppHandle<R>,
    pool: tauri::State<'_, SshPool>,
    settings: tauri::State<'_, crate::db::SettingsCache>,
    cache: tauri::State<'_, crate::ops_engine::CapabilityCache>,
) -> Result<(), GuiError> {
    if enable {
        if ingress_activation_available(server_id, domain, &pool, &cache, INGRESS_PARK_OPERATION).await {
            let maintenance_content = build_maintenance_route_caddyfile(
                domain, reason.unwrap_or("maintenance"), contact_email,
            );
            return ops_engine_park_inner(server_id, domain.to_owned(), maintenance_content, None, app_handle, pool, settings, cache)
                .await
                .map(|_| ());
        }
    } else if ingress_activation_available(server_id, domain, &pool, &cache, INGRESS_UNPARK_OPERATION).await {
        return ops_engine_unpark_inner(server_id, domain.to_owned(), None, app_handle, pool, settings, cache)
            .await
            .map(|_| ());
    }
    set_maintenance_legacy(server_id, filename, domain, enable, reason, contact_email, &pool, &settings).await
}
```

(Exact parameter order/threading to match this file's established `async fn` conventions — the sketch above is the behavior, not necessarily final formatting.)

Note the `enable` branch checks `INGRESS_PARK_OPERATION` availability and the disable branch checks `INGRESS_UNPARK_OPERATION` — these can differ in principle (an older engine might advertise one but not the other, though in practice both ship together in this plan), so checking the specific operation each branch needs, rather than one combined check, fails closed correctly for a partially-upgraded engine.

`sites_maintenance` (`sites.rs:1075`) gains `app_handle: tauri::AppHandle` and `cache: State<'_, CapabilityCache>` parameters (both already threaded through the Tauri app for the 6 other migrated commands — find how `disable_basic_auth`'s Tauri wrapper obtains them and match it exactly) and passes them into `set_maintenance`.

- [ ] **Step 1: Write a failing test**: given an enrolled domain with `ingress.park`/`ingress.unpark` capability available, `set_maintenance(enable: true, ...)` calls the engine path (assert via whatever mock/fake seam Task 7's test used) rather than `set_maintenance_legacy`; given a non-enrolled domain, it calls `set_maintenance_legacy` unchanged; a byte-for-byte regression test that `set_maintenance_legacy`'s behavior (the pre-existing `set_maintenance` test coverage, if any exists — find it) is completely unchanged by the rename.

- [ ] **Step 2: Run the relevant test file** — expect FAIL.

- [ ] **Step 3: Implement** the split and the `sites_maintenance` signature change.

- [ ] **Step 4: Run `cargo test --lib`** for `runtime_pool` and `sites` — expect PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands/runtime_pool.rs src-tauri/src/commands/sites.rs
git commit -m "Route set_maintenance through the engine's ingress.park/unpark when available"
```

---

## Task 10 — Docker-backed workflow test: full park → mutate-while-parked → unpark cycle

**Files:**
- Create or modify: `src-tauri/src/workflow_tests/ops_engine_ingress_maintenance.rs` (new file, following `ops_engine_ingress_activate_config.rs`'s exact harness/fixture pattern — read that file in full before writing this one, since it establishes the Docker-backed fixture stack conventions: enrolling a site, standing up the ingress container, issuing real `ops-engine` CLI calls over the fixture's SSH-equivalent transport)
- Modify: `src-tauri/src/workflow_tests/mod.rs` (register the new test module, if such registration is required — check how `ops_engine_ingress_activate_config` is registered)

**Scenario**, against a real enrolled site with a real live `.caddyfile`:

1. Call `set_maintenance(enable: true, ...)`. Assert: live Caddyfile now serves the maintenance page (fetch it through the fixture's Caddy container, as `ops_engine_ingress_activate_config.rs` already does for its own assertions); `.maintenance-backup` exists and matches the pre-maintenance content.
2. Call `disable_basic_auth` (or whichever of the 6 migrated call sites is simplest to seed a precondition for in this fixture — check which one `ops_engine_ingress_activate_config.rs` already exercises and reuse that setup) against the still-parked site. Assert: the *backup* file's content changed to reflect the mutation; the *live* maintenance page is completely unaffected (byte-for-byte identical to step 1's).
3. Call `set_maintenance(enable: false, ...)`. Assert: live Caddyfile now serves the mutated content from step 2 (not the original pre-maintenance content — proving the mutation-while-parked actually took effect); `.maintenance-backup` no longer exists.
4. As a differential check against the legacy path's known-correct behavior: run the same three-step sequence against a **non-enrolled** site (forcing every call through `set_maintenance_legacy`/the raw-SSH fallbacks) and assert the final live content is identical to step 3's enrolled-site result. This is the test that actually proves the engine path and the legacy path converge on the same outcome, not just that the engine path doesn't crash.

- [ ] **Step 1: Write the test** per the scenario above, following `ops_engine_ingress_activate_config.rs`'s fixture setup/teardown conventions exactly.

- [ ] **Step 2: Run `cargo test --lib workflow_tests:: -- --test-threads=1`** (the full ordered suite — per Global Constraints, an isolated single-test run against the shared fixture stack is unreliable) — expect PASS. If it fails, treat every failure as a real finding (either a bug in Tasks 1–9's implementation or a wrong assumption in this plan's design) — do not adjust the test to match broken behavior.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/workflow_tests/ops_engine_ingress_maintenance.rs src-tauri/src/workflow_tests/mod.rs
git commit -m "Add a Docker-backed workflow test for the full park/mutate/unpark cycle"
```

---

## Task 11 — Sync `operations-engine/PLAN.md`'s Phase 8 section

**Files:**
- Modify: `operations-engine/PLAN.md` (Phase 8 section, currently reading "6 of ~28 ingress call sites migrated, rest deferred")

Update the status line and delivered-summary paragraph to record: `ingress.park`/`ingress.unpark` shipped; `ingress.activateConfig` gained `target: live|backup`; `set_maintenance` (the 7th call site) now migrated; commit SHAs and "both pushed" status for both repos, following the exact prose shape the pilot's and batch-2's entries already use (read the current Phase 8 section in full before editing, to match its voice and level of detail rather than writing a differently-styled addition next to it).

- [ ] **Step 1: Update `PLAN.md`** with the new paragraph, in the same style as the existing pilot/batch-2 entries.
- [ ] **Step 2: Commit**

```bash
git add PLAN.md
git commit -m "Sync Phase 8 status: maintenance-mode park/unpark is shipped"
```

- [ ] **Step 3: Push both repos** (`operations-engine main`, `website-control-panel master`) after confirming with the user.

---

## Out of scope for this plan

- Migrating any of the remaining ~21 non-maintenance-related `activate_caddyfile` call sites (`create_site`, `rename_site`, `migrate_site_runtime_impl`, etc.) — unrelated to maintenance-mode, already called out as out of scope in the pilot/batch-2 plans for their own reasons.
- Reconciliation/orphan-detection awareness of `.maintenance-backup` files left behind by a crashed `park`/`unpark` (Task 4's Step 1 "orphaned backup" test covers the one specific race this plan's own operations can cause; a broader reconciliation sweep for maintenance-backup files is a separate concern, parallel to how `reconciliation.rs`'s existing scope excludes `set_maintenance` today per the pilot plan's own "out of scope" section).
- Any UI/UX change to how `website-control-panel`'s maintenance-mode toggle is presented — this plan is purely about which write path (engine vs. legacy) executes underneath, not the feature's user-facing behavior, which must be unchanged before and after.
