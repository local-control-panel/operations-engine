# Operations Engine implementation plan

Status: active  
Current phase: 7 — release and production hardening. Phases 0-6 are all
complete; Phase 7's engine-side work (reproducible builds, signed
checksummed artifacts, `engine install`/`engine rollback`, compatibility
matrix, redaction review, docs, opt-in rollout procedure) is done and
tested, but the phase is not complete — see its own section for what
remains (the control-plane half of pinned installation, and rotating off
the TEST-ONLY signing key before a real release).
Last updated: 2026-09-08

This file is the shared implementation plan for Operations Engine. It is the
authoritative source for what we build next, in what order, and what must be
true before a phase is considered complete.

The README explains the project. Documents under `docs/` describe individual
contracts and milestones. This file coordinates their execution.

## Working agreement

All contributors and coding agents should follow these rules:

1. Read this file, `docs/protocol.md`, and the relevant milestone before making
   architectural or protocol changes.
2. Work on the earliest incomplete phase unless a documented dependency or
   production issue requires otherwise.
3. Complete one small, testable vertical slice at a time.
4. Do not advertise commands or features through `capabilities` before they are
   implemented and tested.
5. Do not implement a mutating operation before its inputs, invariants, commit
   point, failure states, and recovery behavior are documented.
6. Keep protocol changes backward-compatible within a protocol version.
7. Update this plan in the same change whenever phase status, scope, or an
   architectural decision changes.
8. Keep unfinished work explicit. Do not mark a phase complete because its
   happy path works.

## Definition of done

A work item is complete only when all applicable requirements are satisfied:

- code is formatted and passes Clippy with warnings denied;
- unit and integration tests cover public behavior and failure paths;
- stdout contains only the documented protocol output;
- errors and warnings use stable machine-readable codes;
- inputs are validated at the server execution boundary;
- logs and responses do not expose secrets;
- documentation and `capabilities` match the implementation;
- Linux behavior is tested in CI;
- recovery behavior is tested for mutations;
- any new persistent on-disk state a mutation creates per request/attempt
  (a state file, an index entry, anything keyed by `RequestId` or similar)
  has a bounded, tested retention policy before it ships — not "add
  pruning later." `transaction::prune::prune_completed`, wired into
  `mutation::preflight::run`, already covers everything routed through the
  shared preflight path (`transactions/`, `transactions/idempotency/`); a
  genuinely new kind of per-request state store outside that path needs
  its own retention, reviewed the same way. (Two stores — idempotency
  index, transaction state — grew unbounded from Phase 3 through Phase 8
  before this was caught and fixed on 2026-09-08; this line exists so a
  third one doesn't.)
- `cargo check` passes with the minimum supported Rust version.

Required local validation:

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo +1.85.0 check --all-features
```

## Phase 0 — project direction

Status: complete

Delivered:

- neutral project name: Operations Engine;
- initial binary name: `ops-engine`;
- separate repository and release lifecycle;
- Linux-only production target;
- CLI-first architecture without a persistent daemon;
- SSH as the initial transport used by a separate control plane;
- Git deploy/rollback selected as the first mutation pilot.

Decisions that remain reversible before the first public release:

- adding a stable product prefix to the repository and binary names;
- selecting the final distribution and installation mechanism;
- changing the minimum Rust version when required by supported platforms.

## Phase 1 — foundation

Status: complete

Goal: establish a small, reliable read-only CLI and freeze the minimum protocol
behavior needed by future operations.

Completed:

- Rust crate and `ops-engine` binary;
- command parsing with JSON as the initial output format;
- protocol response envelope;
- `version` command;
- `capabilities` command;
- `doctor` command with platform and dependency checks;
- unit and CLI integration tests;
- formatting, lint, test, and minimum-Rust CI jobs;
- protocol and contribution documentation;
- explicit `INTERNAL_SERIALIZATION_ERROR` response instead of a panic when an
  operation result cannot be encoded;
- stable protocol error and warning code enums with documented safe-detail
  rules;
- explicit `doctor` distinction between successful diagnostics (`ok`) and host
  readiness (`result.ready`);
- release-safe build target and optional Git commit metadata;
- deterministic Linux `doctor` integration coverage with controlled fake
  dependencies;
- reusable subprocess execution with explicit arguments, timeout,
  cancellation, concurrent stream draining, and retained-output bounds.

Exit criteria:

- the response envelope has no panic-based serialization path;
- protocol and exit-status semantics are documented and tested;
- diagnostic results are deterministic in integration tests;
- subprocess execution has explicit time and output bounds;
- the initial read-only command surface is safe to tag as an alpha release.

## Phase 2 — site and filesystem model

Status: complete

Goal: define the trusted local model required by deploy and rollback before any
mutation is implemented.

Work items, in order:

Completed:

- inventoried the control plane's current Git deploy/rollback lifecycle,
  safeguards, state ownership, and migration sequence;
- selected a canonical lowercase UUID `siteId` independent of domain;
- defined root-owned manifests and configured trusted filesystem roots;
- defined the proposed release, transaction, lock, credential, and audit layout;
- created validation types for site identifiers, full Git object IDs, trusted
  roots, and site-relative paths;
- added traversal, NUL, malformed identifier, and symlink-escape tests;
- selected a stable `current` relative symlink with same-directory rename as
  the future atomic activation commit point;
- documented the required one-time runtime identity, Caddy root, and
  `open_basedir` migration;
- finalized the daemonless MVP sudo and per-site subprocess ownership boundary;
- added capability-based filesystem access for race-safe operations beneath an
  opened trusted root;
- implemented strict typed engine config and site manifest parsing;
- added schema, site mismatch, overlapping root, file ownership, file mode,
  policy, and capability-root tests.

Exit criteria:

- untrusted input cannot select a path outside configured roots;
- filesystem layout and ownership rules are documented;
- site identity is stable across domain changes;
- validation types are reusable and fully tested;
- no deploy subprocess is started in this phase.

## Phase 3 — transaction framework

Status: complete

Goal: build reusable mutation infrastructure without yet exposing deploy or
rollback as a capability.

Completed:

- added validated `RequestId` (canonical, non-nil UUID; names transaction
  state files) and `IdempotencyKey` (bounded, printable-ASCII, caller-supplied
  retry token) types in `src/transaction/mod.rs`;
- implemented per-site locking (`src/transaction/lock.rs`): atomic
  create-if-absent lock files via a new `ManagedRoot::create_new`
  (exclusive-create) primitive, a default 15-minute time-based stale bound
  (`DEFAULT_STALE_AFTER`), one bounded reclaim retry, and an RAII guard that
  releases on drop. Staleness is purely time-based (no holder-process
  liveness check); see the `ponytail:` note in `lock.rs` for the upgrade
  path if faster recovery is ever needed;
- implemented persisted transaction state (`src/transaction/state.rs`):
  `TransactionState` (request ID, idempotency key, operation, status,
  timestamps, outcome) with guarded `InProgress` -> `Committed`/`Failed`
  transitions (a second transition is rejected, not silently applied), plus
  `create` (exclusive first write), `save` (atomic update), and `load`. Added
  a new `ManagedRoot::write_atomic` primitive (same-directory temp file +
  rename) that `save` uses and that later state or config writers can reuse.
  (Looking up a transaction by idempotency key was deferred here and
  implemented separately below, once it became blocking for this phase's own
  exit criteria.);
- defined named progress steps and JSON Lines framing
  (`src/protocol/progress.rs`): a `Step` (`&'static str`, always an
  engine-chosen constant, never request input), a `start`/`ok`/`failed`
  `ProgressStatus`, and a `Line` enum (`{"type":"progress",...}` /
  `{"type":"result",...}`) matching the README's documented framing.
  `JsonLinesWriter` flushes every line immediately so a slow or
  disconnecting reader observes progress as it happens, and its `finish`
  method consumes the writer so at most one `Result` line can ever be
  emitted through it. Not yet wired into `cli`/`lib.rs` dispatch or
  `capabilities`'s `jsonLinesProgress` flag — there is still no long-running
  operation to drive it; that lands with Phase 4 deploy;
- defined the commit point and cancellation rules as a type-state pair in
  `src/transaction/commit.rs`: `PreCommit::check` returns `Err(Cancelled)`
  once `CancellationToken::cancel()` has been called, for operation code to
  poll between abortable pre-commit steps; `PreCommit::commit(self)`
  consumes it and returns a `PostCommit` that has no cancellation check at
  all. "Cancellation cannot abort a committed mutation" is therefore a
  compile-time guarantee for any operation built on this type, not a
  runtime convention someone can forget;
- implemented the redacted-diagnostics half of subprocess execution
  (`src/process.rs`): `error_code`/`spawn_error_code` turn the runner's
  `ProcessTermination`/`ProcessRunError` into the stable codes
  `docs/subprocess.md` already documented but that had no code behind them,
  and `SubprocessDiagnostics` is a `SUBPROCESS_FAILED`-details-shaped
  summary (program name, exit code, timeout/cancelled flags, truncation
  flags) built only from the runner's own bookkeeping — it has no field
  captured stdout/stderr bytes could occupy, so it cannot leak them by
  construction. The bounded-execution half (explicit args, timeout,
  cancellation, concurrent draining, output caps) already shipped in
  Phase 1;
- defined mutation audit events (`src/transaction/audit.rs`): `AuditRecord`
  wraps a schema version, timestamp, and one `AuditEvent`
  (`MutationStart`/`Progress`/`Result`/`LockRecovered` — the last covers the
  one recovery path that exists so far, the stale-lock reclaim from
  `transaction::lock`). Events carry only stable identifiers and codes,
  never an error message or other free-text field, matching the `details`
  allowlist in `docs/protocol.md`. Appended via a new
  `ManagedRoot::append` (create-if-missing, O_APPEND, `fsync`) to
  `audit/events.jsonl` as one JSON Lines record per call;
- implemented the idempotency-key lookup this phase's own exit criteria
  require (`src/transaction/idempotency.rs`): `claim(root, key, requestId)`
  registers a fresh attempt via `ManagedRoot::create_new`'s atomic
  create-if-absent and reports `Claimed`, or — if another attempt already
  owns the key — `AlreadyClaimed(RequestId)` so the caller loads that
  attempt's `TransactionState` and returns its original outcome instead of
  doing the work again. Keys are looked up by a dependency-free 64-bit
  FNV-1a hash of the key bytes (stable across Rust versions, unlike
  `std::hash::DefaultHasher`); a stored copy of the key is checked on every
  read, so a hash collision is reported as `HashCollision` rather than ever
  returning a different caller's outcome. Idempotency-key *retention* (when,
  if ever, an old claim is pruned) is still open and deferred to Phase 4,
  where a real operation exists to size it against;
- added `tests/transaction.rs`, an integration suite that exercises
  locking, state, the commit boundary, progress framing, audit, and
  idempotency together the way a future operation will combine them, since
  none exists yet to test through: two-OS-thread lock contention,
  a full success lifecycle (state ends `Committed`, lock is free
  afterward, JSON Lines carries exactly one `result` line, three audit
  lines are written), cancellation observed and acted on before the commit
  point vs. requested-but-ignored after it, a forgotten/crashed lock guard
  left as `InProgress` state that the next attempt can see and reclaim, and
  a retried idempotency key resolving to the original request's state
  instead of creating a second one.

Work items: none — all delivered above.

Exit criteria (all met; see `tests/transaction.rs`):

- two mutations cannot run concurrently for the same site;
- retrying an idempotent request cannot create duplicate work;
- interrupted operations leave enough state for deterministic recovery;
- progress and final responses can be parsed without human text;
- tests cover process interruption on both sides of the commit point.

## Phase 4 — Git deploy pilot

Status: complete

Goal: deliver one complete, recoverable Git deployment operation using the
contracts from phases 2 and 3.

The detailed contract checklist lives in
[`docs/milestones/001-git-deploy-rollback.md`](./docs/milestones/001-git-deploy-rollback.md).

Completed:

- froze the `site.deploy` request/result schema (`src/deploy.rs`):
  `DeployRequest` composes the already-validated `SiteId`, `GitCommitSha`,
  `RequestId`, and `IdempotencyKey` types with one `parse` that reports
  which field failed; `DeployResult` is release ID, previous release ID,
  activated commit, and activation time — nothing else, so it cannot carry
  secrets or subprocess output. Added `ReleaseId`, defined as *equal to* the
  deploying transaction's `RequestId` (`From<RequestId>`) rather than a
  second generated identifier — deploy makes at most one release per
  transaction, so the release, its transaction state, and its audit trail
  stay joinable on one ID. Not wired into `cli`/`capabilities` yet — that is
  item 9, after preflight through cleanup exist;
- implemented preflight (`src/deploy/preflight.rs`), composing the Phase 3
  primitives into the first real caller they didn't have yet:
  `open_site_state` descends an engine-wide state `ManagedRoot` into a
  fresh, capability-scoped root for exactly one site (new
  `ManagedRoot::open_managed_dir`), so a path-construction bug in later
  deploy code cannot reach another site's lock, state, or audit log — the
  OS-level directory handle has no authority to. `preflight::run` then, in
  order: resolves an idempotency-key replay first (so a retry never takes
  the site lock or writes new state at all), acquires the per-site mutation
  lock, creates `InProgress` transaction state, and appends the
  `MutationStart` audit event — returning either `Outcome::Proceed(Admitted
  { lock, state })` for the caller to continue into fetch/stage/switch, or
  `Outcome::Replay(RequestId)` naming the original attempt to load instead.
  Every step here only touches engine-owned bookkeeping (locks/,
  transactions/, audit/); nothing here can touch `releases/` or `current`.
  Manifest/repository-policy loading is deferred to the item below
  (fetch/resolve), which needs it anyway and would otherwise load it twice.
  No disk-space preflight check yet, either: std has no portable free-space
  API and cap-std doesn't expose one; `rustix` (already a transitive
  dependency via cap-std) has `fs::statvfs` on Linux if/when a real staging
  failure makes this worth adding as a direct dependency;
- implemented revision resolution (`src/deploy/resolve.rs`):
  `resolve_allowed_revision` runs one bounded `git ls-remote <url>
  refs/heads/<branch>...` (explicit argv via the Phase 1 runner, no shell)
  and accepts the request only if the requested `GitCommitSha` is the
  *current tip* of one of the manifest's allowed branches — a syntactically
  valid object ID is not authorization by itself, matching
  `docs/site-model.md`. This is a pure read against the remote: no clone, no
  local working tree, so it needs no per-site UID/GID drop (that becomes
  required starting at the next item, which does write into a site-owned
  directory). An optional SSH identity file pins `core.sshCommand` for this
  one call; the path must already be engine-derived (an installed
  credential), never raw request input, since git itself shell-interprets
  that value when invoking `ssh`. Tested against a real local `git`
  repository (`git ls-remote` accepts a plain filesystem path), not a mock —
  covers an authorized branch tip, an unrelated revision, a revision on a
  non-allow-listed branch, and an unreachable remote;
- found and fixed an argument-injection gap in the item above via automated
  security review: `resolve_allowed_revision` passed `remote_url` straight
  after `ls-remote` with no `--`, so a manifest `repository.url` value
  starting with `-` (a config-schema field that only bans control
  characters, not a leading dash) could be parsed by `git` as a flag —
  `--upload-pack=<command>` is a real remote-code-execution primitive.
  Fixed by rejecting a leading `-` outright and adding `--` before the
  positional URL regardless; added a regression test asserting the
  rejection happens before any subprocess starts;
- added general privilege-dropping to the Phase 1 subprocess runner itself
  (`ProcessRequest::run_as(uid, gid)` in `src/process.rs`, Unix-only), not
  just to deploy: `run()` now calls `Command::uid`/`gid` when set. Every
  future build/Git subprocess reuses this one mechanism rather than each
  operation growing its own. Supplementary groups are not yet explicitly
  cleared (`setgroups`) — documented as a gap in the method's own doc
  comment;
- implemented staging (`src/deploy/staging.rs`), the first item that
  writes real content into a site-owned directory: `resolve_site_identity`
  turns the manifest's `siteUser` into a numeric uid/gid via `id -u`/`id
  -g` (bounded subprocess, not a raw NSS/FFI call); `prepare` then
  exclusively creates `sites/<siteId>/releases/<releaseId>/` (new
  `ManagedRoot::create_dir`, fails instead of reusing an existing
  directory), `chown`s it to that identity *before* anything else touches
  it, clones the resolved branch via `run_as` so `git` never runs at the
  engine's own privilege level, and finally verifies the checked-out HEAD
  still equals the revision `resolve` authorized — closing the TOCTOU
  window where the remote branch could have moved in between.
  **Test-coverage gap, by explicit user decision**: this environment has no
  root and cannot create a second real Unix user, so the tests resolve and
  use the *current* user's own identity throughout (chown-to-self and
  `run_as` with one's own uid/gid are always permitted, unlike a genuine
  cross-user drop). Every mechanism is exercised for real except the one
  thing only root can prove — that a *different* uid/gid is actually
  enforced end to end. Verify that specifically before trusting this
  against a real multi-tenant deployment;
- implemented bounded post-clone validation (`src/deploy/validate.rs`):
  `validate_staged_release` runs `git fsck --no-progress --no-dangling`
  (object-database integrity) and `git status --porcelain` (working tree
  must exactly match `HEAD`, empty output required) against the staged
  release, both bounded and both `run_as` the site identity like every
  other subprocess touching a site-owned directory. Deliberately scoped to
  what is generic across *any* Git deploy — not a build or test step, which
  is site/framework-specific and out of scope for this pilot per the
  README's "Scope" section; a manifest-driven build step, if ever added, is
  new scope for a later milestone, not implied by this item.
  `StagedRelease` also grew an `absolute_path` field so this and the next
  item (the atomic switch) don't each re-resolve it independently;
- implemented the atomic switch (`src/deploy/activate.rs`), the one commit
  point of a deploy: `activate` creates a new relative symlink
  (`releases/<releaseId>`) under a unique temp name and `rename`s it over
  `sites/<siteId>/current` in the same directory — the rename call is the
  single line that makes a deploy visible; everything before it is still
  abortable. Reads the previous `current` target first so the result can
  report `previousReleaseId`, but refuses to guess at an existing target
  that isn't shaped exactly like `releases/<releaseId>` rather than
  silently reporting "no previous release." Added three new generic
  `ManagedRoot` primitives this needed (`symlink`, `read_link`, `rename`),
  each with its own filesystem.rs test, plus three activate.rs tests: first
  activation, a second activation's atomic swap (and that no `.tmp-*` link
  survives it), and the unrecognized-target refusal;
- assembled the full pipeline and persisted its result
  (`src/deploy/execute.rs`): `execute` orders preflight → identity →
  resolve → stage → validate → activate → persist, threading one
  `CancellationToken`-backed `transaction::commit::PreCommit` through every
  pre-activation step (`.check()` between each) and calling `.commit()`
  only once `activate` has actually returned success — the true POSIX
  commit point, not merely "the last step before it," since a failure
  inside `activate` itself before its own rename call still means nothing
  changed (see the module doc for why). A shared `fail` helper records
  every pre-commit failure the same way: transition `TransactionState` to
  `Failed` with a stage-appropriate `ErrorCode`, save it, append a
  `Result` audit event, return the original error unchanged, and let the
  lock guard drop normally. An idempotency replay now does real work: it
  loads the original attempt's `TransactionState` and returns its stored
  `DeployResult` (success) or stable code/message (failure) — a request
  still `InProgress` replays as `Conflict` rather than silently starting a
  second attempt. A post-commit persistence failure gets its own
  `PostCommitRecordFailed { result, cause }` so a successful deployment can
  never be silently lost even if writing its record fails. Added
  `tests/deploy.rs`, exercising the assembled pipeline end to end against a
  real local Git "remote": full success (release activated, `current`
  resolves to a real checkout), idempotent replay (retry returns the
  original release, stages nothing new), and a rejected revision (fails
  without activating anything, lock is free immediately afterward for a
  following successful attempt) — substantially covering the later "add
  end-to-end tests" item already; only disconnect-during-operation
  scenarios remain there, which need a real transport to test honestly and
  are deferred to Phase 6 client integration.
  `resolve_allowed_revision` also changed to return the matched branch
  name (`Result<String, Error>`, was `Result<(), Error>`) — staging needs
  to know exactly which branch to clone, not just that authorization
  passed.

Completed:

- implemented bounded release retention (`src/deploy/cleanup.rs`):
  `prune_old_releases` keeps the `DEFAULT_RETAIN_COUNT` (5) most recently
  created releases plus whichever one is currently active — regardless of
  its own age or position — and best-effort-removes the rest (a failure to
  remove one specific release is skipped, not propagated; cleanup must
  never turn a successful deploy into a reported failure). Age is the
  release directory's own filesystem modification time, not a
  cross-reference against `TransactionState.finishedAt` — a documented
  approximation, not exact accounting. Wired into `execute::execute` as
  the last, best-effort step after a successful deploy. New
  `ManagedRoot::remove_dir_all` backs the actual removal;
- advertised `site.deploy` (`src/commands/site.rs`, wired through a new
  `ops-engine site deploy` CLI subcommand): loads the root-owned engine
  config and site manifest from their documented paths
  (`/etc/operations-engine/config.json`,
  `/etc/operations-engine/sites/<siteId>.json`), builds a `DeployContext`,
  and maps `deploy::execute::DeployError` to the protocol envelope via the
  `DeployError::protocol` method added in the previous item — including a
  new `WarningCode::TransactionRecordIncomplete` for the
  `PostCommitRecordFailed` case, so a deploy that actually succeeded but
  failed to persist its own record still reports `ok: true` with a
  warning, never a false failure. `capabilities` now lists `"site.deploy"`
  and sets `features.mutations: true`; `cancellation` and
  `jsonLinesProgress` stay `false` — the internal plumbing for both exists
  (`transaction::commit`, `protocol::progress`) but neither is wired to
  the CLI process lifecycle (no signal handler calls
  `CancellationToken::cancel()`; `--output` has no JSON Lines variant), so
  advertising either now would violate the "don't advertise before
  implemented" rule. Picking a content root when more than one is
  configured is still unsolved generically — `run_deploy` requires exactly
  one and fails safely (`INTERNAL`) otherwise, a known, narrow gap.
  Smoke-tested against the real compiled binary (`capabilities`,
  `site deploy --help`, an invalid site ID, and a valid request against a
  dev host with no engine config installed) in addition to the automated
  suite.

Work items: none — all delivered above.

Completed (continued):

- added the end-to-end disconnect test (`website-control-panel`,
  `src-tauri/src/workflow_tests/ops_engine_deploy_rollback.rs`:
  `ops_engine_deploy_recovers_from_a_disconnect_mid_call`), the one item
  that needed a real transport to test honestly and was therefore deferred
  to Phase 6 landing first. It builds a second, genuinely-handshaked SSH
  session by hand (not through the normal connect path) so a cloned raw
  `TcpStream` handle stays available alongside it, swaps that session into
  the pool in place of the healthy one, dispatches a real `site deploy`
  against the real engine, and forcibly closes the cloned socket a few
  milliseconds in — deterministically interrupting the in-flight blocking
  read regardless of how fast the real pipeline happens to run (a fixed
  short session timeout was tried first and proved unreliable: the whole
  pipeline against a tiny local Git fixture over loopback can finish in
  under 100ms). The interrupted call is asserted to fail at the transport
  layer; a retry with the same idempotency key, after reconnecting, is
  asserted to converge to exactly one activated release, and a second
  retry with the same key is asserted to replay that identical outcome
  rather than redoing work. Ran clean five times in a row (no flake from
  the timing-sensitive fault injection). Along the way this surfaced a
  second, separate recovery layer the test also had to account for:
  `website-control-panel`'s own remote domain lock
  (`commands::site_lock`, a lease with a 180s TTL, wraps every
  `ops_engine_*` call) is held for the duration of the call and had no
  chance to release when the connection died — this engine's own
  idempotency has nothing to do with that lock, it lives entirely in the
  calling app. Production self-heals it the same way any lease does (the
  lock is reclaimable on the next acquire once its TTL expires); the test
  releases it directly rather than sleeping three real minutes.

Exit criteria:

- failed pre-commit work leaves the active release unchanged — met, see
  `tests/deploy.rs`;
- post-commit failures report that deployment changed state — met,
  `PostCommitRecordFailed` plus the `TransactionRecordIncomplete` warning;
- disconnects have a documented and tested recovery path — met, see
  `ops_engine_deploy_recovers_from_a_disconnect_mid_call` above;
- repeated idempotent requests return the original outcome — met;
- the control plane needs one structured operation rather than a shell
  sequence — met, `ops-engine site deploy` is that one operation.

## Phase 5 — Git rollback pilot

Status: complete

Goal: switch safely to a known retained release using the same transaction,
locking, audit, and recovery machinery.

Completed:

- generalized Phase 4's `deploy::preflight` into `mutation::preflight`
  (`src/mutation/preflight.rs`), the first shared module between two
  mutating operations: `preflight::run` now takes a `RequestId`, an
  `Option<&IdempotencyKey>`, and an `&'static str` operation name instead of
  a deploy-specific request type, so rollback (and any future mutation)
  reuses the exact same idempotency-replay, site-lock, transaction-state,
  and `MutationStart`-audit sequence rather than a second copy of it.
  `deploy::execute` was updated to call the moved module with no behavior
  change (its own tests still pass unmodified);
- defined which release identifiers are eligible for rollback
  (`src/rollback/eligibility.rs`): `resolve_retained_release` accepts a
  `ReleaseId` only if `sites/<siteId>/releases/<releaseId>/` already exists
  as a directory this engine itself created, resolved and containment
  checked through the same `TrustedRoot::resolve_existing` deploy's staging
  step uses — never a bare path join. A syntactically valid `ReleaseId` is
  not itself authorization, matching `docs/site-model.md`'s "rollback never
  trusts client-side history as its authorization source." A pre-existing
  symlink escape and a genuinely absent release are both reported as the
  same `Error::NotFound` — the caller does not need to distinguish them,
  and distinguishing them in the response would leak filesystem structure
  for no operational benefit;
- validated retained release integrity by reusing
  `deploy::validate::validate_staged_release` verbatim, not a rollback-owned
  copy: that function was already generic over "a Git working tree at this
  path, run as this identity" and never assumed the directory had just been
  freshly cloned. See the decision log for why this was reused rather than
  forked;
- implemented the atomic switch by reusing `deploy::activate::activate`
  verbatim as well: its signature only ever needed a `TrustedRoot`,
  `SiteId`, and `ReleaseId` — nothing about "was this release just staged"
  — so rollback's commit point is the identical same-directory
  symlink-rename `deploy::activate`'s own tests already cover. No new
  atomic-switch code exists for rollback at all;
- preserved forward recovery information: `RollbackResult` reports both
  `releaseId` (the new target) and `previousReleaseId` (the source, exactly
  as `activate::activate` already returns it). A successful rollback still
  runs the same best-effort `deploy::cleanup::prune_old_releases` a deploy
  runs, passing the new target as `active_release` — this does not reset
  "recency" for the release just switched away from (age is still each
  release directory's own creation-time modification time, an
  approximation already documented in `deploy::cleanup`), so a release
  remains a valid rollback target immediately afterward, but its
  eligibility for a *later* rollback is bounded by the same retention count
  a subsequent deploy would apply — a deliberate reuse of deploy's existing
  approximation, not a new guarantee invented for rollback. Verified end to
  end in `tests/rollback.rs` by rolling back and then rolling forward again
  between two real releases;
- assembled the pipeline (`src/rollback/execute.rs`): `execute` orders
  preflight → identity → eligibility → validate → activate → persist,
  threading the same `CancellationToken`-backed `PreCommit`/`PostCommit`
  boundary deploy uses, with its own `fail`/`replay` helpers mirroring
  `deploy::execute`'s byte for byte (same `Failed`-transition, same
  `PostCommitRecordFailed` carrying the real result so a successful
  rollback can never be silently lost, same `Replayed`/`ReplayInProgress`
  idempotency handling);
- added `tests/rollback.rs`, an end-to-end suite against a real local Git
  "remote" mirroring `tests/deploy.rs`'s style, covering every failure case
  the milestone's rollback section lists: a successful rollback and a
  subsequent roll-forward (proving the source release is not invalidated),
  rollback to a missing release, rollback to a corrupted release (dirty
  working tree), concurrent rollback attempts on one site serialized by the
  site lock (mirroring `tests/transaction.rs`'s two-thread contention
  pattern, using a real background `thread::scope` call against the full
  `execute()` pipeline rather than only the shared preflight primitive),
  an interrupted/crashed rollback whose `InProgress` state survives on disk
  and whose same-key retry is reported as a conflict rather than silently
  redone or lost, and a retried idempotency key after a successful rollback
  replaying the original result without a second switch;
- advertised `site.rollback` (`src/cli.rs`, `src/commands/site.rs`): a new
  `ops-engine site rollback --site-id <uuid> --release <releaseId>
  --request-id <uuid> [--idempotency-key <key>]` subcommand following the
  identical config-loading and error-mapping pattern `site deploy` uses,
  including a `TransactionRecordIncomplete` warning on the same
  post-commit-persistence-failure case. `capabilities` now lists
  `"site.rollback"` alongside `"site.deploy"`. Smoke-tested against the
  compiled binary (`capabilities`, `site rollback --help`, and an invalid
  site ID) in addition to the automated suite.

Work items: none — all delivered above.

Exit criteria (all met; see `tests/rollback.rs`):

- rollback cannot select arbitrary filesystem content — met,
  `eligibility::resolve_retained_release` only trusts engine-created
  directories, never client-supplied paths or history;
- the previous active release remains identifiable — met,
  `RollbackResult::previous_release_id`;
- an interrupted rollback is recoverable deterministically — met: state
  persisted before any switch is attempted, a same-key retry against an
  `InProgress` original is reported as `Conflict` rather than duplicating
  or losing work;
- audit and result data identify both source and target releases safely —
  met, both are stable `ReleaseId`s; the audit `Result` event carries only
  the request ID and error code, never free text, matching
  `docs/protocol.md`'s `details` allowlist.

Unlike Phase 4, rollback has no operation-specific disconnect exit
criterion of its own (see Phase 4's section for why that one is blocked on
Phase 6 transport) — everything Phase 5 requires was testable, and tested,
without a live SSH transport.

Inherited, not new, test-coverage gap: rollback's identity resolution and
`validate::validate_staged_release` call run as the site identity exactly
like deploy staging/validation do, and this environment still has no root
to test a genuine cross-user drop with — see Phase 4's staging entry for
the same, already-documented limitation. Nothing rollback-specific was
added here; it simply inherits the gap by reusing deploy's own identity and
validation code.

## Phase 6 — client integration and compatibility

Status: complete

Goal: integrate one real control plane while keeping client and engine releases
independent.

Completed (all in `website-control-panel`, not this repo):

- protocol-version window defined and enforced:
  `check_protocol_version` (`src-tauri/src/ops_engine/mod.rs`) accepts
  exactly version 1 and rejects both lower and higher, run on every
  envelope before any operation-specific handling — tested for the
  accept case and both reject directions;
- version and capability negotiation implemented in the client: every
  `opsEngine:*` call goes through `capabilities` first, cached per
  `server_id` for the life of the SSH connection
  (`ops_engine::CapabilityCache`, invalidated on reconnect in
  `commands/ssh.rs`) rather than re-fetched per call;
- incompatible engines are rejected before any mutation begins — the
  protocol-version check happens ahead of dispatch, not inside a specific
  operation;
- progress and stable error codes are mapped to client state: typed
  `#[derive(Deserialize)]` envelopes (`ops_engine/envelope.rs`) replace
  hand-written output parsing, and `opsEngine:log` (`ProgressStepEvent`)
  carries progress to the renderer (still unconsumed by any UI — that is
  tracked separately, not a Phase 6 gap);
- older-client/older-engine and older-engine compatibility are tested
  directly (`workflow_tests/ops_engine_deploy_rollback.rs`:
  `older_engine_build_genuinely_lacks_site_rollback`,
  `both_vendored_engine_builds_report_protocol_version_one`) against two
  real vendored engine binaries built from pinned commits
  (`docker/test-server/build-ops-engine.sh`). The newer-client/older-
  engine gap called out in `docs/ops-engine-comparison.md` (no way yet to
  target a specific installed binary) was closed separately in
  `website-control-panel` commit `bd22b8c`. The newer-engine/older-client
  direction has no real coverage yet, honestly: this repo has shipped
  exactly one protocol version so far, so there is nothing newer to test
  against. Revisit once a protocol v2 exists;
- bootstrap behavior when the engine is absent is documented and tested:
  a missing/not-on-PATH `ops-engine` returns "ops-engine is not installed
  (or not on PATH) on this server", asserted in `ops_engine/mod.rs`'s own
  test suite;
- SSH round trips, failure recovery, and orchestration complexity were
  compared against the previous shell-based path in
  `docs/devdocs/ops-engine-comparison.md`, measured against the real
  Docker test server rather than estimated (deploy: 2 round trips → 1;
  rollback: 1 → 1, same, but gains transactional idempotent replay the
  old path never had) — including the honest added costs (a new
  capability cache, a required enrollment step, elevated `sudo`
  invocation, two vendored binaries for compatibility testing).

Exit criteria:

- neither repository requires a simultaneous merge or release — met, the
  two repos ship and version independently;
- incompatibility fails before a mutation begins — met;
- the pilot demonstrates measurable operational or maintenance
  improvement — met, see the comparison doc's "Net read".

## Phase 7 — release and production hardening

Status: pending

Goal: make installation, upgrade, downgrade, and recovery safer than manual
binary replacement.

Suggested starting point: reproducible builds, since every other item in
this phase operates on a real build artifact (checksums, signing, pinned
install, atomic upgrade/downgrade all need one to exist first) — nothing
else here can start honestly before it.

Work items:

- reproducible Linux AMD64 and ARM64 builds — delivered
  (`.github/workflows/release.yml`: tag-triggered, `cargo build --release
  --locked` on the pinned `1.85.0` toolchain, `SOURCE_DATE_EPOCH` from the
  tagged commit, native runners for both `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu`, no cross-compilation);
- checksums and signed release artifacts — delivered (`SHA256SUMS` computed
  over both binaries, signed with minisign; verified on the client side by
  `src/engine/verify.rs` before any checksum from the manifest is trusted);
- explicit, pinned installation through the control plane — **half
  delivered**. The engine side is done and tested: `ops-engine engine
  install --version X.Y.Z --request-id <uuid> [--idempotency-key <key>]`
  and `ops-engine engine rollback --request-id <uuid>
  [--idempotency-key <key>]` exist, go through the same
  `mutation::preflight` locking/idempotency/audit machinery and
  `PreCommit`/`PostCommit` commit boundary as `site deploy`/`site
  rollback`, and are advertised through `capabilities`. The control-plane
  side — `website-control-panel` actually calling these commands, resolving
  which version to request, and replacing
  `docker/test-server/build-ops-engine.sh`'s current build-from-source
  fixture with a real signed-release download — is explicitly out of scope
  for this plan and needs its own separate plan once a real tagged release
  exists to point at;
- atomic upgrade and downgrade with previous-binary recovery — delivered
  (`engine install`/`engine rollback`; a same-directory
  write-temp-then-atomic-rename of the verified binary via
  `ManagedRoot::write_new_executable`, never a window where
  `/usr/local/bin/ops-engine` is missing; the previous binary is retained
  under the engine state root's `versions/` store and read directly by
  rollback — see the decision log for the two deviations from the original
  design this involved). The final whole-branch review (see the decision
  log) found this was not actually recoverable end to end: a newly
  activated binary was never proven to run, and the first install on any
  host retained nothing, so `engine rollback` — the only sudo-permitted
  recovery path — could itself be the broken binary with no fallback. Both
  gaps are now closed: `engine install` smoke-tests the staged binary
  through the bounded process runner before activation and rejects it
  (leaving the running binary untouched) if it won't run or reports the
  wrong version, and the first install on an unmanaged host retains the
  binary it replaces (self-reported version, or a `pre-managed` sentinel);
- release compatibility matrix — delivered (`docs/compatibility.md`);
- redaction and bounded-log review — delivered; see the decision log entry
  below for what was checked and found;
- package and incident-recovery documentation — delivered
  (`docs/release.md`, `docs/incident-recovery.md`);
- opt-in rollout to test servers before broader deployment — delivered as a
  documented procedure (`docs/incident-recovery.md`), exercised by 10
  end-to-end integration tests in `tests/engine.rs` against a local HTTP
  fixture server with a real minisign-signed test fixture (including a
  three-version install-then-install-then-rollback sequence that exercises
  `prune_superseded_version`); full suite is 149/149. Rollout against a
  real production test server has not happened yet — blocked on the
  TEST-ONLY signing key being rotated to a real one (see the decision log).

Exit criteria:

- downloaded artifacts are verified before execution;
- failed upgrades retain a runnable previous binary;
- release provenance and compatibility can be audited;
- production rollout and rollback procedures have been exercised.

These are satisfied for the engine's own install/rollback pipeline, which is
now built, tested, and documented — including, after the final-review fix
round above, "failed upgrades retain a *reachable* previous binary," not
just a retained one. The phase is not marked complete because "explicit,
pinned installation through the control plane" is only half delivered (see
above) and no real release has been cut yet (the committed signing key is
TEST-ONLY — see the decision log).

### Known follow-ups (non-blocking)

Raised by the final whole-branch review and its fix-round re-review;
none were load-bearing for this phase's exit criteria. All closed
2026-09-08. One item (`previous_version`'s `pre-managed` parser
tolerance) was entirely about `website-control-panel` code that does not
exist yet, not this repo — moved to `local-control-panel/docs`'s
`operations-engine/migration-status.md` ("Заведено за по-късно") rather
than tracked here, where a public reader has no way to act on it.

- ~~`docs/protocol.md`'s stable-error-code table is missing
  `ARTIFACT_NOT_RUNNABLE`/`ARTIFACT_FETCH_FAILED`/`ARTIFACT_VERIFICATION_FAILED`
  and the two new warning codes~~ — closed: both tables added (`4f5529f`).
- ~~no minimum-glibc / tested-distribution floor is recorded anywhere
  (`docs/compatibility.md`)~~ — closed: documented as implied by the
  `ubuntu-latest`/`ubuntu-24.04-arm` build runners (currently 24.04,
  glibc 2.39), explicitly not independently tested (`4f5529f`).
- ~~a staged `versions/<version>/` directory is not cleaned up on a
  post-staging failure~~ — closed: `fail_staged` best-effort removes it on
  every post-staging error path, covered by two new test assertions
  (`b279879`).
- ~~`tests/fixtures/engine/regenerate.sh` couples fixture regeneration to
  whichever minisign key is currently committed — regenerating fixtures
  after the production key rotation will require the production secret
  key, which must never be used for this~~ — closed
  (2026-09-08): `tests/fixtures/engine/` now has its own dedicated,
  permanently-test-only keypair, decoupled from `release/minisign.key`.
  `verify::fetch_and_verify` and `InstallContext` gained a
  `verify_public_key` parameter (same pattern as `release_base_url`) so
  production checks against `release/minisign.pub` and every test checks
  against the fixture directory's own `minisign.pub` — regenerating
  fixtures never touches, and after key rotation still won't need, the
  real release-signing secret. All fixtures re-signed under the new key,
  285/285 tests passing.
- ~~the `https_only` loopback exemption in `src/engine/fetch.rs` ... has
  one narrow gap: a URL of the form `http://127.0.0.1:80@evil.test/...`
  passes the exemption via userinfo-with-port~~ — closed: userinfo is now
  stripped before the host:port split, with regression tests for the
  reported bypass shape and a "real userinfo in front of a real loopback
  host is still loopback" case (`21b957d`).
- ~~cancellation during the smoke probe reporting as `ARTIFACT_NOT_RUNNABLE`
  rather than `CANCELLED`~~ — closed: `smoke::Error` gained a `Cancelled`
  variant, checked before the generic non-success branch, mapped to
  `ErrorCode::Cancelled` (`2f7899c`).
- ~~dead `ExpectedArtifact::filename`~~ — inspected, not closed: it is a
  `pub` field with no non-test reader today, not a defect; left as-is
  rather than removed as unrequested API surface reduction.
- ~~`rollback.rs`'s `.expect()` on an `install.state` value~~ — inspected,
  not found: `state::load`'s result is already exhaustively matched
  (`Ok(Some)`/`Ok(None)`/`Err`) with no panicking unwrap on the loaded
  value; may have been fixed by an earlier, untracked commit, or the
  original review meant a different call site than located here.

## Phase 8 — selective expansion

Status: in progress — 7 of ~28 ingress call sites migrated, rest deferred

Additional workflows are considered only after the Git pilot succeeds. Each
workflow requires its own milestone document and measurable reason to move into
Operations Engine.

**"Atomic Caddy and site configuration changes" — pilot, a second
migration batch, and engine-side maintenance-mode modeling all
shipped; 7 of ~28 call sites migrated.**
Milestone docs: `docs/superpowers/plans/2026-09-03-ingress-config-activation-pilot.md`
(pilot, 6 tasks), `website-control-panel`'s own
`docs/superpowers/plans/2026-09-04-ingress-config-migration-batch-2.md`
(batch 2, 7 tasks), and
`docs/superpowers/plans/2026-09-05-ops-engine-maintenance-mode.md`
(maintenance-mode park/unpark, 11 tasks spanning both repos) — all
done and task-reviewed (pilot and batch 2 also got a separate
whole-branch review pass). `operations-engine` `main` at `e3335e8`,
pushed. `website-control-panel` `master` at `f9cdf73` as of this
writing — not yet pushed; confirm push status in that repo before
treating this sub-project as fully landed there.
Delivered: one new `ingress.activateConfig` operation (pilot), wired to
6 of `website-control-panel`'s ~28 `activate_caddyfile`/
`activate_caddyfile_checked` call sites — `disable_basic_auth` (pilot,
proof of concept) plus `update_raw_ingress_route` (2 callers),
`enable_access_log`, `set_security_headers`, `set_redirects`,
`set_ip_acl` (batch 2, via a shared client-side helper,
`activate_ingress_route_via_engine_or`, extracted from the pilot's
proven logic). No further `operations-engine` changes needed for
either batch; the operation and its contract were unchanged from the
pilot through batch 2. Two integration bugs found and fixed during the
pilot (engine config schema v1→v2 was write-once instead of
reconverging; `sudo` reset `HOME` and broke Compose-stack resolution
for every elevated call); one correctness bug found and fixed during
batch 2's final review (`enable_access_log`'s transform silently
dropped a validation its legacy sibling performed, so enrolled and
non-enrolled sites disagreed on a malformed access-log block).
The maintenance-mode sub-project then gave `ingress.activateConfig` a
`target: live|backup` field, letting those same 6 call sites write to
a parked domain's `.maintenance-backup` file — hash-guarded, atomic,
no Caddy validate/reload, since that file is never imported by the
live Caddyfile — instead of falling back to legacy while a site is
parked. Two new operations, `ingress.park` (snapshots live to backup
on first park, then activates a maintenance page onto live, one
transaction) and `ingress.unpark` (restores backup to live and deletes
the backup, one transaction), reuse the existing `activate::activate`/
preflight/transaction/audit pipeline rather than duplicating it; a new
`ErrorCode::IngressNotParked` covers unpark-when-not-parked. CLI
(`ingress park`/`ingress unpark`) and `capabilities` wiring shipped for
both. On the `website-control-panel` side, `set_maintenance` (the 7th
call site) now dispatches through the engine's park/unpark when
available, falling back to its exact previous raw-SSH behavior
otherwise — mirroring how `disable_basic_auth` was migrated in the
pilot — plus new Tauri commands wrapping `ingress.park`/
`ingress.unpark`, and a Docker-backed workflow test proving the full
park→mutate-while-parked→unpark cycle converges on the same final
result as the pure-legacy path (a real byte-level comparison of both
paths' final live route content, normalized for domain). The Docker
test-server's vendored `ops-engine` binary pin was bumped from
`28897b1` to `e3335e8` so the fixture actually advertises the new
operations — necessary infrastructure work discovered mid-plan, not
originally scoped. One correctness bug found and fixed during review
before this shipped: `ingress.park`'s orphaned-backup cleanup was
over-generalized and could have deleted a domain's last-good backup on
a double-fault (the live write failed and its own rollback also failed
to restore live), stranding the domain parked with no recovery path;
narrowed to exclude that specific failure mode. None of this
sub-project's own testing could be executed against real Docker in
this session (no Docker daemon was available in the sandbox); every
task was verified by rigorous inspection against the real,
already-committed source instead — real Docker execution against the
bumped fixture is deferred to whoever next runs the suite on a machine
with Docker available.
The remaining call sites (`enable_basic_auth`,
`activate_site_process_config_checked`, `create_site`,
`restore_deleted_site`, `migrate_site_runtime_impl`, `rename_site`,
`rollback_rename_commit`) and `reconciliation.rs`'s overlapping
remediation paths stay out of scope — see that plan's own "Out of
scope" section for why each one specifically.
A second engine operation, `runtime.activateConfig`, now exists
alongside `ingress.activateConfig`: `create_site`, `restore_deleted_site`,
`migrate_site_runtime_impl`, `rename_site`, and `rollback_rename_commit`
write a per-site runtime-service Caddyfile fragment
(`website-control-panel`'s `RUNTIME_CONTAINER_CONFIG_DIR`), structurally
outside `ingress_root`'s coverage — hence a new trusted root
(`EngineConfig::runtime_root`, `CONFIG_SCHEMA_VERSION` bumped 2→3) and a
new operation rather than a variant on the existing one, since the target
container genuinely varies per request instead of choosing between two
fixed files. Unlike `ingress.activateConfig`'s single host-wide lock,
this one locks per `runtime_id` — two different runtime pools share
nothing a reload could race on, so serializing across them would cost
throughput for no correctness benefit; see `runtime_config::execute::
open_runtime_config_state`'s doc comment. `operations-engine` side only
(`src/runtime_config/`, `src/site.rs`'s new `RuntimeId`, CLI/capabilities
wiring, 40 new tests, 281/281 passing, clippy and fmt clean) — wiring it
into `website-control-panel`'s 6 call sites across those 5 functions
(`migrate_site_runtime_impl` has two) is a separate, not yet
started increment.

Potential candidates:

- atomic Caddy and site configuration changes — **pilot in progress, see above**;
- stack status and reconciliation — **`ingress.reconcile` shipped, first slice** (`docs/milestones/002-ingress-reconcile.md`; `src/ingress/reconcile.rs`, 295/295 passing, clippy and fmt clean). Whole-`ingressRoot` sweep for two of `website-control-panel`'s `reconciliation.rs::sweep`'s seven orphan classes - `TempFile` and both `RedundantBackup`/`RecoverableBackup` variants, the two that need only the ingress root itself. Deliberately narrowed, not everything at once: `OrphanedExecConfig`/`RouteWithoutExecConfig` need a `runtimeRoot` cross-reference this slice's single-root scan doesn't do; `StaleLock` addresses `website-control-panel`'s own pre-engine `/etc/wcp/locks/` coordination directory, which this engine has no visibility into and shouldn't; `IdlePool` needs the site registry (which sites reference which runtime pool), which lives in that app's own SQLite. `runtime.reconcile` (the near-identical follow-up for `runtimeRoot`'s own temp/backup orphans) and wiring `website-control-panel`'s call site are both separate, not yet started increments;
- backup and restore — **`db.restore` shipped, audit-trail scope only** (runs the existing `mariadb`/`psql` restore client against an already-on-disk dump via argv-only subprocess execution instead of a raw SSH shell string; no `HashGuard`, no pre-restore snapshot, no rollback - a destructive import has no "expected prior content" to guard and this was an explicit scope decision, not an oversight, deferring real transactional safety - snapshot + verify + auto-rollback-on-failure - as a materially larger follow-up on par with this engine's original deploy/rollback pipeline). Required two small additions to `process.rs` (`run_with_stdin_file`, `run_piped`) so a large dump file streams into the client via direct fd handoff/OS-level pipe rather than being buffered through this process - the first two callers here that need input larger than what `ProcessLimits`' bounded output capture was ever sized for;
- narrowly scoped scheduled jobs — **`cron.installTab` shipped** (host-wide, hash-guarded whole-crontab replacement via a staged file + `crontab <path>`, no `docker compose exec`/`TrustedRoot` involved - the first mutation this engine runs as a bare host subprocess rather than against a container or a managed root). Deliberately narrow: only the engine's own host user's crontab, not an arbitrary named user's (`website-control-panel`'s general-purpose per-user cron admin UI stays on its existing raw-SSH path - a materially broader privilege surface this engine's site-scoped model isn't built for);
- Docker Compose stack configuration (`website-control-panel`'s `docker.rs::compose_write`, an arbitrary-stack `docker-compose.yml` write with no validation and no hash-guard today) — **`compose.activateConfig` shipped** (`src/compose_config/`, mirroring `runtime_config`'s validate/write/rename/reload/restore-on-failure shape, `docker compose config` standing in for `caddy validate` and `docker compose up -d` for `caddy reload`, argv-only `docker` subprocesses via `process::run` rather than `compose::exec`, which is specifically `docker compose exec` into the one fixed WCP stack). Locks per `stack_name`, same reasoning as `runtime.activateConfig`'s per-`runtime_id` lock. No `EngineConfig` schema change: unlike every other trusted root here, the compose root (`website-control-panel`'s `COMPOSE_DIR = "~/compose"`) is inherently relative to whichever account this process runs as, not a fixed operator-configured absolute path, so it is resolved dynamically at request time via a new `compose::compose_root_dir` (mirroring that module's existing `compose_base_dir` resolution for the one fixed WCP stack) rather than sourced from config. `operations-engine` side only, 324/324 passing, clippy and fmt clean — wiring `website-control-panel`'s `compose_write` is a separate, not yet started increment.

Interactive terminals, arbitrary shell execution, general file browsing, and
live log streaming remain outside the structured privileged API unless a new
architecture and threat model explicitly justify them.

## Decision log

Record decisions here when they affect more than one milestone. Detailed ADRs
may later live under `docs/decisions/` and be linked from this table.

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-09-02 | Use the neutral working name Operations Engine and binary `ops-engine`. | Avoid coupling the server component to a client product name that may change. |
| 2026-09-02 | Keep the engine in a separate repository. | It has a distinct Linux target, security boundary, release cadence, and compatibility lifecycle. |
| 2026-09-02 | Start with a CLI over SSH and no daemon. | Prove the structured execution boundary before adding a persistent privileged service. |
| 2026-09-02 | Separate protocol version from semantic release version. | Allow independent compatibility decisions and releases. |
| 2026-09-02 | Use Git deploy/rollback as the first mutation pilot. | It exercises locking, staging, atomic switching, idempotency, progress, and recovery. |
| 2026-09-02 | Use an opaque canonical UUID as `siteId`; domain is mutable metadata. | Renaming a domain must not rename security, transaction, or release state. |
| 2026-09-02 | Resolve request paths through root-owned manifests and opened directory capabilities. | Caller-provided absolute paths and lexical checks are not a sufficient mutation boundary. |
| 2026-09-02 | Activate releases by renaming a prepared relative symlink over a stable `current` path. | Caddy and runtime consumers keep one document root while activation has one explicit commit point. |
| 2026-09-02 | Invoke the daemonless mutation CLI through a dedicated sudo entry and drop Git/build children to the site UID/GID. | The engine needs bounded privileged coordination without granting a privileged shell or running application code as root. |
| 2026-09-02 | Per-site lock staleness is a pure 15-minute time bound (`DEFAULT_STALE_AFTER`), not a holder-process liveness check. | Keeps recovery deterministic and portable (no `/proc` dependency) for a first pass; revisit only if a real workflow needs faster recovery than 15 minutes. |
| 2026-09-02 | Idempotency-key lookup is a per-site, on-disk FNV-1a hash index with a stored-key check on read; key *retention* is not yet decided. | The exit criterion "retrying an idempotent request cannot create duplicate work" was blocking in Phase 3 itself, so the lookup half had to be resolved now; retention has no forcing operation yet and stays open for Phase 4. |
| 2026-09-02 | A deployed release's `ReleaseId` equals the `RequestId` of the transaction that created it, rather than a separately generated identifier. | Deploy makes at most one release per transaction; reusing the ID keeps the release directory, transaction state, and audit trail joinable on one value instead of three. |
| 2026-09-02 | Site UID/GID is resolved via the `id` subprocess, and privilege-dropping lives on `ProcessRequest` (`run_as`) in the shared runner, not only in deploy code. | Keeps every subprocess call — including future build steps — on the same bounded, argv-only, no-shell, no-raw-FFI discipline instead of a one-off mechanism per operation. |
| 2026-09-02 | Deploy staging was implemented and merged with cross-user privilege-dropping untested (only self-drop, tested for real). | Explicit user choice: build the real code now rather than deferring it, with the root-only test gap called out in `PLAN.md` and each affected file rather than silently shipped. Must be exercised under an actual multi-user Unix host before production use with more than one site owner. |
| 2026-09-02 | Generalized `deploy::preflight` into `mutation::preflight`, parameterized by `RequestId`/`Option<&IdempotencyKey>`/operation name instead of a deploy-specific request type. | Rollback needed the identical idempotency-replay/lock/state/audit sequence; a second copy would let the two drift apart silently, and the primitive was already operation-agnostic in everything but its parameter type. |
| 2026-09-02 | Rollback reuses `deploy::validate::validate_staged_release` and `deploy::activate::activate` verbatim rather than forking rollback-owned copies. | Neither function ever depended on "freshly staged" — both were already generic over "a Git working tree at this path" / "a `SiteId` and `ReleaseId`" respectively. Forking them would only create two integrity checks and two atomic-switch implementations to keep in sync for no behavioral difference. |
| 2026-09-02 | Rollback runs the same best-effort `deploy::cleanup::prune_old_releases` after a successful switch, passing the new target as `active_release`; it does not reset or otherwise special-case "recency" for the release just switched away from. | Keeps retention behavior identical and predictable across both mutation types instead of inventing rollback-specific retention semantics; a rolled-back-from release stays retained immediately afterward purely because cleanup already keeps the most recent N regardless of which operation is calling it. |
| 2026-09-02 | `RollbackResult` has no `commit` field, unlike `DeployResult`. | Deploy's `commit` echoes an already-validated request input (`DeployRequest::revision`); rollback's request carries a `ReleaseId`, not a commit, so there is no equivalent input to echo without an extra unrequired subprocess call. `releaseId`/`previousReleaseId` alone already satisfy the exit criterion to identify both releases safely. |
| 2026-09-03 | Phase 6 marked complete; Phase 4's disconnect-test item reclassified from "blocked" to "actionable, not yet written". | `website-control-panel` already has a full, tested client integration (protocol negotiation, capability cache, typed envelopes, older-engine compatibility test, comparison doc) — this repo's `PLAN.md` had not been updated to reflect it. The one remaining Phase 6 gap (newer-engine/older-client coverage) is structurally untestable until a protocol v2 ships, so it is recorded as deferred rather than blocking. |
| 2026-09-03 | Phase 4 marked complete; a real, deterministic disconnect test was added in `website-control-panel` rather than raced against a fixed session timeout. | A fixed short libssh2 session timeout proved unreliable against this fixture (the deploy pipeline can finish in under 100ms over loopback). Forcibly closing a cloned raw `TcpStream` handle mid-call interrupts the in-flight blocking read deterministically, independent of how fast the real pipeline runs. This also surfaced that `website-control-panel`'s own remote domain lock (a separate, lease-based recovery layer, unrelated to this engine's idempotency) is held for the call's duration and needs its own TTL-based reclaim after a disconnect — already handled in production, now accounted for in the test too. |
| 2026-09-03 | Redaction and bounded-log review of `src/engine/install.rs`, `src/engine/rollback.rs`, and `src/engine/verify.rs` found nothing to fix. | Every `ErrorCode`/message pair in all three files' `protocol()` methods is a static string literal (`.to_owned()` of a fixed string, or a straight pass-through of a previously-stored, already-static `Replayed { code, message }` from a prior attempt) — none interpolate a URL, filesystem path, HTTP response body, or fetched-artifact byte. The wrapped lower-level errors that do carry more detail (`fetch::Error(ureq::Error)`, which can embed a request URL in its own `Debug` output) are matched on by variant only, inside `protocol()`, and never formatted with `{:?}`/`{}` into a response, log line, or audit record anywhere in `src/commands/engine.rs`. The full URL concern is structurally closed, not just avoided by convention: `install.rs`/`verify.rs` only ever build a request URL from the fixed `GITHUB_RELEASES_BASE` constant (`src/commands/engine.rs`) or, in tests, `InstallContext::release_base_url`, and no code path echoes the assembled URL back into an error. |
| 2026-09-03 | `InstallContext::release_base_url` is a field on the context struct, populated from the fixed `GITHUB_RELEASES_BASE` constant in production, rather than a hardcoded constant inside `install.rs`/`verify.rs`. | The only reason it is a parameter at all is so tests can point it at a local fixture server; every real call site still passes the one compiled-in GitHub Releases base. |
| 2026-09-03 | Engine version retention is a fixed two-slot `active`/`previous` pair (`src/engine/state.rs`), not a configurable-count history like site releases. | Deliberate, recorded in the design spec (`docs/superpowers/specs/2026-09-03-release-pipeline-design.md`, §2 item 8): the exit criterion only ever required "a runnable previous binary," singular, so a longer history would be unused capability. |
| 2026-09-03 | The engine binary is activated by writing the verified bytes directly into `/usr/local/bin/ops-engine` via a same-directory write-temp-then-atomic-rename (`ManagedRoot::write_new_executable`), not the symlink-based `versions/<version>/ops-engine` + `current`-symlink pattern the original spec described for site releases. | `/usr/local/bin` and the engine's state root are different trusted roots, and `ManagedRoot::symlink`'s target is deliberately typed as same-root-relative — no primitive exists for a symlink crossing trusted roots, and this design doesn't otherwise need one. Still exactly one atomic `rename(2)`, so there is still never a window where the binary is missing. Full reasoning recorded in `docs/superpowers/specs/2026-09-03-release-pipeline-design.md` and `docs/superpowers/plans/2026-09-03-engine-install-rollback.md`'s "Deviation from the spec" section; not re-explained here. |
| 2026-09-03 | The committed minisign public key (`release/minisign.pub`) and its signing counterpart are a deliberately-marked TEST-ONLY keypair with a publicly-known password, not a production key. | Needed to build and test the full signed-release pipeline end to end before a real keypair exists. Must be rotated to a real, secret-held production keypair — both the committed public key and the `MINISIGN_SECRET_KEY`/`MINISIGN_KEY_PASSWORD` GitHub Actions secrets — before the first real release is ever cut; see `src/engine/verify.rs` and `docs/release.md`'s "Signing key" section. The `MINISIGN_SECRET_KEY`/`MINISIGN_KEY_PASSWORD` secrets themselves also still need to be configured in the repo's Settings — a manual, one-time step — before `.github/workflows/release.yml` can run to completion on a real tag push. |
| 2026-09-03 | Final whole-branch review of Phase 7 (commits `95ec377..b0576ba`) found 2 Critical + 7 Important issues — a clippy lint failing the pinned toolchain's CI gate, and, more substantively, that a newly activated binary was never proven runnable while `engine rollback` (the only sudo-permitted recovery path) ran through that same binary, plus no retention on a host's first install, unbounded HTTP fetch under the engine-global lock, ambient proxy/HTTP fallback, a state-write race and silent failure, zero test coverage of the upgrade/prune path, and a release workflow that both leaked the signing secret into a rendered script and accepted malformed/mismatched tags. All 9 were fixed in one fix round (commits `b0576ba..6287726`) and independently re-verified clean by a second reviewer (149/149 tests, up from 138). | The whole-branch pass is what caught these — each was invisible from any single task's own diff (the lock/state-write ordering spans three tasks; the missing recovery path only appears when the code, `docs/site-model.md`, and `docs/incident-recovery.md` are read together). Fixing the signing key's secret-handling gap and the tag-validation gap before any real tag is ever pushed, and fixing the recovery-path gap before any real server is ever upgraded, converts each from a design promise into a checked property. The fix round also required regenerating the TEST-ONLY minisign keypair (`release/minisign.pub`) — the secret half was never available outside the machine that originally built it — with the same publicly-documented password; nothing was ever released under the old key. Ten Minor findings from the review and thirteen more from the re-review were deliberately left unfixed (see Phase 7's "Known follow-ups" list); none are load-bearing for this phase's exit criteria. |
| 2026-09-04 | `CONFIG_SCHEMA_VERSION` bumped 1 -> 2, adding a required `ingressRoot` to `/etc/operations-engine/config.json`; a v1 config is rejected outright rather than defaulted. | `ingress.activateConfig` writes into a directory that is not any site's content root, so it needed a fourth trusted root, and a root the engine only *sometimes* has is not a boundary — a defaulted or optional `ingressRoot` would mean the operation's containment guarantee depended on whether an operator had happened to set it. Rejecting a v1 config outright rather than accepting it with a guessed root is the same fail-closed rule the rest of the config applies. The cost is that every host and every client-side config writer must be updated together; `website-control-panel` absorbs that with a self-heal keyed on the `"engine configuration is unavailable"` message (see `commands::CONFIG_UNAVAILABLE_MESSAGE`, whose exact text is now a pinned cross-repo contract with a test). |
| 2026-09-04 | `ingress.activateConfig` takes one host-wide lock (`ingress/locks/mutation.lock`), not a per-site or per-domain one. | The resource the operation actually mutates is shared: `caddy reload` reloads the whole imported config set, so two domains activating concurrently can each observe the other's half-applied file, and a reload failure caused by domain B can push domain A's activation down its rollback path and restore a file that was never the problem. `website-control-panel` locks per domain, which is finer than the thing being shared and therefore does not serialize the actual race. Ingress config changes are operator-paced, so the throughput a host-wide lock costs is worth the race it removes. Recorded here because it deliberately diverges from the client's existing lock granularity. |
| 2026-09-04 | `HashGuard` has exactly two wire-reachable states — `Absent` and `Sha256` — and no unguarded/`Unchecked` overwrite path at all. Omitting `--expected-hash` means "assert no live file exists", not "skip the check". | The pilot's only real caller (`disable_basic_auth`) always has a prior file it just read, so it always has a genuine hash to send; nothing needed silent-overwrite semantics. Leaving an unchecked path on the wire would have shipped exactly the silent-overwrite default the hash guard exists to remove, and the ~27 unmigrated `activate_caddyfile` call sites in `website-control-panel` are precisely the population that would have reached for it by habit. Cost if this is ever wrong: a future caller that genuinely wants unguarded overwrite has to add that path back deliberately — cheap, reviewable, and safer than the reverse. |
| 2026-09-07 | `runtime.activateConfig` locks per `runtime_id` (`runtime-config/<id>/locks/mutation.lock`), not host-wide like `ingress.activateConfig`. | The resource a reload actually shares is everything imported by *that one runtime-service container's* Caddyfile — every domain currently on that same runtime pool — the same "the lock must match what a reload really touches" reasoning behind `ingress`'s own host-wide lock. But unlike ingress's single shared container, two different runtime pools (`fp1-php83` vs `fp1-php84`) share nothing: serializing activations across them would cost throughput for a race that cannot occur. Per-`runtime_id` is coarser than per-domain (matches what a reload touches) and finer than host-wide (matches what it does not) — deliberately diverges from both `ingress.activateConfig`'s and the client's own granularity, recorded here for the same reason the ingress lock choice was. |
| 2026-09-08 | `runtime.reconcile` takes `--runtime-id` and sweeps only that pool's `<runtime_id>/` subdirectory of `runtimeRoot`, reusing `runtime_config::execute::open_runtime_config_state` verbatim — not a whole-`runtimeRoot` sweep across every pool in one call with a new, coarser lock. | `runtimeRoot` nests one subdirectory per pool (unlike `ingressRoot`, which `ingress.reconcile` sweeps flat), so some scoping decision was unavoidable. A host-wide reconcile lock would serialize a sweep of one pool against a concurrent `runtime.activateConfig` on a completely unrelated pool — exactly the throughput-for-no-correctness-benefit cost the 2026-09-07 per-`runtime_id` lock entry above already rejected for `activateConfig` itself; introducing it here for reconcile would contradict that reasoning for no new benefit. Per-`runtime_id` costs the caller having to loop the call across every known pool to sweep a whole host, but that enumeration is site-registry knowledge (`website-control-panel`'s SQLite) this engine already deliberately doesn't have — the same reason `IdlePool` reconciliation stays client-side per `002`'s "out of scope" section. Full reasoning in `docs/milestones/003-runtime-reconcile.md`. |
| 2026-09-08 | Idempotency-key retention (open since Phase 3) is a 7-day age-based sweep (`transaction::prune::DEFAULT_COMPLETED_RETENTION`), run from `mutation::preflight::run` rather than per-operation. Transaction state files (`transactions/<requestId>.json`, never addressed as an open decision at all) get the same fix in the same change — both had grown unbounded, forever, since Phase 3/4 with nobody noticing until an explicit audit. | `preflight::run` is the one place every mutating operation (site- and engine-scoped alike) already passes through, so wiring the sweep there — not in each of the 9 operation modules — makes it structurally impossible for a future operation to add unbounded per-request state by forgetting to call a prune function; see the new "Definition of done" bullet. 7 days covers a plausible offline-client retry without letting state accumulate over a server's real lifetime. Pruning a transaction with an idempotency key removes the idempotency-index entry *before* the transaction state file, not after: if a retry ever races the sweep, the failure mode is "treated as a fresh request" (mirrors work) rather than "`StateError::NotFound`" (hard error) — the friendlier of the two, and consistent with this engine's general preference for graceful degradation over failing closed on a stale-but-recoverable condition. `audit/events.jsonl` is deliberately not addressed here: append-only audit trails are unbounded by design, and bounding one is a real, separate decision (rotate vs. cap vs. leave it), not a prune loop. |

## Open decisions

Resolve these in the phase where they first become blocking:

- final product prefix, if any;
- canonical site identity;
- configuration source and trusted filesystem roots;
- service user and sudo allowlist;
- exact deploy commit mechanism;
- cancellation behavior after disconnect;
- audit-event destination;
- protocol compatibility window;
- release signing and distribution mechanism.

## How to update this plan

When work advances:

1. mark individual delivered items under the active phase;
2. do not change a phase to complete until every exit criterion is satisfied;
3. move `Current phase` only after the prior phase is complete;
4. add new scope to the appropriate future phase instead of silently inserting
   it into current implementation work;
5. record cross-cutting decisions in the decision log;
6. update `Last updated` in the same change.
