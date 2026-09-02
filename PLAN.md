# Operations Engine implementation plan

Status: active  
Current phase: 4 — Git deploy pilot
Last updated: 2026-09-02

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

Status: in progress

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

Work items, in order:

1. Clean up according to bounded retention rules.
2. Add end-to-end disconnect tests (success/failure/retry already covered
   by `tests/deploy.rs`).
3. Advertise `site.deploy` only after all previous items pass.

Exit criteria:

- failed pre-commit work leaves the active release unchanged;
- post-commit failures report that deployment changed state;
- disconnects have a documented and tested recovery path;
- repeated idempotent requests return the original outcome;
- the control plane needs one structured operation rather than a shell sequence.

## Phase 5 — Git rollback pilot

Status: pending

Goal: switch safely to a known retained release using the same transaction,
locking, audit, and recovery machinery.

Work items, in order:

1. Define which release identifiers are eligible for rollback.
2. Validate retained release integrity before the commit point.
3. Implement the atomic switch without rebuilding the release.
4. Preserve forward recovery information.
5. Add missing, invalid, concurrent, interrupted, and repeated rollback tests.
6. Advertise `site.rollback` after the complete contract passes.

Exit criteria:

- rollback cannot select arbitrary filesystem content;
- the previous active release remains identifiable;
- an interrupted rollback is recoverable deterministically;
- audit and result data identify both source and target releases safely.

## Phase 6 — client integration and compatibility

Status: pending

Goal: integrate one real control plane while keeping client and engine releases
independent.

Work items:

- define the supported protocol-version window;
- implement version and capability negotiation in the client;
- safely reject incompatible engines;
- map progress and stable error codes to client state;
- test older-client/newer-engine and newer-client/older-engine combinations;
- document bootstrap behavior when the engine is absent;
- compare SSH round trips, failure recovery, and orchestration complexity with
  the previous implementation.

Exit criteria:

- neither repository requires a simultaneous merge or release;
- incompatibility fails before a mutation begins;
- the pilot demonstrates measurable operational or maintenance improvement.

## Phase 7 — release and production hardening

Status: pending

Goal: make installation, upgrade, downgrade, and recovery safer than manual
binary replacement.

Work items:

- reproducible Linux AMD64 and ARM64 builds;
- checksums and signed release artifacts;
- explicit, pinned installation through the control plane;
- atomic upgrade and downgrade with previous-binary recovery;
- release compatibility matrix;
- redaction and bounded-log review;
- package and incident-recovery documentation;
- opt-in rollout to test servers before broader deployment.

Exit criteria:

- downloaded artifacts are verified before execution;
- failed upgrades retain a runnable previous binary;
- release provenance and compatibility can be audited;
- production rollout and rollback procedures have been exercised.

## Phase 8 — selective expansion

Status: pending

Additional workflows are considered only after the Git pilot succeeds. Each
workflow requires its own milestone document and measurable reason to move into
Operations Engine.

Potential candidates:

- atomic Caddy and site configuration changes;
- stack status and reconciliation;
- backup and restore;
- narrowly scoped scheduled jobs.

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

## Open decisions

Resolve these in the phase where they first become blocking:

- final product prefix, if any;
- canonical site identity;
- configuration source and trusted filesystem roots;
- service user and sudo allowlist;
- exact deploy commit mechanism;
- idempotency-key retention (lookup mechanism decided in Phase 3);
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
