# Operations Engine roadmap

Status: active

Release gate: Phase 7 — production release readiness

Parallel work: Phase 8 — selective migration of privileged operations

Last updated: 2026-09-28

This file is the authoritative source for current priorities, remaining work,
and completion criteria. It intentionally does not duplicate completed
implementation history. The former long-form plan, including its decision log
and detailed delivery notes, is preserved in
[`docs/implementation-history.md`](docs/implementation-history.md).

Detailed contracts and milestone plans live under `docs/` and in the shared
documentation repository. The README describes the product and its supported
surface; `ops-engine capabilities --output json` is authoritative for the
operations supported by a particular binary.

## Working agreement

1. Work on the release gate first unless a production issue or documented
   dependency requires otherwise.
2. Complete one small, testable vertical slice at a time.
3. Do not advertise an operation through `capabilities` before it is
   implemented and tested.
4. Document a mutation's inputs, invariants, commit point, failure states, and
   recovery behavior before implementing it.
5. Keep protocol changes backward-compatible within a protocol version.
6. Update this roadmap in the same change when priority, scope, or status
   changes. Put durable architectural decisions in `docs/decisions/` rather
   than growing another decision log here.
7. Keep unfinished work explicit.

## Definition of done

A work item is complete only when all applicable requirements are satisfied:

- formatting and Clippy pass with warnings denied;
- unit and integration tests cover public behavior and failure paths;
- stdout contains only documented protocol output;
- errors and warnings use stable machine-readable codes;
- inputs are validated at the server execution boundary;
- logs and responses do not expose secrets;
- documentation and `capabilities` match the implementation;
- Linux behavior and mutation recovery are tested;
- persistent per-request state has a bounded, tested retention policy;
- the minimum supported Rust version still builds the project.

Required local validation:

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo +1.85.0 check --all-features
```

## Completed foundation — Phases 0–6

Status: complete

The project direction, execution boundary, site/filesystem model, transaction
framework, Git deploy and rollback pilots, and client compatibility layer are
complete. Their original exit criteria and delivery notes are retained in the
[implementation history](docs/implementation-history.md).

## Phase 7 — production release readiness

Status: pending; engine-side implementation is complete

Goal: make installation, upgrade, downgrade, and recovery safer than manual
binary replacement.

Delivered:

- reproducible Linux AMD64 and ARM64 builds;
- checksummed, minisign-verified release artifacts;
- transactional `engine install` and `engine rollback` operations;
- atomic activation and recovery of the previous executable;
- compatibility, release, rollout, and incident-recovery documentation;
- redaction, bounded-log, and whole-branch reviews;
- automated end-to-end coverage using signed test fixtures.

Remaining release blockers, in order:

1. Replace the deliberately public TEST-ONLY release signing key with a real
   production key and configure the release workflow secrets.
2. Cut and verify a real tagged release.
3. Wire `website-control-panel` to request an explicit engine version and use
   the signed release instead of building its test fixture from source.
4. Exercise the documented install, upgrade, failed-upgrade recovery, and
   rollback procedure on an opt-in Linux test server.

Exit criteria:

- downloaded artifacts are verified before execution;
- failed upgrades retain a runnable and reachable previous binary;
- release provenance and compatibility can be audited;
- the control plane performs explicit, pinned installation;
- production rollout and rollback procedures have been exercised with a real
  release key and artifact.

Do not mark Phase 7 complete until all four remaining blockers are closed.

## Phase 8 — selective migration

Status: in progress

Goal: replace raw privileged client-side mutations only where a typed engine
operation gives a measurable security, recovery, or maintenance benefit. Each
new workflow needs its own milestone and must satisfy the definition of done.

Delivered families include:

- ingress and runtime configuration activation, park/unpark, and reconciliation;
- permissions repair;
- MariaDB and PostgreSQL provisioning and restore workflows;
- protected database-tool lifecycle operations;
- WordPress install, clone, update, and cleanup operations;
- target-aware cron installation;
- backup activation and retention operations;
- Docker Compose configuration activation.

The detailed shipped-operation history is retained in
[`docs/implementation-history.md`](docs/implementation-history.md). The exact
surface of a build remains discoverable through `ops-engine capabilities`.

Current follow-up queue:

1. Finish the Phase 7 control-plane release integration before expanding the
   API merely for breadth.
2. Wire the existing `runtime.activateConfig`, `ingress.reconcile`, and
   `runtime.reconcile` operations into the control panel where the matching raw
   paths still exist.
3. Migrate remaining ingress call sites only after checking their multi-file
   and cross-root transaction requirements; do not force them through the
   single-file activation contract.
4. Design snapshot, verification, and automatic rollback before claiming that
   database restore is transactionally safe. Its current scope is auditability
   and bounded execution only.
5. Keep interactive terminals, arbitrary shell execution, general file
   browsing, and live log streaming outside the privileged structured API
   unless a new architecture and threat model justify them.

## Repository-local queue

These tasks can be completed and verified entirely in this repository. They do
not require production credentials, a GitHub release, a control-panel change,
or access to a real server.

- [x] Classify and archive the existing implementation plans; add a status
  index so their historical checkboxes are not mistaken for open work
  (completed 2026-09-28).
- [ ] Design and implement reconciliation for orphaned
  `<domain>.maintenance-backup` files left by interrupted `ingress.park` or
  `ingress.unpark` operations. Define safe classification and recovery rules
  before changing `ingress.reconcile`. Implementation and regression tests are
  present; final local validation is pending because the current environment
  has no Rust toolchain.
- [ ] Design transactional database-restore safety: pre-restore snapshot,
  post-restore verification, and automatic rollback. Keep this separate from
  the existing bounded-execution/audit-only `db.restore` contract until its
  failure semantics are specified and tested.

Implementation-plan status is indexed in
[`docs/superpowers/plans/README.md`](docs/superpowers/plans/README.md).

## Updating this roadmap

When work advances:

1. update the relevant status or remaining-work item;
2. link the milestone or durable decision instead of pasting its history here;
3. update `Last updated` in the same change;
4. move completed detail to `docs/implementation-history.md` when it is useful
   for future investigation;
5. keep this file focused on what is true now and what happens next.
