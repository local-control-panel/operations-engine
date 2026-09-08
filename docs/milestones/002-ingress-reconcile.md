# Milestone 002: `ingress.reconcile`

Status: implemented — advertised in `capabilities`, covered by unit and
integration tests (`src/ingress/reconcile.rs`), 295/295 passing, clippy
and fmt clean. Wiring `website-control-panel`'s
`reconciliation.rs::sweep`'s `TempFile`/`RedundantBackup`/
`RecoverableBackup` classes over to this operation, and `runtime.reconcile`
(the structurally-identical follow-up for `runtimeRoot`), are both
separate, not yet started increments — see `PLAN.md`'s decision log.

Phase 8 candidate ("stack status and reconciliation") from `PLAN.md`,
scoped down to a first tractable slice. `website-control-panel`'s own
`src-tauri/src/commands/reconciliation.rs` (RP-06) already does this over
raw SSH (`find` + `rm`/`mv`), for seven orphan classes across ingress
routes, runtime exec configs, stale lock directories, and idle runtime
pools, with zero transaction/audit/idempotency — a dropped connection
mid-sweep leaves partially-remediated state with no record of what
happened.

## Why this class first

`ingress::activate::activate_live` (`src/ingress/activate.rs`) already
uses the exact `.tmp` staging / `.rollback-<suffix>` backup naming
convention this milestone cleans up — this is the engine tidying up after
its own interrupted activations, not a new concept. A domain that is
activated again naturally overwrites its own stale `.tmp`/`.rollback-*`
(the sibling names are fixed per route, not unique per attempt); orphans
only accumulate for domains nothing touches again after a crash — exactly
what a periodic/on-demand sweep is for.

## Scope

In scope, this milestone:

- **`TempFile`**: any `*.tmp`/`*.tmp-*` file directly under `ingressRoot`
  — always safe to remove; nothing ever reads a `.tmp` sibling except the
  activation that is about to rename it into place.
- **`RedundantBackup`**/**`RecoverableBackup`**: any `*.rollback-*` file
  under `ingressRoot`. If its live sibling (the path before
  `.rollback-<suffix>`) still exists, the backup is redundant — remove
  it. If the live sibling is missing, the backup is the only copy of a
  route that a previous activation's post-reload-failure restore never
  completed — move it back into place as the live file.

Out of scope, deferred to a later milestone (each needs a call this one
doesn't):

- **`OrphanedExecConfig`**/**`RouteWithoutExecConfig`** — need
  `runtimeRoot` cross-referenced against `ingressRoot`'s live routes, a
  two-root read this milestone's single-root scan doesn't do.
- **`runtime.reconcile`** (runtime_root's own `TempFile`/backup orphans)
  — structurally identical to this milestone once it ships, the same way
  `runtime.activateConfig` followed `ingress.activateConfig` as a near-copy;
  not bundled here to keep this slice reviewable on its own.
- **`StaleLock`** (`/etc/wcp/locks/<domain>.lock`) — this is
  `website-control-panel`'s own pre-engine coordination mechanism, not
  content this engine owns or even knows exists. Stays on the client's
  existing raw-SSH path.
- **`IdlePool`** (stopping a Compose runtime-pool service with zero
  referencing sites) — needs the site registry (which sites reference
  which runtime pool), which lives in `website-control-panel`'s own
  SQLite, not anything this engine has visibility into. Also stays
  client-side.

## Proposed operation

```console
ops-engine ingress reconcile --request-id <uuid> [--idempotency-key <key>] --output json
```

No `--domain` — this is a whole-root sweep, not a per-site operation, so
it locks and records against the *engine-wide* state root
(`state::open_engine_state`, the same scope `engine install`/`engine
rollback` already use), not a per-site one. Concurrent reconcile attempts
serialize on that lock; a reconcile does not take any individual site's
own lock, so it never contends with a deploy/rollback/config-activation
in progress for a specific site (they read/write different files by
construction — a reconcile only ever touches `.tmp`/`.rollback-*`
siblings, never a live route file).

### Result shape

```json
{
  "removedTempFiles": ["<path>", ...],
  "removedRedundantBackups": ["<path>", ...],
  "restoredRecoverableBackups": [{"backupPath": "<path>", "restoredTo": "<path>"}, ...]
}
```

Every path is relative to `ingressRoot` (never absolute — this response
crosses the wire, and an absolute host path is exactly the kind of detail
`docs/protocol.md`'s `details`/result allowlist principle argues against
echoing unnecessarily). Paths are `SiteRelativePath`-valid content, not
free text.

## Failure and recovery cases

- A file that no longer exists by the time this sweep tries to remove or
  move it (removed by a concurrent successful activation between the
  scan and the remediation) is not an error — treated as already-fixed,
  logged nowhere, sweep continues.
- A recoverable backup's move-into-place uses the same atomic
  same-directory rename primitive `activate_live` itself uses for its own
  commit step (`ManagedRoot::rename`) — never a copy-then-delete, so an
  interrupted process never leaves the live path missing *and* the
  backup gone.
- The scan itself (listing `ingressRoot`) is read-only; if it fails
  (I/O error), the whole operation fails cleanly before any remediation,
  same as every other operation's precondition-check-first shape.
- One file this sweep cannot classify, remove, or restore does not abort
  the rest of the sweep — matches `install::prune_superseded_version`'s
  and the client's own existing `reconciliation.rs::remediate`'s
  best-effort shape. The response only reports what actually succeeded.

## Exit criteria

- No shell string is built anywhere in this path — pure `ManagedRoot`
  directory listing and file operations, not a ported `find`/`rm`/`mv`
  subprocess sequence.
- A crash mid-sweep (transport dies after some files are removed/restored
  but before the response is returned) leaves the filesystem in a valid
  intermediate state — every individual removal/restore is already
  atomic on its own, so partial completion is just "fewer orphans than
  before," never a half-written file.
- Idempotent replay: retrying with the same idempotency key after a
  transport failure returns the original recorded result rather than
  re-scanning (matches `site.deploy`/`site.rollback`'s existing guarantee
  — `mutation::preflight` gives this for free).
- Integration test proves a real orphaned `.tmp` and a real orphaned
  `.rollback-*` (both with and without a live sibling) are handled
  correctly against a real filesystem, not just unit-level classification
  logic.
