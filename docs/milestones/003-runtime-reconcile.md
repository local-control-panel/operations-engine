# Milestone 003: `runtime.reconcile`

Status: implemented — advertised in `capabilities`, covered by unit and
integration tests (`src/runtime_config/reconcile.rs`), 300/300 passing,
clippy and fmt clean. Wiring `website-control-panel`'s `reconciliation.rs::
sweep`'s `TempFile`/`RedundantBackup`/`RecoverableBackup` classes over to
this operation (alongside `ingress.reconcile`'s equivalent call site) is a
separate, not yet started increment — see `PLAN.md`'s decision log.

The `runtimeRoot` follow-up to `ingress.reconcile`
(`docs/milestones/002-ingress-reconcile.md`, `src/ingress/reconcile.rs`),
flagged there as "structurally identical... once it ships." Sweeps orphaned
`.tmp`/`.tmp-*` staging siblings and `.rollback-*` backup siblings left
behind by a `runtime.activateConfig` attempt that never reached its own
commit point, the same way `ingress.reconcile` does for `ingressRoot`.

## Two differences from `ingress.reconcile`, and how this milestone resolves them

`runtimeRoot` is not flat like `ingressRoot`: fragments live at
`runtime_root/<runtime_id>/<domain>.caddyfile`, one subdirectory per runtime
pool (`runtime_config::route_path`). `ManagedRoot::file_names()` is
non-recursive and lists only its own root's direct children, so a bare port
of `ingress::reconcile::execute` scanning `runtime_root` directly would see
zero files (they are all one level down) — this has to be resolved before
any code is written, not discovered after tests fail to find anything.

The resolution: **this operation takes `--runtime-id`, same as
`runtime.activateConfig`, and sweeps only that pool's `<runtime_id>/`
subdirectory** — not a whole-`runtime_root` sweep across every pool in one
call. Concretely: `ManagedRoot::open(runtime_root)` then
`open_managed_dir(<runtime_id>)`, then `file_names()` on the result, exactly
the capability-scoped descent pattern `open_managed_dir`'s own doc comment
describes. No new filesystem primitive is needed — no recursive
`file_names`, no directory-listing/`dir_names` addition — because the
operation never needs to *discover* which runtime ids exist; the caller
already knows (see the lock-granularity discussion below for why that is
also the correct place for that knowledge to live).

This directly determines the lock granularity, which is the second
difference: `runtime.activateConfig` locks per `runtime_id`
(`runtime_config::execute::open_runtime_config_state`), deliberately not
host-wide like `ingress.activateConfig` — see `PLAN.md`'s 2026-09-07 decision
log entry. A reconcile sweep only ever touches `.tmp`/`.rollback-*` siblings
under one pool's subdirectory, which is exactly the same resource
`activateConfig` locks per pool for the same reason (`caddy reload` only
ever reloads that one runtime-service container's imported config set, and
two different pools share nothing a reload could race on). Taking a
**host-wide** reconcile lock — the other option considered — would
contradict that already-recorded reasoning for no correctness benefit: it
would serialize a reconcile sweep of `fp1-php83` against a concurrent
`activateConfig` on `fp1-php84`, a pair that cannot race on anything. So
**`runtime.reconcile` reuses `open_runtime_config_state` verbatim**, unchanged,
giving it identical lock semantics and identical preflight/idempotency/audit
state scoping to `runtime.activateConfig` for the same `runtime_id` — a
reconcile and an activation for the same pool correctly serialize; a
reconcile for one pool and an activation (or another reconcile) for a
different pool correctly do not.

The consequence of choosing per-`runtime_id` is that sweeping every runtime
pool on a host means the caller issues one `runtime.reconcile` call per
known `runtime_id`, not one call for the whole host. This is the same shape
`runtime.activateConfig` already has (it also takes `--runtime-id` and never
discovers pools on its own), and mirrors `002`'s own "out of scope" ruling
for `IdlePool`: knowing which runtime pools exist is site-registry knowledge
that lives in `website-control-panel`'s SQLite, not something this engine
has — or should have — visibility into. The engine only ever answers "sweep
the pool you named," the same way it only ever answers "activate the
fragment you named." Enumerating known pools and looping the call across
them is the client's job, exactly like today's raw-SSH `reconciliation.rs`
already has to know which runtime pools exist to sweep them at all.

## Scope

Same two orphan classes as `ingress.reconcile`, scoped to one runtime pool's
subdirectory instead of the flat ingress root:

- **`TempFile`**: any `*.tmp`/`*.tmp-*` file directly under
  `runtime_root/<runtime_id>/` — always safe to remove.
- **`RedundantBackup`**/**`RecoverableBackup`**: any `*.rollback-*` file
  under `runtime_root/<runtime_id>/`. Redundant (live sibling present) is
  removed; recoverable (live sibling missing) is moved back into place.

Classification is byte-for-byte identical to `ingress.reconcile`'s
`is_temp_file`/`rollback_backup_live_sibling` (the `.tmp`/`.rollback-<suffix>`
naming convention is shared verbatim by `runtime_config::activate::RoutePaths`
and `ingress::activate`'s equivalent) — those two functions are promoted to
`pub(crate)` on `ingress::reconcile` and reused directly rather than
duplicated.

Out of scope, same reasons as `002`:

- **`OrphanedExecConfig`**/**`RouteWithoutExecConfig`** — still need an
  `ingressRoot` cross-reference this single-root-per-call scan doesn't do.
- **`StaleLock`**, **`IdlePool`** — still client-owned coordination/registry
  state this engine has no visibility into.

If a runtime pool has never been activated on this host, its
`<runtime_id>/` subdirectory does not exist yet. That is not an error — see
"Failure and recovery cases" below.

## Proposed operation

```console
ops-engine runtime reconcile --runtime-id <id> --request-id <uuid> [--idempotency-key <key>] --output json
```

### Result shape

```json
{
  "runtimeId": "<id>",
  "removedTempFiles": ["<name>", ...],
  "removedRedundantBackups": ["<name>", ...],
  "restoredRecoverableBackups": [{"backupPath": "<name>", "restoredTo": "<name>"}, ...],
  "reconciledAtUnixSecs": <u64>
}
```

Every name is relative to `runtime_root/<runtime_id>/` (bare
`<domain>.caddyfile[.tmp|.rollback-<suffix>]`, never an absolute host path
and never prefixed with the runtime id again, since `runtimeId` is already
its own field) — same `SiteRelativePath`-valid, wire-safe shape
`ingress.reconcile`'s result uses.

## Failure and recovery cases

Same as `ingress.reconcile`'s four cases (file already gone between scan and
remediation is not an error; the recoverable-backup restore uses
`ManagedRoot::rename`, never copy-then-delete; a failed initial scan aborts
before any remediation; one unclassifiable/unresolvable file does not abort
the rest of the sweep), plus one new case specific to the nested layout:

- **The `<runtime_id>/` subdirectory does not exist.** A pool that has never
  had a fragment activated on this host has no subdirectory yet
  (`runtime_config::activate::activate` only calls `create_dir_all` on first
  activation). Opening a nonexistent subdirectory is treated as a clean,
  empty no-op sweep (all three result lists empty), not an error — a pool
  with nothing on disk yet has nothing to reconcile, the same successful-
  no-op outcome `002`'s "an empty root is a successful no-op" test already
  establishes for the flat case.

## Exit criteria

Same four as `002`'s (no shell string built anywhere in this path; a crash
mid-sweep leaves a valid intermediate state; idempotent replay returns the
original recorded result without re-scanning; an integration test proves a
real orphaned `.tmp` and a real orphaned `.rollback-*`, with and without a
live sibling, against a real filesystem), plus:

- A lock held for one `runtime_id` does not block a `runtime.reconcile` call
  for a different `runtime_id` — the same proof
  `runtime_config::execute`'s own test suite already makes for
  `activateConfig`, extended to cover reconcile using the identical shared
  state-scoping function.
- A `runtime.reconcile` call for a `runtime_id` with no subdirectory on disk
  yet succeeds as an empty no-op rather than failing.
