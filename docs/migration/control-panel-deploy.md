# Control Panel deploy migration map

Status: Phase 2 contract  
Source reviewed: `website-control-panel/src-tauri/src/commands/deploy.rs`  
Reviewed: 2026-09-02

This document maps the existing Git deployment workflow to the future
Operations Engine boundary. It is an inventory and migration contract, not an
instruction to remove the current implementation yet.

## Current workflow

The current Tauri backend owns the complete lifecycle:

1. `deploy_connect` generates an Ed25519 deploy key and stores encrypted key
   material, repository URL, branch, and domain-keyed state in local SQLite.
2. `deploy_test_and_clone` installs the private key remotely, runs
   `git ls-remote`, inspects the caller-provided root, and clones when empty.
3. `deploy_confirm_clone` renames a non-empty root to a timestamped sibling
   backup and then clones.
4. Clone pins `core.sshCommand` to the installed deploy key.
5. `deploy_run` optionally checks out a branch, executes `git pull`, captures
   HEAD, and updates local status/history.
6. `deploy_rollback` accepts only a SHA present in local SQLite history and runs
   `git reset --hard` in the caller-provided root.
7. Auto-deploy writes a remote cron entry that runs `git pull` directly.
8. `deploy_reconcile` reads remote HEAD and copies externally changed state into
   local SQLite history.
9. Disconnect deletes local state and best-effort removes the remote key, but
   leaves the checkout untouched.

Current safeguards include shell escaping, absolute-path/traversal validation,
a ten-entry SQLite history bound, a 64 KiB stored-log bound, explicit user
confirmation before moving a non-empty root, and rollback allowlisting against
recorded history.

## Current weaknesses addressed by the engine

- Domain is used as identity even though it changes during site rename.
- The remote root is supplied by the caller; it is not selected from a
  root-owned server-side manifest.
- Absolute-path validation accepts `/` and does not prove containment under a
  managed root.
- Deploy and rollback are in-place Git operations, not release transactions.
- Locking, idempotency, persisted transaction state, and a commit point are
  absent.
- Local SQLite history is authoritative for rollback even though filesystem
  state lives on the server.
- Several sequential SSH commands can be interrupted between state changes.
- Git and filesystem operations are assembled as shell strings.
- Cron bypasses the client but does not persist a structured remote result.

## Ownership after migration

| Concern | Control plane | Operations Engine |
| --- | --- | --- |
| UI state and user confirmation | Authoritative | Not stored |
| Server connection and SSH transport | Authoritative | Not stored |
| Stable `siteId` allocation | Creates once and stores | Validates and uses |
| Domain and display metadata | Authoritative for UI | Snapshot in trusted manifest |
| Repository selection and branch policy | User-facing configuration | Validates registered policy |
| Private deploy key backup | Vault-encrypted local copy | Restricted installed credential |
| Trusted filesystem root | Displays discovered value | Reads only from root-owned config |
| Transaction, lock, and idempotency state | Mirrors result | Authoritative on server |
| Release inventory and active release | Caches/displays | Authoritative on server |
| Rollback eligibility | Requests a known release ID | Validates against server inventory |
| Progress and final result | Renders and persists summary | Emits structured protocol events |
| Audit event for mutations | May ingest/display | Produces at execution boundary |
| Auto-deploy scheduling | Configures policy later | Out of the initial pilot |

## Migration sequence

1. Add a stable `siteId` to the control plane without changing deploy behavior.
2. Register or discover a root-owned site manifest on the server.
3. Import the existing root as an initial release and transactionally update
   runtime identity, Caddy root, and `open_basedir` to the stable `current`
   path.
4. Add engine compatibility and capability negotiation.
5. Implement engine deploy behind an explicit feature flag.
6. Compare engine state with the existing checkout/history without mutating it.
7. Enable engine deploy for opt-in test sites and mirror results into SQLite.
8. Add engine rollback and verify disconnect/retry recovery.
9. Stop treating SQLite history as rollback authority.
10. Remove old deploy/rollback shell builders and their SSH sequencing only
   after the engine path passes production rollout criteria.
11. Evaluate clone/connect, credential installation, reconcile, and auto-deploy
    as separate migrations; do not bundle them into pilot removal.

## Code to remove eventually

After successful Phase 6 integration, the control plane should no longer own:

- `build_deploy_command` and `build_rollback_command`;
- `build_capture_head_command` and parsing of Git's human output;
- remote root backup/rename orchestration for deployment;
- direct `git pull`, `git checkout`, `git reset`, and HEAD capture over SSH;
- rollback validation against local history as the security boundary;
- deploy log aggregation from raw subprocess streams.

Local SQLite tables may remain temporarily as a UI cache and migration source.
Their removal or schema replacement is a separate control-plane migration and
must not be coupled to the first engine release.

## Compatibility rule

No current deploy code is deleted until the control plane has verified a
compatible engine protocol and the required operation capability before any
mutation begins. A fallback may select the old implementation before a request
starts; it must never switch implementation midway through a transaction.
