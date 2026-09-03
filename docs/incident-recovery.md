# Incident recovery: engine install/upgrade

## A failed or misbehaving upgrade

1. Run `ops-engine engine rollback --request-id <new-uuid>` first — it
   requires no network access and switches
   `/usr/local/bin/ops-engine` back to the one retained previous binary
   in under a second. This is always the first response.
2. If the previous binary was also bad (rare — it was itself verified
   and running before this upgrade), install a specific known-good older
   version instead: `ops-engine engine install --version <known-good>
   --request-id <new-uuid>`. This re-fetches and re-verifies that
   version from GitHub Releases rather than depending on local state.
3. Both commands are idempotent by `--request-id`/`--idempotency-key`
   exactly like `site deploy`/`site rollback` — a retried call after a
   dropped connection returns the original outcome rather than
   double-applying.

Two properties make step 1 dependable, and both matter because the
automation user's sudo policy permits nothing but `ops-engine` itself
(`docs/site-model.md`), so a `/usr/local/bin/ops-engine` that cannot run
would leave no recovery path over the control plane's connection:

- **A binary that cannot run here is never activated.** `engine install`
  runs the staged copy's own `version` command before switching
  `/usr/local/bin/ops-engine`. If it does not start, or reports a version
  other than the one requested, the install fails with
  `ARTIFACT_NOT_RUNNABLE`/`ARTIFACT_VERIFICATION_FAILED` and the running
  binary is left untouched.
- **The first install on a host retains what it replaces.** On a server
  with no prior managed install, the binary already at
  `/usr/local/bin/ops-engine` is copied into the engine's `versions/`
  directory before it is overwritten — under the version it reports for
  itself, or as `pre-managed` if it cannot say. So `engine rollback` works
  on the first upgrade too, and reports `pre-managed` as the version it
  restored.

## Opt-in rollout to test servers

There is no separate "rollout channel" mechanism — `engine install`
already requires an explicit, pinned version on every call, so nothing
auto-updates and every rollout is manual and per-server by construction.
Before rolling a new version out broadly:

1. Run `engine install`/`engine rollback` against the
   `website-control-panel` repo's `docker/test-server` fixture first.
2. Run it against exactly one real managed server and confirm
   `capabilities`/`version` report the expected result.
3. Only then roll out to additional servers, one at a time.
