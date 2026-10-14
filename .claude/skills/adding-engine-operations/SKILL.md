---
name: adding-engine-operations
description: Adds or extends a protocol operation of the Operations Engine (typed, root-owned, transaction-recorded server mutations such as wordpress.clone or drupal.updateDb) and the panel side that calls it. Use when a feature needs the server to change something, when a request gains a field, or when capabilities or the engine pin change.
---

# Adding or extending an engine operation

The engine is the only thing that mutates a customer server. The panel sends a typed JSON request file; the engine validates it again at its own boundary, runs fixed subprocesses and records the result. Read `CONTRIBUTING.md` (design rules) and `docs/protocol.md` first; this is the procedure.

## New operation

```
- [ ] 1. CLI shape in src/cli.rs; operation name `namespace.verb` returned by the command's name match
- [ ] 2. module src/<name>.rs: `pub const OPERATION`, a `Plan` (serde, rename_all camelCase, deny_unknown_fields), a validated `Request`, `execute()`
- [ ] 3. dispatch in src/commands/<namespace>.rs; return a protocol Response, never print
- [ ] 4. list it in OPERATIONS in src/commands/capabilities.rs ONLY once it works; update tests/cli.rs expected list
- [ ] 5. docs/protocol.md paragraph (what it does, what it refuses, how it fails)
- [ ] 6. tests (below); cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features
- [ ] 7. PR, merge when "Format, lint, and test" and "Minimum Rust version" are green
- [ ] 8. panel: bump docker/test-server/build-ops-engine.sh to the merge commit, call it with `require_operation` first, Lima workflow test (see the panel's running-lima-workflow-tests)
```

## Extending a request

`deny_unknown_fields` makes an old engine reject a new key, which is the point: the panel must never think a protection was applied when it was not.

- New field: `#[serde(default)]` and a closed set of values, parsed into a typed struct; an unknown value is `RequestError`, not ignored.
- Advertise it as a boolean in `Features` (`features.<name>`) in `capabilities`, and cover it in `tests/cli.rs`.
- The panel sends the field only when the feature is `true`, and **fails closed** (refuses the whole action) when the user asked for the protection and the engine lacks it.

## Rules specific to mutations

- Subprocesses: executable plus explicit args through `src/process.rs`'s bounded runner. No `sh -c`, no `std::process::Command` in operation modules.
- Secrets go through stdin (`run_with_stdin_bytes`), never argv; no secret in state, audit or error text.
- Files: fd-relative through `ManagedRoot` / `TrustedRoot`. When a path came from a copied site tree (`cp -a` keeps symlinks), `symlink_metadata` every component you write through and refuse symlinks (`Error::UnsafeTarget`).
- Take the resource lock, then `preflight::run` for idempotency; a replay returns the recorded result. Anything half done on failure is rolled back or leaves a durable recovery marker.
- Verify what you promised: if the point is "this copy cannot send mail", run a check that proves the plugin loads and fail the operation (rolling back) when it does not.

## Tests that every operation gets

- Request parsing: valid, each rejected field, the closed sets, optional fields absent.
- `execute` with fake `docker`/`cp` scripts (see `wordpress_clone.rs` tests: the fake logs argv, delegates the real copy, and uses marker files like `REJECT_HEALTH` to force failures).
- Ordering assertions on the logged argv (what runs before what).
- The failure path leaves the target as it was.
- A symlink/escape test for anything that writes files.

Evaluation scenarios: [EVALS.md](EVALS.md).
