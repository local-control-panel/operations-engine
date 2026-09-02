# Milestone 001: Git deploy and rollback

Status: design pending

Git deploy and rollback will be the first mutating Operations Engine workflow.
Implementation should begin only after the inputs, invariants, and recovery
contract below are resolved.

## Goal

Replace a multi-step remote shell workflow with one validated local operation
that remains inspectable and recoverable when SSH disconnects or a subprocess
fails.

## Proposed operations

```console
ops-engine site deploy --site-id <uuid> --revision <full-object-id> --output json
ops-engine site rollback --site-id <uuid> --release <release-id> --output json
```

The stable site identifier is an opaque canonical UUID. Domain is mutable
display/routing metadata and is not accepted as operation identity. Rollback
selects an engine-owned retained release rather than trusting client history.

## Contract to define

- canonical site identifier and trusted filesystem root;
- accepted Git revision formats and remote/ref resolution rules;
- request or idempotency key;
- per-site lock location, ownership, timeout, and stale-lock recovery;
- staging directory lifecycle and disk-space preflight;
- repository ownership and safe-directory behavior;
- exact atomic switch mechanism;
- database migration policy, if migrations are ever in scope;
- progress event steps and final result fields;
- bounded stdout, stderr, and subprocess output;
- cancellation semantics before and after the commit point;
- audit event fields and secret redaction;
- retention and cleanup rules for previous releases.

## Failure and recovery cases

Integration tests must cover at least:

- invalid site identifiers and path traversal attempts;
- unknown or ambiguous Git revisions;
- concurrent operations on the same site;
- stale locks;
- insufficient disk space;
- fetch, checkout, build, and validation failures;
- SSH disconnection before and after the commit point;
- an interrupted filesystem switch;
- rollback to a missing or invalid release;
- repeated requests with the same idempotency key;
- cleanup failures that occur after a successful switch.

## Exit criteria

- No user-controlled value is interpolated into a shell command.
- A failed pre-commit operation leaves the active release unchanged.
- The active release can be identified without parsing human-oriented output.
- Repeating an idempotent request cannot create a second deployment.
- A client can distinguish validation, conflict, dependency, subprocess,
  timeout, and internal errors by stable codes.
- Disconnect and partial-failure tests demonstrate a documented recovery path.
- The operations are advertised by `capabilities` only after the contract and
  integration tests are complete.
