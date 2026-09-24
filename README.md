# Operations Engine

Operations Engine is a Linux-only command-line execution layer for structured,
reliable server operations.

It is designed to be installed on managed servers and invoked by a control
plane over an existing SSH connection. Instead of assembling long shell
scripts remotely, a client calls a versioned operation and receives a
machine-readable result.

> [!IMPORTANT]
> Phases 0-6 (foundation, transaction framework, Git deploy/rollback,
> client integration) are complete. Phase 7 (release and production
> hardening) is functionally done and tested, with a small remainder before
> a real release — see [PLAN.md](./PLAN.md) for the authoritative current
> status and test count. Dozens of typed operations beyond the original Git
> deploy/rollback pilot now ship (WordPress lifecycle, database, permissions,
> ingress/runtime, backups). The protocol and installation process are
> stabilizing but not yet frozen.

Development follows the shared [implementation plan](./PLAN.md). It records the
current phase, agreed decisions, completion criteria, and the next work item.

## Why it exists

Remote orchestration built from shell commands becomes difficult to maintain as
workflows grow. Quoting, partial failures, multiple SSH round trips, and parsing
human-oriented command output make operations such as deploy and rollback more
fragile than they need to be.

Operations Engine provides a narrow boundary between a control plane and the
server. It is intended to make complex operations:

- typed and machine-readable;
- transactional where the underlying system allows it;
- recoverable after interrupted connections or partially completed work;
- versioned independently from the client application;
- reusable from a desktop application, CI, or a direct SSH session;
- testable without a graphical interface.

## Architecture

```text
Control plane
  -> SSH: ops-engine <operation> --output json
  -> Operations Engine
  -> Docker / Git / Caddy / filesystem / databases
```

The control plane remains the source of truth for user-facing state and local
metadata. Operations Engine is the execution layer: it validates input,
performs a local server operation, and returns a structured result.

The first version will be a CLI, not a continuously running daemon or a
general-purpose remote agent.

## Command surface

The original small surface (`version`, `capabilities`, `doctor`, `stack
status`, `site inspect/deploy/rollback`, `reconcile`) shipped first as the
Git deploy/rollback pilot — it was a useful test of locking, filesystem
staging, Git state, progress reporting, recovery, and compatibility between
client and engine versions.

Selective expansion (Phase 8) has since added typed, capability-gated
operations well beyond that pilot: WordPress lifecycle (`wordpress.install`,
`wordpress.clone`, `wordpress.updateCore`/`updatePlugins`/`updateThemes`,
`wordpress.cleanup`), database operations (`db.provisionMariaDb`,
`db.restore`, `db.export`, MariaDB/PostgreSQL/Valkey lifecycle),
`permissions.fixOwnership`, backup workflows, and ingress/runtime
reconciliation, among others. `ops-engine capabilities --output json` lists
what a given build actually supports; see [PLAN.md](./PLAN.md) for the full,
current list and the criteria each migration must meet.

## Protocol direction

Standard output is reserved for protocol messages. Diagnostic logs belong on
standard error.

A completed operation will return a versioned JSON envelope similar to:

```json
{
  "protocolVersion": 1,
  "operation": "site.deploy",
  "ok": true,
  "result": {},
  "warnings": [],
  "error": null
}
```

Long-running operations may use JSON Lines for progress followed by a final
result:

```jsonl
{"type":"progress","step":"validate","status":"start"}
{"type":"progress","step":"validate","status":"ok"}
{"type":"result","ok":true,"result":{}}
```

The protocol version and the engine's semantic version are separate. Clients
will negotiate support through `capabilities` and reject incompatible protocol
versions safely.

## Scope

Good candidates for structured operations include:

- server preflight checks and diagnostics;
- stack status and reconciliation;
- Git deploy and rollback;
- atomic site and Caddy configuration changes;
- backup and restore workflows;
- locks, staging, and recovery;
- narrowly scoped scheduled operations.

The following should generally remain outside the structured API:

- interactive terminals;
- arbitrary shell or container execution;
- live log streaming;
- SFTP and general file browsing;
- small read-only probes where an abstraction adds no value.

## Security principles

Operations Engine is intentionally not an unrestricted privileged remote
execution API.

- The installed binary should be owned by `root` and not writable by the
  managed service user.
- Privileged operations should use a minimal allowlist rather than broad sudo
  access.
- Domains, paths, container names, and service names must be validated at the
  execution boundary.
- Mutating filesystem operations should use temporary files, validation, and
  atomic rename where possible.
- Per-resource locks must have bounded and explicit stale-lock recovery.
- Mutation operations should produce audit events.
- Protocol output must never expose secrets, private keys, or raw environment
  dumps.
- Releases should be distributed with checksums and signatures.

## Implementation direction

The engine is planned as a Rust application. Likely building blocks include:

- `clap` for the command-line interface;
- `serde` and `serde_json` for protocol messages;
- `tracing` for diagnostic logs;
- `semver` for compatibility checks;
- `thiserror` for a stable error taxonomy;
- `sha2` for release asset verification.

External processes should be started with explicit argument lists through
`std::process::Command`. Shell execution should be limited to isolated cases
where it is genuinely required.

## Development

The project requires Rust 1.85 or newer. The repository toolchain file selects
the current stable toolchain for local development.

```console
cargo build
cargo test --all-features
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

Run a command locally with:

```console
cargo run -- version --output json
cargo run -- capabilities --output json
cargo run -- doctor --output json
```

macOS is useful for development, but production builds and operational behavior
target Linux. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution and
validation workflow.

External process execution follows the bounded timeout, output, and
cancellation contract in [docs/subprocess.md](./docs/subprocess.md).

## Roadmap

1. ~~Define the protocol, privilege model, and threat model.~~ Done.
2. ~~Build `version`, `capabilities`, and `doctor` with Linux releases for
   AMD64 and ARM64.~~ Done.
3. ~~Implement and test a Git deploy/rollback pilot.~~ Done.
4. Signed releases, atomic upgrades, audit logging, and recovery procedures —
   done and tested; rotating off the TEST-ONLY signing key remains before a
   real release.
5. Migrate additional operations only where the structured boundary provides a
   measurable benefit — in progress (Phase 8); see [PLAN.md](./PLAN.md) for
   what has shipped and what's next.

Detailed implementation milestones live in the docs repository's
[`operations-engine/milestones`](https://github.com/local-control-panel/docs/tree/main/operations-engine/milestones).
The authoritative execution order and current status live in [PLAN.md](./PLAN.md).

## Naming

**Operations Engine** and `ops-engine` are neutral working names. They do not
depend on the name of any client product. A stable product prefix may be added
before the first public release without changing the component's architectural
role.

## License

This project is licensed under the terms in [LICENSE](./LICENSE).
