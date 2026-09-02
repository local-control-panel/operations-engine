# Operations Engine

Operations Engine is a Linux-only command-line execution layer for structured,
reliable server operations.

It is designed to be installed on managed servers and invoked by a control
plane over an existing SSH connection. Instead of assembling long shell
scripts remotely, a client calls a versioned operation and receives a
machine-readable result.

> [!IMPORTANT]
> This project is in the planning and early development stage. The command-line
> interface, protocol, and installation process are not stable yet.

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

## Proposed command surface

The initial command surface is expected to be small:

```console
ops-engine version --output json
ops-engine capabilities --output json
ops-engine doctor --output json
ops-engine stack status --output json
ops-engine site inspect --domain example.com --output json
ops-engine site deploy --domain example.com --revision abc123 --output json
ops-engine site rollback --domain example.com --revision abc123 --output json
ops-engine reconcile --output json
```

Git deploy and rollback are the proposed first end-to-end workflow. They provide
a useful test of locking, filesystem staging, Git state, progress reporting,
recovery, and compatibility between client and engine versions.

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

## Roadmap

1. Define the protocol, privilege model, and threat model.
2. Build `version`, `capabilities`, and `doctor` with Linux releases for AMD64
   and ARM64.
3. Implement and test a Git deploy/rollback pilot.
4. Add signed releases, atomic upgrades, audit logging, and recovery procedures.
5. Migrate additional operations only where the structured boundary provides a
   measurable benefit.

Detailed implementation milestones live in [`docs/milestones`](./docs/milestones).

## Naming

**Operations Engine** and `ops-engine` are neutral working names. They do not
depend on the name of any client product. A stable product prefix may be added
before the first public release without changing the component's architectural
role.

## License

This project is licensed under the terms in [LICENSE](./LICENSE).
