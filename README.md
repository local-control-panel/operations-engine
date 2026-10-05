# Operations Engine

Operations Engine is a Linux command-line execution layer for typed server
mutations. A control plane, currently `website-control-panel`, invokes
`ops-engine` over SSH and receives a versioned JSON response. The engine runs
on the managed host; it has no daemon or inbound API.

The project is in selective migration and release preparation. It is not yet
production release ready: the signing key, real tagged release, pinned panel
installation, and live Linux rollout remain open. [PLAN.md](./PLAN.md) tracks
those gates.

## How it works

```text
website-control-panel or another client
    -> SSH: ops-engine <command> --output json
    -> validated operation on the managed Linux host
    -> Docker, Git, filesystem, database, or system service
```

The panel owns its user-facing state and local metadata. The engine validates
each request again at the server boundary and uses bounded subprocesses,
resource locks, idempotency records, transaction state, and audit events for
mutations. These mechanisms do not make every workflow automatically
reversible. In particular, `db.restore` has no automatic rollback or final
application health probe, and an SSH disconnect does not turn a synchronous
operation into a background job.

## Supported surface

Run `ops-engine capabilities --output json` against the installed binary for
its authoritative operation list. The current source includes:

- Site Git deploy and rollback; ingress, runtime, cron, Compose, and host
  configuration activation.
- MariaDB, PostgreSQL, Valkey, database tool, export, restore, and backup
  operations. `backup.importRemote` stages a remote artifact only after a
  SHA-256 match; the panel separately performs site-bound restore with a
  safety backup.
- WordPress install, clone, bounded WXR import, updates, cleanup, credential
  rotation, and multisite subsite deletion.
- Permissions repair, Meilisearch lifecycle, system updates, Docker start,
  agent configuration, and engine install/rollback.

Interactive terminals, arbitrary shell execution, general file browsing, and
live log streaming are outside this privileged API. Some panel mutations
still use older paths.

## CLI and protocol

```console
ops-engine version --output json
ops-engine capabilities --output json
ops-engine doctor --output json
ops-engine backup import-remote --request-file /path/to/root-owned-plan.json --request-id <uuid> --output json
```

Mutation commands use typed arguments or a bounded, root-owned request file.
The engine emits one JSON response on stdout, with `protocolVersion`,
`operation`, `ok`, `result`, `warnings`, and `error` fields. Diagnostics go to
stderr. `capabilities` currently reports JSON output and does not advertise
JSON Lines progress or cancellation as protocol features. Clients check the
protocol version and required operation before dispatch.

`operation status` reads durable mutation state; it does not retry a mutation.
Request IDs and optional idempotency keys let callers distinguish a replay
from a new attempt. Review each operation's contract for its commit point,
failure state, and recovery limits.

## Security boundary

- Install the privileged binary as root-owned and restrict the caller's sudo
  access to approved commands.
- Validate domains, paths, container names, operation parameters, and the
  configured content and state roots on the host.
- Use explicit subprocess argument lists, bounded time and output, and
  capability-based filesystem access for mutations.
- Keep secrets out of protocol output and audit records. Use verified release
  artifacts for production installation once the release gate is complete.

The current release signing material is **test only**. Do not treat the
existing test fixtures as a production distribution channel.

## Development

Rust 1.85 is the minimum supported compiler. The repository toolchain file
selects the local development toolchain. CI runs these checks on Linux:

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo +1.85.0 check --all-features
```

macOS is useful for development; operational behavior and releases target
Linux. See [CONTRIBUTING.md](./CONTRIBUTING.md) for command design and
validation rules, [docs/subprocess.md](./docs/subprocess.md) for subprocess
limits, and [PLAN.md](./PLAN.md) for current priorities.

## License

This project is licensed under the PolyForm Noncommercial License 1.0.0 with
additional public-source conditions; see [LICENSE](./LICENSE). Commercial use
requires separate written permission.
