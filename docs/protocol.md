# Protocol

Operations Engine protocol version 1 uses one JSON object per completed
operation. Long-running operations may later add JSON Lines progress events,
but that feature is not implemented yet.

## Response envelope

```json
{
  "protocolVersion": 1,
  "operation": "version",
  "ok": true,
  "result": {},
  "warnings": [],
  "error": null
}
```

| Field | Meaning |
| --- | --- |
| `protocolVersion` | Version of the response contract, independent of the binary version. |
| `operation` | Stable operation identifier. |
| `ok` | Whether the operation completed successfully. |
| `result` | Operation-specific result, or `null` after a failure. |
| `warnings` | Non-fatal machine-readable warnings. |
| `error` | Stable error code, safe message, and optional structured details. |

## Output rules

- Field names use `camelCase`.
- stdout contains protocol output only.
- stderr contains human-oriented diagnostic logs.
- Secret values and raw environment dumps are forbidden in both streams.
- Clients must ignore unknown result fields within a compatible protocol
  version.
- Clients must reject unsupported protocol versions rather than attempting to
  interpret them.
- Operation and warning codes are stable API values, not display text.

## Version negotiation

Clients should call `version` and `capabilities` before using operations whose
availability depends on the installed engine version. The engine semantic
version describes a release; `protocolVersion` describes the wire contract.
Neither value substitutes for the other.

Protocol-breaking changes require a new protocol version. Adding an optional
result field or a new capability does not necessarily require one.

## `cron.installTab`

`cron install-tab` atomically replaces a complete crontab with an optimistic
SHA-256 guard. The optional `--user` selects a named host account; it is a
strictly validated identifier and is passed to `crontab` as separate `-u` and
value arguments. Transactions and locks are scoped per target user.

## `permissions.fixOwnership`

`permissions fix-ownership` accepts `--owners-file`, `--request-id`, and an
optional `--idempotency-key`. The owners file is root-owned JSON:

```json
{
  "default": { "root": "/var/www", "uid": 33, "gid": 33 },
  "targets": [
    { "root": "/var/www/example.com", "uid": 10001, "gid": 10001 }
  ]
}
```

The default root must exactly match a configured `contentRoot`; every target
must be a non-overlapping strict descendant. The engine repairs each target,
then repairs the default tree while excluding those targets. It stays on each
root's filesystem, skips symbolic links, and applies ownership with
`AT_SYMLINK_NOFOLLOW`. The result reports `processedRoots`, `repairedEntries`,
and `completedAtUnixSecs`. Request and result are persisted in the engine's
transaction/audit trail.

## `permissions.fixWorldWritable`

`permissions fix-world-writable` accepts `--root`, `--request-id`, and an
optional `--idempotency-key`. The root must exactly match a configured
`contentRoot`. The engine walks regular files and directories without crossing
mount points or following symbolic links, removes only the world-write bit, and
preserves every other mode bit. The result reports `processedRoots`,
`hardenedEntries`, and `completedAtUnixSecs`; transaction and audit behavior is
the same as for ownership repair.

## `dbTool.converge`

`db tool-converge` accepts a root-owned JSON plan selecting exactly
`phpMyAdmin|adminer` and `install|start|stop`. Install additionally requires a
validated domain and supports the allowlisted `mariadb|postgresql` Adminer
default. Container names, images (version plus manifest digest), networks,
restart policy, security options, labels, ports, and environment keys are fixed
by the engine and never accepted as caller-provided command fragments.

## `dbTool.remove`

`db tool-remove` accepts a root-owned JSON plan selecting `phpMyAdmin|adminer`
and an optional validated domain. When a route exists, the engine atomically
moves it outside Caddy's import glob, validates and reloads the remaining
configuration, and only then removes the fixed container. A failed container
removal restores the route and reloads Caddy before returning failure.

## `db.provisionMariaDb`

`db provision-mariadb` accepts a root-owned, non-group/world-writable JSON
request file plus `--request-id` and optional `--idempotency-key`. It may create
or ensure a database, create or ensure a user, and independently grant access
to an existing validated database. At least one action is required.

The root password and generated SQL are delivered to a fixed MariaDB client
command over stdin; neither appears in host process argv, protocol envelopes,
audit records, or subprocess diagnostics.

## `db.dropMariaDb`

`db drop-mariadb` accepts a root-owned JSON request containing a validated
container name, database identifier and MariaDB root password. The system
schemas `mysql`, `information_schema`, `performance_schema` and `sys` are
rejected case-insensitively. The password and generated `DROP DATABASE`
statement travel only over stdin. Per-database mutation state provides
locking, idempotent replay and an append-only audit record.

## `db.export`

`db export` accepts a root-owned JSON request containing the database type,
validated database/container identifiers and root credential. It invokes only
the fixed MariaDB or PostgreSQL dump argv and returns UTF-8 SQL in the result.
The response is capped at 64 MiB and the subprocess at five minutes; truncated,
failed or non-UTF-8 output is rejected rather than returned as a partial dump.

## `db.dropMariaDbUser`

`db drop-mariadb-user` accepts a root-owned JSON request containing a validated
container name, MariaDB account name, host and root password. The engine
rejects `root`, `mysql`, `mariadb.sys` and `healthcheck` accounts
case-insensitively. The password and generated `DROP USER` statement travel
only over stdin; the account name and host contain no SQL quoting characters.
Each `user@host` account has an independent mutation lock, idempotency state
and audit trail.

## `db.deleteValkeyKey`

`db delete-valkey-key` accepts a root-owned JSON request containing a validated
container name and one non-empty Valkey key of at most 4096 UTF-8 bytes. The
key is sent verbatim over stdin to the fixed `valkey-cli -x DEL` invocation and
never appears in process argv, transaction results or audit records. Lock and
transaction state are scoped by the key's SHA-256 digest. The result reports
whether the key existed and was deleted.

## `db.flushValkeyDb`

`db flush-valkey-db` accepts a root-owned JSON request containing a validated
container name and the exact confirmation token `FLUSHDB`. The engine rejects
missing, differently-cased or broader tokens before execution, then invokes
only the fixed `valkey-cli FLUSHDB ASYNC` argv. Per-container locking,
idempotency, transaction state and audit records prevent overlapping or
ambiguous retries. The operation never exposes a generic Valkey command.

## `db.flushAllValkey`

`db flush-all-valkey` accepts a root-owned JSON request containing a validated
container name and the exact confirmation token `FLUSHALL`. `FLUSHDB` and all
other variants are rejected before execution. The engine invokes only the
fixed `valkey-cli FLUSHALL ASYNC` argv and serializes the host-wide mutation
with its own per-container lock, idempotency state and audit trail.

## `backup.delete`

`backup delete` accepts a root-owned JSON request naming one `.sql` or
`.sql.gz` artifact beneath the fixed `/root/db-backups` root. The engine strips
that exact prefix, validates the remainder as a normal relative path and
deletes through an opened directory capability. It cannot delete a directory
or escape through traversal or symlink resolution. Missing files are an
idempotent success reported as `deleted: false`; transaction scope stores only
a SHA-256 digest of the relative path.

## `db.provisionPostgres`

`db provision-postgres` accepts a root-owned JSON request containing a
validated container name, database identifier, and PostgreSQL root password.
The engine invokes a fixed `psql` command with `ON_ERROR_STOP` and sends both
the password and generated `CREATE DATABASE` statement through stdin. Neither
the credential nor caller-provided command fragments appear in process argv.

## `db.dropPostgres`

`db drop-postgres` accepts a root-owned JSON request containing a validated
container name, database identifier and PostgreSQL root password. The system
databases `postgres`, `template0` and `template1` are rejected. The engine uses
the fixed `DROP DATABASE <identifier> WITH (FORCE)` operation, which closes
active sessions as part of the drop instead of exposing a terminate/drop race.
The password and generated SQL travel only over stdin.

## `db.provisionPostgresUser`

`db provision-postgres-user` creates a validated login role and may grant it
access to one validated database. The `postgres` role and the reserved `pg_`
namespace are rejected. Role creation and the optional grant share one SQL
transaction. Root and user passwords, together with generated SQL, travel only
over stdin and never appear in process argv or persisted transaction state.

## `db.dropPostgresUser`

`db drop-postgres-user` removes one validated role. The `postgres` role and
the reserved `pg_` namespace are rejected before execution. The root password
and fixed `DROP ROLE` statement travel only over stdin; PostgreSQL dependency
errors fail closed without attempting ownership reassignment or cascading
object deletion.

## Exit status

An envelope with `ok: true` exits with status 0. An envelope with `ok: false`
exits with a non-zero status. CLI parsing errors occur before an operation is
selected and are currently emitted by the argument parser on stderr.

If an operation result cannot be serialized, the engine returns an unsuccessful
envelope with code `INTERNAL_SERIALIZATION_ERROR`. It does not emit a partial
result or panic while constructing the response.

## Error taxonomy

Protocol version 1 reserves these stable codes:

| Code | Meaning |
| --- | --- |
| `INVALID_INPUT` | The request failed validation before work began. |
| `UNSUPPORTED_PLATFORM` | The host platform cannot run the requested operation. |
| `DEPENDENCY_UNAVAILABLE` | A required local executable or service is unavailable. |
| `CONFLICT` | Another operation or current state prevents this request. |
| `TIMEOUT` | Work exceeded its documented time bound. |
| `CANCELLED` | Cancellation was accepted before the operation completed. |
| `SUBPROCESS_FAILED` | A bounded external process exited unsuccessfully. |
| `INTERNAL_SERIALIZATION_ERROR` | A result could not be encoded safely. |
| `INTERNAL` | An unexpected internal failure occurred. |
| `ARTIFACT_FETCH_FAILED` | A release manifest or binary could not be downloaded (`engine install`). |
| `ARTIFACT_VERIFICATION_FAILED` | A downloaded manifest or binary failed signature, checksum, or version verification (`engine install`). |
| `ARTIFACT_NOT_RUNNABLE` | A verified binary did not run on this host during its pre-activation smoke test, so it was rejected before anything was activated (`engine install`). |

Error messages are safe summaries for operators, not stable API values. The
optional `details` object is `null` unless an operation documents an allowlisted
shape for its error code. It must contain identifiers, limits, or state needed
for recovery—not command lines, environment variables, unrestricted paths,
subprocess output, or secret-bearing input.

## Warning taxonomy

Warnings ride alongside a successful (`ok: true`) response — the operation's
primary effect happened, but something adjacent to it needs attention.

| Code | Meaning |
| --- | --- |
| `UNSUPPORTED_PLATFORM` | `doctor` found a dependency check that cannot run on this host's platform. |
| `DEPENDENCY_UNAVAILABLE` | `doctor` found a required local executable or service missing. |
| `TRANSACTION_RECORD_INCOMPLETE` | A mutation completed and its reported state really changed, but its transaction record could not be persisted afterward. The result is genuine; only the durable bookkeeping is in question. |
| `INSTALL_STATE_RECORD_INCOMPLETE` | An `engine install`/`engine rollback` completed - the binary at `/usr/local/bin/ops-engine` really was switched - but the record naming the active and rollback-able versions could not be written afterward. Operationally significant: until repaired, `engine rollback` restores the version named by the stale record, not the one just replaced. |

## Doctor semantics

`doctor` is a diagnostic query. A successful diagnostic execution returns
`ok: true` even when the host is not ready. Consumers must inspect
`result.ready` and individual dependency checks:

- `passed`: the dependency executed successfully;
- `missing`: the executable could not be started;
- `failed`: it started but did not complete successfully;
- `timedOut`: the check exceeded its two-second bound.

An unsupported platform or unavailable dependency makes `ready` false and adds
a machine-readable warning. These conditions become operation errors only when
a requested operation requires the missing capability.
