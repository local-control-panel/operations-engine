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

## `operation.status`

`operation status` accepts exactly one scope selector — `--site-id <uuid>` for
site deploy/rollback, `--database <name>` for `db.restore`, or
`--backup-database <name>` for `backup.createDatabase` — plus
`--request-id <uuid>`. It reads one durable transaction without retrying or
otherwise executing the mutation.
The result mirrors the stored transaction (`operation`, `status`, timestamps,
safe outcome and idempotency key) and adds `active`. For an `IN_PROGRESS`
transaction, `active` is true only when the same request currently owns the
site's kernel-backed mutation lock. `IN_PROGRESS` plus `active: false` is an
interrupted transaction that requires operation-specific recovery; stale lock
file contents alone never make it active. A missing transaction returns
`NOT_FOUND` and never creates a replacement transaction.

## `operation.list`

`operation list` takes exactly one scope selector (`--site-id`, `--database`,
`--backup-database` or `--stack wcp`) and an optional `--limit` (default 20,
clamped to 100). It returns the newest durable transactions of that scope
first and never executes or retries a mutation. Each entry carries only
`requestId`, `operation`, `status`, start/finish times, `errorCode`, `active`
and `nextAction`; the stored result, the error message text and the
idempotency key are deliberately omitted. `nextAction` is `none` for a
finished transaction, `wait` while the same request owns the mutation lock and
`manualRecovery` for an interrupted `IN_PROGRESS` transaction without a live
owner. The engine never names an automatic retry for interrupted work. A
scope that never ran a mutation returns an empty list. `unreadable` counts
records that exist but could not be parsed and `truncated` is true when more
records exist than were returned.

## `journal.append`, `journal.list`

The change journal answers "who changed what on which site, when, with which
result". The engine is the source of truth; the panel appends its own events
and reads the list. `capabilities` advertises it as `features.journal`.

`journal append` takes `--actor`, `--action`, `--result` and optional `--site`,
`--operation-id`, `--target`, `--error-code`, `--summary`, plus `--request-id`
(canonical UUID, becomes the entry id) and an optional `--idempotency-key`.
The engine assigns `seq` (strictly increasing, the pagination cursor), the
time (`atUnixSecs`, engine clock) and `source: "api"`. A retry with the same
request id or idempotency key returns the stored entry with `replayed: true`
and writes nothing; the check covers the recent tail of the active segment.

Validation is closed and server-side, and a rejected value is never echoed:

- `action` is `namespace.name[.name[.name]]` with a namespace from a closed set
  (`agent auth backup cms compose cron db docker drupal engine file ingress
  joomla panel runtime site stack system tool wordpress`) and camelCase
  segments, at most 64 characters (`cms.adminLogin`, `wordpress.updateCore`).
- `result` is `ok`, `failed`, `denied` or `cancelled`; `errorCode` is
  `UPPER_SNAKE_CASE` (at most 48).
- `actor`, `site`, `operationId` and `target` are short identifiers (at most
  64 characters of `A-Za-z0-9._-`, plus `@:+` for actor/target and `:` for
  operation id) with no run of 40 or more opaque characters. `target` is the
  thing acted on, for example an admin user name; it can never hold a link.
- `summary` is optional free text of at most 200 characters, rejected when it
  contains a URL (`://`, `www.`), a query pair (`?x=`), a secret-looking word
  followed by `=` or `:` (password, token, secret, apikey, authorization,
  cookie, nonce, signature, ...), a bearer value, a PEM header, a well-known
  token prefix (`eyJ`, `AKIA`, `ghp_`, ...), a run of 32 or more base64/hex
  characters or a control character.

Never put secrets or one-time login links in any field. For a one-time admin
login the journal records only the fact (`cms.adminLogin`) and the admin user
(`target`), never the link.

`journal list` is read-only and returns the newest entries first. Filters:
`--site`, `--since <unix secs>`, `--action-prefix`, `--result`, `--source`
(`api` or `engine`), `--limit` (default 50, clamped to 200) and
`--before-seq` (the previous page's `nextCursor`). The result is `entries`,
`nextCursor` (absent on the last page) and `skipped` (stored lines that could
not be parsed). A journal that was never written is an empty list.

Storage is `<stateRoot>/journal/` (`0700`, root-owned): `events.jsonl` (the
active JSON Lines segment) and rotated `events.<lastSeq>.jsonl` segments, all
`0600`. Appends and reads serialize on `journal.lock` (`flock`, waits up to 3
seconds, then `CONFLICT`). A segment rotates at 2 MiB, at most 10 rotated
segments are kept and a rotated segment untouched for 400 days is removed.
A torn last line after a crash is skipped by readers and does not swallow the
next entry.

The engine journals its own operations (`source: "engine"`, `actor:
"engine"`, the request id as entry id and `operationId`) for the ones whose
identity is on the command line: `site.deploy`, `site.rollback`,
`site.renameManifest`, `site.unenroll`, `engine.install` and
`engine.rollback`. The write is best effort and never changes the operation's
response; an operation rejected as `INVALID_INPUT` is not journaled. Other
mutating operations are not journaled yet (they name their target in a
request file or by domain, and need their own secret-free way to name the
site); they are listed in the CMS-core design notes as a follow-up.

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

## `db.clearMariaSlowLog`

`db clear-mariadb-slow-log` accepts a root-owned request containing a validated
container name and root credential. Under a per-container lock it reads the
configured log path and enabled state, disables logging, invokes only the fixed
`truncate -s 0 <absolute-path>` argv inside the container, and restores the
previous enabled state. The path never enters a shell command. Requests have
idempotent transaction state and an append-only audit record.

## `db.configureMariaSlowLog`

`db configure-mariadb-slow-log` accepts a root-owned request containing a
validated container, root credential, enabled flag and optional finite
`longQueryTime` in the inclusive `0..=3600` range. When enabling, the threshold
is applied before the log is enabled; disabling ignores the optional threshold.
The fixed MariaDB argv runs under the same per-container lock namespace as
`db.clearMariaSlowLog`, with idempotent transaction state and audit records.

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

## `backup.createDatabase`

`backup create-database` accepts a root-owned JSON request containing a
validated database type/name, container, root password and retention window.
The fixed `mariadb-dump` or `pg_dump` argv streams stdout directly into an
exclusively-created temporary file beneath `/root/db-backups`; successful
completion atomically renames it to `<database>_<unix-seconds>.sql`, while a
failed or cancelled dump removes the temporary artifact. Retention deletes
only older `.sql` files carrying the same validated database prefix.

## `backup.scheduleDatabase`, `backup.unscheduleDatabase`, `backup.listScheduledDatabase`, `backup.runScheduledDatabase`

Scheduled database backups keep the database root password out of every
crontab line. `backup schedule-database` accepts a root-owned JSON request
(`dbType`, `database`, `container`, `rootPassword`, `schedule`,
`retentionDays`). The schedule is an allowlisted cron expression (five
`[0-9A-Za-z*/,-]` fields or `@hourly|@daily|@midnight|@weekly|@monthly|@yearly|
@annually`; `%`, `#`, newlines and `@reboot` are rejected). Under the same
`cron/root` lock `cron.installTab` uses, the engine writes
`<credentialRoot>/db-backup/<dbType>_<database>.json` (directory `0700`, file
`0600`, atomically), then installs the root crontab with one line:

```
<schedule> /usr/local/bin/ops-engine backup run-scheduled --db-type <t> --database <db> --retention-days <n> >/dev/null # [db-backup] <t>:<db>
```

The crontab is re-read just before the install and the request fails with
`CONFIG_HASH_MISMATCH` if it changed meanwhile; a rejected crontab restores the
previous credential file (or removes the new one). An existing line for the
same database and schedule, in either format, is replaced; other lines are
preserved byte for byte.

`backup unschedule-database` takes `dbType`, `database` and `schedule`, removes
the matching tagged lines (either format, enabled or disabled) and, after the
install succeeded, deletes the credential file when no engine-format line for
that database remains.

`backup list-scheduled` is read-only. It returns every `# [db-backup]`
line as `{line, schedule, dbType, database, retentionDays, enabled, format,
secretInCrontab}` where `format` is `engine` or `legacy`. For legacy lines
(the pre-engine `mariadb-dump -p'...'` / `PGPASSWORD='...'` form) the password
in `line` is replaced by `[redacted]` and `secretInCrontab` is true; they keep
running unchanged until they are removed or scheduled again.

`backup run-scheduled` is what cron runs. It refuses a credential file that is
group/other accessible, then goes through the same transactional path as
`backup.createDatabase` (per-database lock, `MYSQL_PWD`/`PGPASSWORD` only in the
process environment, atomic publish, retention). A failure is also printed to
stderr so cron can mail it.

## `backup.activateConfig`

`backup activate-config` consumes one root-owned bounded JSON plan containing
the three remote-backup configs, agent script and complete crontab. Four files
are staged beneath `/root/.wcp`, activated with exact modes and reverse-order
rollback, then `crontab -` is installed over stdin as the final commit step.
The operation uses a host-wide lock, idempotent transaction state and redacted
audit records; no submitted config or credential is persisted in engine state.

## `backup.triggerNow`

`backup trigger-now` accepts only a request ID and optional idempotency key; it
has no caller-controlled command, path or payload. The engine invokes the fixed
`bash /root/.wcp/agents/backup-agent.sh` argv with a six-hour timeout under one
host-wide lock. Retries replay the recorded result instead of starting a second
backup, and completion or failure is recorded in the transaction and audit log.

## `wordpress.cleanup`

`wordpress cleanup` accepts a root-owned JSON request selecting one of four
fixed cleanup actions together with a validated runtime container, WordPress
root and site UID/GID. The root must be beneath a configured content root. The
engine invokes `docker exec` with a fixed argv and passes the developer-owned
PHP fragment as one argument to `wp eval`; no caller-controlled command text
is interpreted by a shell.

## `wordpress.install`

`wordpress install` accepts a root-owned JSON request containing the
validated runtime container, WordPress root, site UID/GID, domain, site
title, admin credentials and already-provisioned database/cache connection
details. The WordPress root must already exist beneath a configured content
root (the control plane's own site-creation step creates and owns it) and
must not escape that root through a symlink; this operation never creates
or removes that directory itself. Under a per-site lock, it runs a fixed
WP-CLI sequence as the site's own UID/GID: `wp core download` (with a fixed
`bg_BG`, falling back to `en_US`, locale), `wp config create` and `wp core
install` are the critical path — any failure fails the whole request, with
no partial WP-CLI argument accepted from the caller. Object-cache wiring,
the bundled cache plugin and disabling native WP-Cron run afterward as
best-effort steps whose own output is not checked, matching the raw-shell
behavior this operation replaces. The operation is idempotent and
transaction/audit recorded like every other WordPress mutation here.

## `wordpress.clone`

`wordpress clone` accepts a root-owned JSON request naming the source and
staging WordPress roots (each validated beneath a configured content root,
neither nested inside the other), their runtime containers/UID-GID pairs,
the MariaDB container, the already-provisioned staging database name and
the MariaDB root password. Under one lock scoped to the staging root, the
engine (re)creates the staging directory fresh - any prior contents are
removed first, mirroring the `rsync --delete` this replaces - and populates
it with a fixed, bounded `cp -a` subprocess; exports the source database
with `wp db export -` into a request-scoped file beneath the fixed backup
root; imports it into the staging database with the same bounded restore
client `db.restore` uses, deleting the dump immediately afterward either
way; and finally re-chowns the copied tree to the staging site's own
UID/GID with `permissions.fixOwnership`'s own fd-relative repair walk. Any
failure removes the staging directory this request itself (re)created. The
operation is idempotent and transaction/audit recorded; `wp-config.php`'s
DB credentials and the source→staging domain search-replace remain outside
it, run by the client afterward.

## `wordpress.updateCore`

`wordpress update-core` accepts a root-owned typed request containing the
validated runtime container, WordPress root, site UID/GID and an optional
bounded version. Under a per-site lock, the engine first streams a complete
site archive and `wp db export -` into a request-specific recovery directory
beneath `/root/db-backups/wordpress-updates`. Only after both recovery
artifacts complete does it invoke the fixed `wp core update` argv as the site
UID/GID. The operation is idempotent and transaction/audit recorded; no shell
command or free-form WP-CLI argument is accepted.

## `wordpress.updatePlugins`

`wordpress update-plugins` reuses the recovery-first, per-site transaction
boundary of `wordpress.updateCore`. It accepts either an empty plugin list,
which maps only to the fixed `--all` flag, or at most 128 validated plugin
slugs. A full site archive and database export must complete before the fixed
site-UID `wp plugin update` argv runs. Plugin names never enter a shell.

## `wordpress.updateThemes`

`wordpress update-themes` uses the same recovery-first per-site transaction.
It accepts an empty theme list only as the fixed `--all` mode, or at most 128
bounded theme slugs. The full site archive and database export must complete
before the fixed site-UID `wp theme update` argv runs; no theme name is
interpreted by a shell.

## `wordpress.rotateCredentials`

`wordpress rotate-credentials` accepts a root-owned JSON request containing
the validated runtime container, WordPress root, site UID/GID, the MariaDB
container, the MariaDB root password and a caller-generated new password.
Under a per-site lock, the engine reads the site's current `DB_USER` and
`DB_PASSWORD` out of `wp-config.php`, applies the new password to the
MariaDB account with `ALTER USER ... IDENTIFIED BY` (fed to `mariadb` over
stdin, like `db.provisionMariaDb`) and writes it to `wp-config.php` with `wp
config set`, then verifies database connectivity with `wp db check`. If
writing the new password or the connectivity check fails, both MariaDB and
`wp-config.php` are reverted to the prior password before the request
fails. The MariaDB root password and both the old and new site passwords
never appear in a subprocess argument list. The operation is idempotent and
transaction/audit recorded like every other WordPress mutation here.

## `wordpress.dropTables`

`wordpress drop-tables` accepts a root-owned JSON request containing the
validated runtime container, WordPress root, site UID/GID and an explicit list
of 1..=200 unique table names (`[A-Za-z0-9_$]`, at most 64 bytes each). Under a
per-site lock the engine re-reads, as the site user, the `table_prefix`
(`wp config get`), every table carrying that prefix
(`wp db tables --all-tables-with-prefix`) and the set WordPress registers
(`wp db tables --scope=all`, plus `--network` on a multisite). A table is
dropped with a fixed ``DROP TABLE IF EXISTS `name` `` only when it carries the
prefix, still exists and is not registered; core and registered tables are
always refused. The result lists every requested table as `dropped` or
`refused` with a reason (`wrongPrefix`, `notFound`, `registered`,
`dropFailed`). If the registered listing does not contain the core
`{prefix}options` table the request fails before anything is dropped. The
operation is transaction/audit recorded and replays its outcome for a retried
request with the same idempotency key, like every other WordPress mutation.
It takes no backup: callers are expected to have shown the user the exact
names (and typically to have taken a database export) before sending them.

## `tool.install`, `tool.remove`, `tool.status`

Host-managed tools are mounted read-only into the runtime containers instead of
being baked into their images. The catalog is compiled into the engine: one
pinned official release URL, exact version and SHA-256 per tool (today only
`wp-cli`, from the official `wp-cli/wp-cli` GitHub release; the pin was
cross-checked against the `.sha256` and `.sha512` the release publishes).
Requests name only a catalog tool; there is no way to supply a URL, version
or path.

`tool install --tool wp-cli --request-id <uuid> [--idempotency-key <key>]`
downloads the pinned release over HTTPS with a size and time bound, verifies
the SHA-256 and that the file has the expected shape (for WP-CLI, a PHP phar),
and installs it root-owned and executable as
`/var/lib/wcp/tools/wp-cli/<version>/wp.phar`. A relative `current` symlink is
switched to the new version with a same-directory atomic rename, so a
container reading `/var/lib/wcp/tools/wp-cli/current/wp.phar` sees either the
old or the new file. Other version directories are pruned. An intact install
of the pinned version is left alone (`changed: false`) without downloading; a
damaged one is repaired. Download failures are reported as
`artifact_fetch_failed` / `timeout`, digest or shape mismatches as
`artifact_verification_failed`, and nothing is installed in either case.

`tool remove --tool wp-cli` removes `current` first and then the tool
directory; removing an absent tool is `changed: false`.

`tool status` returns, for every catalog tool, the pinned version, the
installed version `current` points at, whether the tool is recorded as
selected on this host, and whether the installed file still hashes to its
pinned digest (`intact`).

Install and remove run under one per-host lock, are transaction/audit
recorded, and replay their outcome for a retried request with the same
idempotency key. The selection is recorded in the engine state root
(`tools/selection.json`).

## `drupal.cacheRebuild`, `drupal.cronRun`, `drupal.maintenance`

`drupal cache-rebuild`, `drupal cron-run` and `drupal maintenance` each accept
a root-owned JSON request with the validated runtime container, the Drupal
project root, the public document root (the project root itself or a directory
below it), the site UID/GID and, for `maintenance` only, an explicit
`"state": "on"` or `"off"`. Unknown fields are rejected, so there is no way to
name a Drush command or argument: the operation selects a fixed argv
(`cache:rebuild`, `core:cron`, or `state:set system.maintenance_mode 1|0
--input-format=integer` followed by `cache:rebuild`).

Under a per-site lock the engine runs Drush inside the site's container as the
site user, never root, from the project root: the project's own
`vendor/bin/drush` when it is executable, `drush` on `PATH` otherwise, with
`--root=<document root>`. `maintenance` reads `system.maintenance_mode` back
and fails the request if Drupal does not report the requested state. Output is
bounded and the response carries no Drush output, only the action, the
maintenance mode read back (for `maintenance`) and the completion time. The
operations are transaction/audit recorded and replay their outcome for a
retried request with the same idempotency key.

## `agent.activateBruteforceConfig`

`agent activate-bruteforce-config` accepts a root-owned JSON request with the
complete typed `wpLogin` and `caddy` jail configuration. Every numeric
threshold must be within `1..=1_000_000`. The engine renders the fixed env-file
shape itself and atomically replaces `bruteforce-config.env` through a
directory capability rooted at `/root/.wcp`.

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
