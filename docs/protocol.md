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

## `secretResult`

A response whose `result` carries a value that must reach the caller exactly
once and must never be stored (a one-time login link) sets the top-level
envelope field `"secretResult": true` (the field is absent on every ordinary
response). The rule, which clients must follow:

- Do not persist, log, cache or replay a response with `secretResult: true`.
  Show it once and keep it in memory only.
- The engine splits such a result into a *public* part and a *secret* part
  (`src/secret_result.rs`). Only the public part is written to the transaction
  state, only the public part is returned by an idempotent replay, and
  `operation.status`/`operation.list` can therefore never expose the secret.
  The secret is not written to the audit trail, the change journal or stderr,
  and the response type redacts it in `Debug` output.
- A replay (same idempotency key) succeeds with the stored public fields plus
  `alreadyIssued: true`, no secret, no `secretResult` flag and the warning
  `SECRET_RESULT_ALREADY_ISSUED`. A new secret needs a new idempotency key.

## `site.adminUsers`, `site.adminLogin`

One-time administrator login. Implemented for WordPress (`"cms":
"wordpress"`), Joomla (`"cms": "joomla"`) and Drupal (`"cms": "drupal"`,
through the engine-managed Drush). Other kinds are refused with
`INVALID_INPUT`. `capabilities` lists the supported values in
`features.adminLoginCms`; an engine without that field supports WordPress
only.

Both take `--request-file`, a root-owned JSON plan:
`{"cms","container","root","uid","gid"}` plus, for the login,
`"adminUserId"` and an optional `"ttlSeconds"` (60 to 600, default 300).
For Drupal the plan also needs `"projectRoot"` (where `vendor/bin/drush`
lives; `root` is the public document root, e.g. `.../web`), `"siteUrl"` is
required, and `"ttlSeconds"` is **refused** (`INVALID_INPUT`). `"siteUrl"` (public base URL, `http(s)://host[:port][/path]`, no query,
fragment or credentials) is **required for Joomla** (the engine cannot know
the public address from inside the container) and ignored for WordPress. The
root must lie under a configured content root; the CMS kind comes from the
panel's `site.probe` result.

`site admin-users` is read-only and returns `users: [{id, login}]` for the
`administrator` role (at most 50, `truncated` when there are more). No emails,
no hashes.

`site admin-login` also takes `--request-id` and a **required**
`--idempotency-key`, runs under the per-site resource lock and returns, with
`secretResult: true`: `url`, `adminUserId`, `adminLogin`, `issuedAtUnixSecs`,
`expiresAtUnixSecs`. Errors: `NOT_FOUND` (no such user), `PERMISSION_DENIED`
(not an administrator), `CONFLICT` (10 unexpired links already outstanding, or
another operation in progress).

How it works on WordPress: the engine generates a 244-bit token and keeps it
in memory. The container receives (on stdin, never argv) only the user id, the
expiry and the SHA-256 of the token, and writes a mu-plugin
`wp-content/mu-plugins/wcp-otl-<expiresAt>-<random>.php` as the site user.
That file holds the hash; a request with `?wcp_otl=<token>` is compared with
`hash_equals`, the file is `unlink`ed (atomic: exactly one of several
concurrent requests wins), the administrator is logged in (`wp_login` fires)
and redirected to the dashboard with `no-store` and `Referrer-Policy:
no-referrer`. An expired file deletes itself on its next request, and every
issue removes expired files. Not covered: a site-level two-factor plugin that
only hooks the login form does not run, and the site's own web server access
log records the request line of the spent link (the token is already invalid
by then).

How it works on Joomla: Joomla has neither a CLI login nor a must-use plugin
directory, so the engine writes one minimal, self-deleting entry file
`wcp-otl-<expiresAt>-<random>.php` (0600, tmp + rename, as the site user) into
the Joomla root; the link is `<siteUrl>wcp-otl-...php?wcp_otl=<token>`. The
file holds only the token hash, the expiry, the user id and the absolute
administrator URL. The request is compared with `hash_equals`, the file is
`unlink`ed before Joomla is loaded (atomic: of several concurrent requests
exactly one continues, the rest get a 404, or a 500 if the file vanished while PHP was loading it, never a session), then Joomla's
`AdministratorApplication` is booted and the official `onUserLogin` /
`onUserAfterLogin` events run for the user (`core.login.admin`, blocked users
refused, session forked by the `joomla` user plugin), followed by a redirect
to `<siteUrl>administrator/index.php` with `no-store` and `Referrer-Policy:
no-referrer`. The "administrator" of a Joomla site is an unblocked member of a
group that holds `core.admin` (Super Users); `site.adminUsers` lists exactly
those (found by booting Joomla in CLI with `php -r`, the plan on stdin).
Expired files are removed on the next issue (at most 10 outstanding) or by
their own next request. **Joomla multi-factor authentication is not
bypassed**: a super user with a second factor lands on Joomla's MFA captive
page and must still pass it. Not covered: a web-server rule that blocks
unknown `.php` files in the root, or protection of `/administrator` (HTTP auth,
secret-URL plugins), will stop the link.

How it works on Drupal: nothing is written to the site. The engine runs, as
the site user in the site's container from `projectRoot` (project
`vendor/bin/drush` first, `drush` on `PATH` as fallback; **`DEPENDENCY_UNAVAILABLE`**
when neither exists: run `drupal.installDrush`), a fixed `drush php:eval` that
checks the user (exists, active, uid 1 or a role flagged `is_admin`;
otherwise `NOT_FOUND` / `PERMISSION_DENIED`) and reads
`user.settings:password_reset_timeout`, then `drush user:login --no-browser
--uid=<id> --uri=<siteUrl>`. The returned Drupal reset link
(`/user/reset/<uid>/<timestamp>/<hash>/login`) is the secret. **Honest
limits, reported in the result as `limits`:** `ttlFromSiteSettings` - the link
lives as long as the site's own `password_reset_timeout` (24 h by default), so
`expiresAtUnixSecs` is that real expiry (timestamp + timeout), not a request
TTL; the engine neither changes the site's configuration nor can shorten it
for one link. `singleUseNotRaceSafe` - single use comes from Drupal's own
login timestamp: after one successful open the link no longer works, but
parallel opens before that completes can each get a session (8 simultaneous
opens gave 8 sessions on Drupal 11.4 in testing). Landing is the user's
edit form (Drupal's one-time-login flow), and a site with a two-factor module
that hooks `hook_user_login` may redirect to it. The clients must show these
limits before the link is used.

The panel records only the fact in the change journal
(`site.changeLog.append`, action `cms.adminLogin`, `target` = admin login).

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
clamped to 100). It returns unfinished transactions before terminal ones,
newest first within each group, so newer rejected attempts cannot hide interrupted work. It never
executes or retries a mutation. Each entry carries only
`requestId`, `operation`, `status`, start/finish times, `errorCode`, `active`
and `nextAction`; the stored result, the error message text and the
idempotency key are deliberately omitted. `nextAction` is `none` for a
finished transaction, `wait` while the same request owns the mutation lock and
`manualRecovery` for an interrupted `IN_PROGRESS` transaction without a live
owner. The engine never names an automatic retry for interrupted work. A
scope that never ran a mutation returns an empty list. `unreadable` counts
records that exist but could not be parsed and `truncated` is true when more
readable records exist than were returned. Scanning is limited to 1,000
entries, 1 MiB per transaction and 16 MiB of transaction bytes per request.
Non-regular, oversized, malformed, unsupported-schema and filename/request-ID
mismatched records count as unreadable. `scanTruncated` is true when an entry
or total-byte scan budget is reached: returned entries prioritize unfinished
work and are sorted newest first within each group in the scanned subset,
and may omit other operations. Clients must show
that incompleteness rather than claim a complete or globally newest history.
Old engines may omit `scanTruncated`; clients treat an absent field as false.
If the kernel lock is held but its bounded diagnostic record cannot identify
the owner, the query fails rather than labelling transactions as inactive or
suggesting recovery. Optional recovery-action probes read at most 16 KiB from
a regular checkpoint or creation journal; oversized metadata never advertises
a recovery action.

## `site.changeLog.append`, `site.changeLog.list`

The change journal answers "who changed what on which site, when, with which
result". The engine is the source of truth; the panel appends its own events
and reads the list. `capabilities` advertises it as `features.changeLog`.

`change-log append` takes `--actor`, `--action`, `--result` and optional
`--site`, `--subsite`, `--environment` (`production`, `staging` or
`development`), `--operation-id`, `--target`, `--error-code`, `--summary`, plus `--request-id`
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

`change-log list` is read-only and returns the newest entries first. Filters:
`--site`, `--subsite`, `--environment`, `--since <unix secs>`, `--action-prefix`, `--result`, `--source`
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

## `ingress.applyAdminPaths`

Restricts one domain's sensitive admin paths to an IP allowlist, to Basic auth, to both at once, and/or under a per-path rate limit, or removes the restriction. Request file: `{"domain":"example.com","restriction":null}` removes it; otherwise `restriction` is `{"kind","paths":[<catalog ids>],"ips":[<ip or cidr>],"username","passwordHash":"<bcrypt>","rateLimit":{"maxHits":3-10000,"windowMinutes":1-60,"banMinutes":1-1440}}` where at least one of `ips`, the `username`/`passwordHash` pair and `rateLimit` is present. The old `mode` field is still accepted (and checked against the fields). `features.adminPathsCombined` tells a client the engine takes the combined form and `rateLimit`; without it exactly one control is accepted. With both an allowlist and Basic auth, an address outside the allowlist gets 403 before it is asked for a password. The rate limit is not a Caddy directive: the header carries it with the expanded path patterns and the `bruteforce-guard` agent (2.1.0 or newer) bans an address that makes more than `maxHits` non-static requests to those paths within `windowMinutes`, through `ingress.applyBans` (jail `admin_paths`). The catalog (kinds `wordpress`, `drupal`, `joomla`, `laravel`; ids such as `login`, `admin`) is advertised in `features.adminPaths` of `capabilities`, with the public exceptions it keeps open (WordPress `admin-ajax.php`, `admin-post.php`). The engine maps ids to paths, so a request cannot inject a matcher.

It writes `bans/admin-<domain>.caddy`, which every route already imports through `bans/*.caddy` (the same file family as `ingress.applyBans`), with a `host <domain>` matcher so it affects only that site. The file is validated, swapped in, reloaded, and put back if the reload refuses it. An allowlist answers 403 to every other address, Basic auth answers 401; an empty allowlist is refused (it would lock everyone out). Only a bcrypt hash is accepted (use `caddy hash-password`); it is written to the file and never returned, logged or recorded, and the file header (`# wcp-admin-paths {json}`) carries the settings without it so a client can read them back. Removal restores normal access; removing an absent restriction reports `changed: false` after a confirming reload.

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
key is sent verbatim over stdin to the fixed `-x DEL` invocation and
never appears in process argv, transaction results or audit records. Lock and
transaction state are scoped by the key's SHA-256 digest. The result reports
whether the key existed and was deleted.

## `db.flushValkeyDb`

`db flush-valkey-db` accepts a root-owned JSON request containing a validated
container name and the exact confirmation token `FLUSHDB`. The engine rejects
missing, differently-cased or broader tokens before execution, then invokes
only the fixed `FLUSHDB ASYNC` command. Per-container locking,
idempotency, transaction state and audit records prevent overlapping or
ambiguous retries. The operation never exposes a generic Valkey command.

## `db.flushAllValkey`

`db flush-all-valkey` accepts a root-owned JSON request containing a validated
container name and the exact confirmation token `FLUSHALL`. `FLUSHDB` and all
other variants are rejected before execution. The engine invokes only the
fixed `FLUSHALL ASYNC` command and serializes the host-wide mutation
with its own per-container lock, idempotency state and audit trail.

## Valkey access control and the administrator wrapper

Valkey runs with its `default` user off (see the `images` repository). Every
Valkey operation runs `docker exec <container> sh /etc/valkey/wcp-valkey-cli.sh
<command>`: the wrapper reads the administrator's password from the container's
own environment, so no Valkey credential appears in a request, an argv or a
log. An older Valkey container without the wrapper makes these operations fail
(`SUBPROCESS_FAILED`) rather than fall back to an unauthenticated client.

## `db.provisionValkeySite`

`db provision-valkey-site` accepts a root-owned request with a validated
container, a site `domain` (lowercase letters, digits, hyphens and dots) and the
site's `database` (1 to 255; the image sets `databases 256`, database 0 stays
with the administrator), and requires an idempotency key. It needs Valkey 9.
The engine creates the ACL user `site_<domain>`, or replaces its password:
`ACL SETUSER ... reset on #<sha256> resetkeys ~* resetchannels db=<n>`, all
commands off, then the read/write/keyspace/data-type/transaction/connection
categories with `@dangerous` and `@admin` removed, and `FLUSHDB`,
`EVAL`/`EVALSHA` allowed back. `db=<n>` limits every command, `SELECT`
included, to the site's own database, so `FLUSHDB` there empties only the
site's data (Valkey checks every command and key inside a script against the
same user). No Pub/Sub channels. `ACL SAVE` persists the user. The password is
generated here (32 alphanumeric characters), reaches Valkey only as a SHA-256
hash and is returned once as a secret result together with `username` and
`database`. The transaction state keeps only the public part; a replay returns
it with `alreadyIssued: true` and no password.

## `db.revokeValkeySite`

`db revoke-valkey-site` empties the site's database (`DBSIZE`, then `FLUSHDB
ASYNC`), deletes the user (which also closes its connections) and runs `ACL
SAVE`. The database is read from the user's own ACL (`ACL GETUSER`), never from
the request. A site without a user is a success with `revoked: false` and
nothing flushed.

## `db.renameValkeySite`

`db rename-valkey-site` moves a site's Valkey user to a new domain name. The
request names the container, the new `domain` and the previous domain as
`from`. The engine reads the old user (`ACL GETUSER`: its single database and its
single SHA-256 password hash), creates `site_<new>` with the same database and
the same hash, deletes `site_<old>` (closing its connections) and runs `ACL
SAVE`. The password and the data stay as they were; only the user name changes.
A site whose old domain has no user is a success with `renamed: false`; a
different existing user under the new name is refused with `CONFLICT` and
nothing changes; a retry after a partial run (both users present and equal)
finishes the move.

## `db.flushValkeySite`

`db flush-valkey-site` empties the site's database and reports `keysRemoved`
and `database`; the user stays. The database comes from the user's ACL, so a
wrong request cannot empty another site's database, and a site without a user
is refused. The same flush is also available to the site itself (its user may
`FLUSHDB` its own database), without the panel.

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
operation is idempotent and transaction/audit recorded.

An optional `stagingDefaults` list makes the copy safe, from a closed set
(anything else is rejected): `noindex` (`blog_public` = 0), `disableCron`
(`DISABLE_WP_CRON`), `blockMail` (a must-use plugin short-circuits `wp_mail`)
and `blockPayments` (the same plugin hides every WooCommerce payment gateway).
They apply to the copy only, after the domain replacement. The plugin is
written to `wp-content/mu-plugins/wcp-staging-safety.php` (refused through a
symlinked `wp-content`/`mu-plugins`) and the clone verifies that it loads; if
it does not, the clone fails and is rolled back rather than reporting a copy
that can still mail or charge customers. `capabilities` reports
`features.cloneStagingDefaults`; an engine without it rejects the key.

## `joomla.clone`

`joomla clone` accepts a root-owned JSON request naming the source and staging
Joomla roots (each beneath a configured content root, neither nested inside
the other), the staging runtime container and UID/GID, the MariaDB container,
the already-provisioned staging database, its user and password, and the
MariaDB root password. The source must be a Joomla 4 or later site (it needs
`cli/joomla.php`) whose `configuration.php` uses `mysqli`/`pdomysql` against
that same MariaDB container; anything else is refused before the staging site
is touched.

Under a lock scoped to the staging root the engine snapshots the staging
database and any existing staging files, (re)creates the staging directory
with a bounded `cp -a`, and rewrites only the copy's `configuration.php`: `db`,
`user`, `password`, `host`, a freshly generated 32-character `secret`, and
`log_path`/`tmp_path`/`cache_path` when they point into the source root; a
non-empty `live_site` is emptied. Each of those lines must exist exactly once
in the plain `public $name = value;` shape Joomla writes, otherwise the
operation fails closed. A symlinked `configuration.php` is refused, the file is
replaced with a temporary file and a rename, and nothing is evaluated. The
source database is dumped with `mariadb-dump` (read only, `--single-transaction`)
and imported into the staging database with the `db.restore` client, the copy
is re-chowned to the staging site's UID/GID, and finally Joomla's own console
(`php cli/joomla.php extension:list`) is run as the site user: it must boot
with the new credentials and read the copied tables. Any failure restores the
staging database and files; an interrupted run leaves `pending.json` that
`site.reconcile` rolls back, like `wordpress.clone`. Idempotent and
transaction/audit recorded; the source site is never written.

An optional `stagingDefaults` list, from a closed set (anything else is
rejected): `noindex` (`robots` = `noindex, nofollow`) and `blockMail`
(`mailonline` = false). The copy's database content is not search-replaced:
Joomla keeps few absolute URLs and a blind replace could damage serialized
data.

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
pinned official release URL, exact version and SHA-256 per tool (`wp-cli`, from the official `wp-cli/wp-cli` GitHub release, pin
cross-checked against the published `.sha256` and `.sha512`; and `composer`,
`composer.phar` from getcomposer.org, pin cross-checked against the published
`composer.phar.sha256sum`).
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

Every action that runs WP-CLI in a site's container (all `wordpress.*`
operations except `wordpress.migrateDiscard`, and `site.adminUsers` /
`site.adminLogin` for a WordPress site) first checks that the managed WP-CLI is
installed on the host. If it is not, the request fails with
`DEPENDENCY_UNAVAILABLE` ("WP-CLI is not installed on this server; install the
managed tool first") before anything is staged or run, because WP-CLI is not
part of the runtime images.

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

## `drupal.watchdog`

`drupal watchdog --request-file F` is read-only: no lock, transaction or audit
record. The root-owned request carries `container`, `projectRoot`,
`documentRoot`, `uid`, `gid` and optionally `count` (1-200, default 50),
`severity` (`emergency`, `alert`, `critical`, `error`, `warning`, `notice`,
`info`, `debug`; exactly that level) or `severityMin` (the same names; that
level and every more severe one, `--severity-min`; not both) and `type` (a Drupal log channel: 1-64 characters of letters,
digits, space, `.`, `_`, `-`). Unknown fields are rejected. The engine runs
`drush watchdog:show --format=json --count=N [--severity=Level] [--type=..]` (Drush matches the capitalised level label and an existing log channel; an unknown `type` makes Drush fail, so the request fails with `SUBPROCESS_FAILED`) as
the site user and returns `{"entries": [{id, date, type, severity, message,
truncated?}]}`, newest first. Messages are redacted before they leave the
engine: URLs lose credentials, query string and fragment (`?[redacted]`),
`password=`/`token:`/`Bearer ...` values, e-mail addresses, long opaque
strings and PEM blocks are replaced, markup and control characters removed,
and a message is cut at 500 characters (`truncated: true`). Hostname, user name,
referer and location are never returned. Without Drush the error is
`DEPENDENCY_UNAVAILABLE`; a site without the Database Logging module fails
with `SUBPROCESS_FAILED`. Advertised in `capabilities.operations` as
`drupal.watchdog`.

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

## `drupal.automatedCron`

`drupal automated-cron` takes the same request as the other Drupal actions plus
an optional `"interval"` (whole seconds, 0 to 31536000, default `0`; refused for
every other Drupal action). It switches Drupal's web-triggered cron
(`automated_cron.settings:interval`, `0` = off) so a system cron job can own the
schedule, and can restore a previous interval. Under the same lock, idempotency
and audit rules it runs, as the site user in the site's container, `drush
config:get automated_cron.settings interval --format=json`, then (only when the
value differs) `drush config:set --input-format=yaml automated_cron.settings
interval <n>`, then reads it back and fails with `subprocessFailed` if Drupal
does not report the requested value. Nothing is written to files. When Drush or
Drupal cannot report the interval (no Drush, no Drupal, the `automated_cron`
module uninstalled) the request fails before anything is set. The result has
`previousInterval`, `interval` and `changed` (`false` for a repeat). The read
accepts a nonnegative integer or a single JSON entry named
`automated_cron.settings:interval`, as emitted by Drush; unrelated keys, extra
entries, strings and malformed output are refused.

## `drupal.updateDb`

`drupal update-db` takes the same request as the other Drupal actions
(without `state`). Under the per-site lock the engine first runs `drush
updatedb:status --format=json` as the site user. When no update is pending it
stops there (`changed: false`, `updatesPending: 0`): nothing is mutated. When
updates are pending the engine, in this order: reads the maintenance mode
(`state:get system.maintenance_mode`; unreadable output fails the request
before anything changes), dumps the database into the
backup root (for MySQL/MariaDB: connection from `drush sql:conf` and the
database container's own `mariadb-dump`, so the PHP container needs no client,
the password only in the environment of that one `docker exec`; the
connection host must be the database container's name; other drivers use
`drush sql:dump`) at `drupal-updates/<requestId>/database.sql` (a failed dump is
deleted and the request fails with no update run), turns maintenance mode on
unless it already was, runs `drush updatedb --no-interaction` (30 minute
limit) and reads `updatedb:status` again; the request fails with
`SUBPROCESS_FAILED` if any update is still listed. Whatever happened, the
engine then puts the PREVIOUS maintenance mode back (also after an error, a
timeout or a cancel); if it cannot, the request fails with a message saying
the site may still be in maintenance mode. Status output that is not a JSON
list or object is refused rather than guessed at. The result carries
`changed`, `updatesPending` (before), `updatesRemaining` (after, `0` on
success), `previousMaintenanceMode` and `backupFile` (relative to the backup
root) and no Drush output. `capabilities` advertises
`features.drupalUpdateDbSafety`; an engine without it neither backs up nor
toggles maintenance, so clients must keep their own warning.

## `cms.clearCache`

`cms clear-cache` takes a root-owned JSON request `{kind, container,
projectRoot, uid, gid}` where `kind` is `laravel`; unknown fields and other
kinds are rejected. After checking that `artisan` exists in the project root
(`invalid_input` otherwise) the engine runs a fixed argv as the site user
inside the site's container from the project root: `php artisan optimize:clear
--no-interaction` (compiled files, config, route, view and event caches and
the application cache store, so sessions kept in the cache store are dropped).
WordPress and Drupal keep `wordpress.boundedAction` (`cacheFlush`) and
`drupal.cacheRebuild`. Joomla is not a kind: its only native console command,
`cache:clean`, cleans just the default cache group and cannot be told to clean
all of them, so it would leave page and component caches behind. Lock,
idempotency, transaction and audit as for the Drupal actions; the result is
`{kind, completedAtUnixSecs}` with no command output. Advertised as
`cms.clearCache`.

## `cms.maintenance`

`cms maintenance` takes a root-owned JSON request `{kind, state, container,
projectRoot, uid, gid}` where `kind` is `joomla` or `laravel` and `state` is
`on` (site offline) or `off`; unknown fields, other kinds and any other state
are rejected. After checking the CMS entry point (`cli/joomla.php`, `artisan`;
`invalid_input` otherwise) the engine runs a fixed argv as the site user
inside the site's container from the project root: Joomla `php cli/joomla.php
site:down|site:up` (Joomla edits `configuration.php` itself), Laravel `php
artisan down --secret=<token>|up`. Nothing is run when the project is already
in the requested mode. The mode is read back (`offline` in `configuration.php`;
`storage/framework/down`) and anything but the requested mode fails with
`SUBPROCESS_FAILED`, so an unreadable state is never reported as done. The
result is `{kind, maintenanceMode, changed, secretIssued,
completedAtUnixSecs}` with no command output. Laravel `on` that changed the
mode is a `secretResult`: the engine-generated bypass token is returned once as
`bypassSecret` (visit `/<token>` to get past the 503) and never stored; a
replay carries `alreadyIssued: true` and no token. Lock, idempotency,
transaction and audit as for the Drupal actions. Advertised as
`cms.maintenance`.

## `cms.safeMode`

`cms safe-mode` ("disable all extensions") takes a root-owned JSON request
`{kind, state, container, projectRoot, documentRoot?, uid, gid}` where `kind`
is `wordpress`, `drupal` or `joomla`, `state` is `on`, `off` or `status`, and
`documentRoot` is required for Drupal and forbidden for WordPress and Joomla
(`projectRoot` is the Joomla root). Unknown fields, other kinds and states are rejected.

WordPress `on` reads the active plugins (`wp plugin list --status=active`),
writes them to a saved list in the engine's own state directory, then runs
`wp plugin deactivate --all`, all with `--skip-plugins --skip-themes` so a
broken plugin cannot stop the command. The result must read back as no active
plugins; otherwise the previous plugins are re-activated and the list removed
(kept if that fails too). A multisite install is refused with `invalid_input`.
`off` re-activates exactly the saved plugins that are not active and removes the
list only when all of them read back as active; otherwise it fails with
`SUBPROCESS_FAILED` and keeps the list, so the restore can be retried. `on`
while already on changes nothing (`conflict` if plugins were activated since).

Drupal `on` records the previous maintenance mode and the enabled modules (for
the record, nothing is disabled or uninstalled) and turns maintenance mode on
(`state:set`, `cache:rebuild`, read back); `off` puts the maintenance mode back
to the recorded value, so a site that was already in maintenance stays there.

Joomla has no console command to switch extensions, so the engine runs a fixed
inline `php -r` script in the runtime container as the site user (plan on
stdin, as `site.adminUsers` does) that boots Joomla's own framework and uses its
database API. The engine never reads configuration.php, the credentials or the
table prefix. Only `#__extensions` rows with `type = 'plugin'`, `protected = 0`
and `locked = 0` that Joomla's own `ExtensionHelper::checkIfCoreExtension` does
not list as core (third-party plugins; Joomla ships unlocked core plugins such
as schemaorg, so `locked` alone is not enough) are read or updated, with
`enabled`, by integer id. `on` saves the enabled plugins (id and
`folder/element`) before touching anything, sets `enabled = 0` for exactly those
ids and reads back that none of them is enabled (otherwise it re-enables them
and removes the list, or keeps it if that fails). `off` sets `enabled = 1` for
the saved ids that are disabled and removes the list only when every saved id
reads back as enabled (else `SUBPROCESS_FAILED`, list kept). Plugins that were
already disabled stay disabled. Joomla's `com_plugins` cache is cleaned on a
best-effort basis. `extensions` holds `folder/element`.

`status` only reads the saved list. The result is `{kind, safeMode, changed,
extensions, maintenanceMode, savedAtUnixSecs, completedAtUnixSecs}` with no
command output. Lock, idempotency, transaction and audit as for the Drupal
actions. Advertised as `cms.safeMode`.

## `drupal.installDrush`

`drupal install-drush` takes the same request as the other Drupal actions
(without `state`). Drush is installed per project, never globally: when the
project has no executable `vendor/bin/drush` but has a `composer.json`, the
engine runs `php /opt/wcp-tools/composer/current/composer.phar require
drush/drush` inside the site's container as the site user, with a fixed argv
(`--no-interaction --no-ansi --no-progress --no-scripts --quiet`) and a
throwaway `COMPOSER_HOME`/cache under `/tmp`. It then runs `drush --version`
to prove the result works. The managed Composer (`tool.install --tool
composer`) must be installed on the host first (`dependency_unavailable`
otherwise); a project without `composer.json` is `invalid_input`. The result
carries `changed: false` when Drush was already there (no Composer run).

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

## `site.recoverDeployment`

`site recover-deployment --site-id <uuid> --request-id <uuid>` reconciles the
original `site.deploy` or `site.rollback` transaction. It never runs deploy,
rollback, Git, validation hooks, or another release switch. The command takes
the same site mutation lock and refuses a live owner, including an owner with
the same request id. A finished request returns its recorded outcome unchanged.

New deploy/rollback attempts save a checkpoint before staging: original request
and site identity, operation, previous release, target release and, for deploy,
the immutable revision. They keep the lock until the outcome has been saved.
An unresolved checkpoint blocks subsequent deploy/rollback attempts. Recovery
compares `current` with that checkpoint: the target proves activation and
commits the stored identity; the previous release proves interruption before
activation and records `CANCELLED`. A missing/corrupt checkpoint, changed current
link, or unsupported layout is refused;
legacy interrupted requests still need manual investigation. If the requested target was already active before an interrupted rollback, recovery records an unchanged, cancelled attempt rather than claiming a new activation. Recovery never
removes staged content or changes the active link.

`operation.status` and `operation.list` add optional `recoveryAction`:
`"site.recoverDeployment"` only for an inactive incomplete deployment with a
readable matching checkpoint. This is an offer to explicitly reconcile, not
permission to retry the mutation. Recovery validates all checkpoint identities
again while holding the lock. A recovered success includes `recovered: true`;
its `activatedAtUnixSecs` is the time recovery verified the active release.
Completed checkpoint files are pruned with their transaction records.

## `site.create` and `site.recoverCreate`

`site create --request-file <root-owned JSON> --request-id <uuid>
--idempotency-key <key>` creates a new PHP site in the managed WCP stack. The
closed JSON plan has `domain`, `runtimeId`, optional `relativeRoot` and Compose
`profile`, `workerMode` (default false), and `workerCount` (1–64, default 4).
The content root is derived from the sole configured content root and domain;
absolute paths and existing directories, routes (including parked/disabled
routes), identities, services and execution configs are refused. This first
slice does not adopt an existing tree or provision a database.

One engine invocation allocates a new Unix identity, prepares the private
root, ensures the runtime, writes its supervised service and execution
config, proves the runtime serves the site, then publishes ingress and
verifies through ingress. Mutations reuse the existing typed operations.
The per-domain scope is `site-create/<domain>`. The same idempotency key and
plan replay the recorded result; a changed plan conflicts. A pending journal
blocks a new creation even with another key.

A durable journal precedes each mutation boundary. Failure compensates in
reverse order: remove the hash-guarded route, remove the matching execution
config, stop/remove the matching service, remove only an empty root owned by
the allocated identity, then release the identity. Ownership comes from the
nested allocation transaction, not from domain-name coincidence. Modified
configurations, non-empty roots and unproven nested outcomes are retained
with a visible incomplete transaction and journal. A started runtime pool is
kept running; recovery never stops a shared pool.

`site recover-create --domain <domain> --request-id <uuid>` explicitly
compensates an interrupted attempt while holding its domain mutation lock.
If verification completed and its completion checkpoint was saved, recovery
records success instead of undoing the healthy site. A live lock, foreign
identity or changed artifact is refused. Retrying recovery is safe; it does
not repeat the creation. `operation status` and `operation list` accept
`--create-domain <domain>` as an exclusive scope selector. Status/list offer
`recoveryAction: "site.recoverCreate"` only for an inactive incomplete
transaction with a readable matching journal.

The desktop persists request identity before dispatch and reads the remote
outcome after timeout/reconnect. It does not orchestrate these steps or run
compensation over SSH. The optional database provisioning flow remains a
separate desktop-owned scope; it is not part of this composite.

### Protected offline database restore

`db restore-protected --request-file <root-owned-0600.json> --request-id <uuid>
--idempotency-key <key>` implements `db.restoreProtected`. The closed request is
`{dbType: "mariadb"|"postgres", database, container, filePath, rootPassword,
confirmOffline: true}`. Applications, queues and other writers must be stopped
before confirming; the engine's database lock does not stop external writers.
Only trusted, single-database SQL/plain gzip dumps are supported. SQL executes
with administrative privileges; this is not a sandbox and changes to other
databases, roles or external effects are outside compensation. System databases
are refused. Credentials travel through the private request and child environment,
never argv, transaction state, error output or audit.

The engine stages a private plain input and verifies gzip decompression before
mutation, then streams a complete logical snapshot (MariaDB routines/events/
triggers; PostgreSQL create/clean metadata) into `db-restore/<database>/snapshots/`
with mode 0600 under a 0700 directory. It syncs the snapshot and a SHA-256-bound
pending marker before import. A successful client exit and a fresh `SELECT 1`
probe are required for success; this verifies connectivity, not application
health. A private fixed client script records completion inside the immutable container;
a nonzero Docker CLI exit is not accepted as proof that SQL stopped. Only a
proven rejected import or failed post-import probe triggers a
separate, uncancelled snapshot restore and another connection probe. Successful
compensation records the original as failed, not successful. Snapshot restores
replace the target database, removing objects created by a partial import;
PostgreSQL recovery terminates sessions connected to that database first.

An import timeout, cancellation, lost client process, failed compensation or
invalid checkpoint returns `DATABASE_RECOVERY_REQUIRED`, retains the snapshot
and leaves the original transaction unresolved. Killing `docker exec` does not
prove the in-container client stopped, so the engine does not race automatic
rollback with it. Both protected and legacy `db.restore` refuse a pending
protected restore in that database scope. `operation status --database` and
`operation list --database` expose `db.recoverRestore` as an explicit next action.

After confirming every prior import and compensation client in this database scope has stopped, use
`db recover-restore --request-file <root-owned-0600.json> --request-id <new-uuid>
--idempotency-key <new-key>`, implementing `db.recoverRestore`. Its request is
`{dbType, database, container, rootPassword, confirmOffline: true,
originalRequestId, confirmClientsStopped: true}` (no input file). Recovery takes
the same database lock and validates the original request, immutable container
ID and snapshot hash before replacing anything. It does not import the submitted
dump again. Recovery itself has a transaction, idempotency and audit record;
repeating its key returns the original result. A terminal original is never
rolled back again. Completed artifacts are removed after durable terminal state;
unresolved artifacts remain for explicit recovery. This operation does not
provide online restore, automatic application maintenance or cross-database
atomicity. The existing `db.restore` raw import remains for compatibility and
for existing enclosing CMS transactions; clients requiring snapshot protection
must negotiate `db.restoreProtected` and must not fall back to raw import.

## Resource status and explicit content recovery

`operation resource-status --resource-operation <operation> --resource <resource> --request-id <id>`
selects only fixed operation scopes. Resource is the normalized remote root for CMS/archive
operations, domain for runtime migration, runtime ID for runtime config, `wp-stack` for
Meilisearch, `server` for Docker installation/start, or an opaque image identity for pulls.
It returns bounded transaction identity/status and `outcomeKnown`, never stored plugin
output or free-form errors. `recovery` contains safe availability/reason and optionally the
validated database container name. Missing status never implies success or permission to replay.
Lexical root aliases are normalized by clients; symlink aliases still require operator review.

`site recover-content --request-file <private-root-owned-json> --request-id <new-id>
--idempotency-key <key>` recovers exactly one checkpoint, never scans a server.
Document: `{"target":{"operation":"wordpress.clone","resource":"/var/www/stage",
"originalRequestId":"<uuid>","confirmOffline":true,"confirmClientsStopped":true},
"mariadbRootPasswords":{"<container>":"<secret>"}}`. The confirmations mean the site is
offline and every previous import, rollback and CMS database client has been stopped.
Supported original operations: site.importArchive, wordpress.clone, joomla.clone,
wordpress.migrateImport and site.migrateRuntime. Recovery has its own persisted status
under `site-content-recovery/<original-id>`; resourceStatus uses operation site.recoverContent
and resource original request UUID. Same-key recovery replays its own original outcome.

The `contentRecoveryEvidence` feature permits clone/migrate plans to opt in with
`recoveryEvidence:true`. Database snapshots then record an immutable Docker container ID,
SHA-256 and a durable mutation boundary; SQL clients use the pinned container. Failures
retain the checkpoint instead of speculative automatic compensation. Explicit restore
refuses replaced containers, modified snapshots, live owners and legacy evidence, and
requires independent in-container completion proof. Loss of proof leaves the recovery
IN_PROGRESS. A later attempt requires fresh explicit confirmation that prior clients stopped.
A partial file rollback whose prior files cannot be proved remains manual. No automatic
rollback is provided for incremental WXR imports, WordPress updates, Meilisearch upgrades,
host package installation or image pulls: their status is inspectable, and retained artifacts
and live services require manual assessment.
