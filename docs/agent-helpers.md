# Agent helper subcommands

`ops-engine agent heartbeat|lock|log|result|config|site|tool|version` are the shared helpers for agent scripts,
usable identically from Bash and Python (an installed agent is a single script
file, so a library file is not an option for Bash). They are **not** protocol
operations: they are not listed in `capabilities`, print no envelope unless
`--json` is given, and their exit code is the contract. Design and rationale:
`docs/agent-api.md` in the agents repository.

State lives under `$WCP_DIR` (default `/root/.wcp`), in the files the agent
contract already uses, so old hand-written prologues and these helpers
interoperate (both take the same `flock`).

| Command | Does | Exit codes |
| --- | --- | --- |
| `agent heartbeat NAME [--exit-code N] [--json]` | Atomically writes `agents/NAME.heartbeat` as `{"ts":..,"exit_code":N}` | 0, 1 I/O, 2 bad name |
| `agent lock NAME -- CMD...` | Takes `agents/NAME.lock` (non-blocking `flock`, mode 0600) and `exec`s CMD with the lock inherited. `WCP_LOCK_HELD=NAME` is set for CMD. Lock held: CMD is not started, exit `--held-exit-code` (default 0) | CMD's own; 126/127 exec failure; 2 bad usage |
| `agent lock NAME --check` | Probe only | 0 free, 75 held |
| `agent log NAME [--level L] [--max-lines N] [MESSAGE...]` | Appends `{"ts","agent","level","msg"}` to `logs/NAME.log` and keeps the last N lines (default 2000). Message from stdin when none | 0, 1 I/O, 2 invalid |
| `agent result emit NAME --status ok\|warn\|fail\|skipped --summary TEXT [--data KEY=VALUE]... [--data-json JSON] [--max-lines N]` | Appends the result line `{"ts","agent","status","summary","data"}` to `logs/NAME.log` (same bounded file as `agent log`). Summary is cut at 500 characters; `data` is an object of at most 4 KiB whose keys are `[A-Za-z0-9_.-]` and must not look like a secret (`password`, `secret`, `token`, `api_key`, `credential`...) | 0, 1 I/O, 2 invalid |
| `agent config get NAME KEY [--default V] [--json]` | Prints KEY from `agents/NAME.conf`, which is `KEY=VALUE` lines (`#` comments), values verbatim, no expansion. The file must be a regular file owned by the running user and not writable by others (opened with `O_NOFOLLOW`, at most 64 KiB). Missing key without `--default`: exit 1 | 0, 1 missing or unreadable, 2 bad key or name |
| `agent config list NAME [--json]` | The key names, one per line, never the values | 0, 1, 2 |
| `agent site list [--json]` | One domain per line; `--json` gives `{"sites":[{siteId,domain,siteUser,contentRoot,source}]}`. Sites with an engine manifest (`/etc/operations-engine/sites`, trusted like a deploy trusts it) plus dot-named directories under `/var/www` without one (`siteId` null, `source` `filesystem`). Overridable by `WCP_SITES_MANIFEST_DIR` and `SITES_ROOT`. The same data is the read-only protocol operation `site.list` (`ops-engine site list`) | 0 |
| `agent tool status NAME [--json]` | NAME is `wp-cli`, `rclone` or `docker` (a closed list). Prints the version when known; exit 0 present, 1 missing, 2 unknown name. `--json` always prints one envelope with `present`, `version`, `path` and `installer`. Read-only | 0, 1, 2 |
| `agent tool ensure NAME [--json]` | Present: nothing is done. Missing: only when the operator listed NAME in `$WCP_DIR/allow-tool-ensure` (one name per line; a file owned by the running user, not writable by others, not a symlink) does it run the engine's own installer (`tool.install`, `backup.installRclone`, `system.installDocker`, with their pinning, locks and audit); `WCP_DRY_RUN=1` only reports (`outcome: wouldInstall`). Not allowed or failed: one line on stderr, exit 1, error code `DEPENDENCY_UNAVAILABLE` with `--json` | 0, 1, 2 |
| `agent version [--json]` | `agent-helpers N` then the helper names, one per line. The same list is `capabilities.features.agentHelpers`. `ops-engine agent help` lists every subcommand | 0 |

`WCP_DRY_RUN=1` skips the heartbeat, log and result writes (a dry run must not look
like a real run to the panel) but still takes the lock.

Cron runs agents with a minimal `PATH`. The engine therefore writes
`WCP_DIR=/root/.wcp OPS_ENGINE=/usr/local/bin/ops-engine
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` into every agent cron line
and `Environment=` lines into every sandboxed agent's systemd service, on
install or reinstall (a line written by an older engine gets them the next time
the agent is installed). Call the binary as `$OPS_ENGINE`, with
`/usr/local/bin/ops-engine` as the default.

```bash
NAME=my-agent
OPS="${OPS_ENGINE:-/usr/local/bin/ops-engine}"
trap '"$OPS" agent heartbeat "$NAME" --exit-code $?' EXIT
[ "${WCP_LOCK_HELD:-}" = "$NAME" ] || exec "$OPS" agent lock "$NAME" -- bash "$0" "$@"
"$OPS" agent log "$NAME" "started"
```

## Requirements checked at install

`agent.installFromRegistry` refuses an agent whose registry entry lists
requirements this host does not meet, before anything is written. The fields
are optional and come from the agent's `agent.toml` (`requires_ops`,
`requires_helpers`, `requires_tools`) as `requiresOps`, `requiresHelpers`,
`requiresTools` in `registry.json`; `minEngine` was already checked.

| Field | Checked against | Refusal |
| --- | --- | --- |
| `minEngine` | The engine's version | `INVALID_INPUT`, "needs a newer engine" |
| `requiresOps` | `capabilities.operations` | `DEPENDENCY_UNAVAILABLE`, names the missing operations |
| `requiresHelpers` | `capabilities.features.agentHelpers` | `DEPENDENCY_UNAVAILABLE`, names the missing helpers |
| `requiresTools` | `agent tool status` (installed now) | `DEPENDENCY_UNAVAILABLE`, "install them first"; a name outside the tool list is `INVALID_INPUT` |

At most 32 names per list, validated before they can appear in a message.
Bundled agents have no requirements.

## Running and configuring an agent (protocol operations)

These two are protocol operations (`capabilities.operations`), not helpers for
scripts: they print one envelope.

### `agent.run`

`ops-engine agent run NAME [--dry-run] [--timeout-seconds N]`

Starts an installed agent once, now, and answers with
`{agent, dryRun, scheduler, exitCode, timedOut, durationMs, heartbeat, result, stdout, stderr}`.

- The agent runs as its scheduler would start it: `bash $WCP_DIR/agents/NAME.sh`
  with `WCP_DIR`, `OPS_ENGINE` and `PATH` set as in its cron line (`scheduler:
  cron`), or `systemctl start wcp-agent-NAME.service` for a sandboxed agent
  (`scheduler: systemd`; its output is in the journal).
- Only an agent listed in `manifest.json` whose script is a regular file owned by
  the running user and not writable by others runs; anything else is
  `NOT_FOUND` or `PERMISSION_DENIED`. A held lock is `CONFLICT` and nothing is
  started.
- `--dry-run` sets `WCP_DRY_RUN=1`: the helpers write no heartbeat, log or result
  line, and `heartbeat` and `result` in the answer are null. A cooperating agent
  changes nothing outside `$WCP_DIR`. It is not a sandbox. A sandboxed agent has
  no dry run (`INVALID_INPUT`).
- `heartbeat` and `result` are the ones this run wrote (newer than its start).
  `stdout` and `stderr` are the last 4 KiB. The run is killed at the timeout
  (default 300, 1 to 3600 seconds; processes the agent started itself may
  survive). A failing agent is an answer (`exitCode` 7), not an error.
- Runs are not journaled by the engine.

### `agent.configure`

`ops-engine agent configure --request-file FILE`

FILE is a root-owned request that is not writable by others:

```json
{"name": "my-agent", "values": {"WEBHOOK_URL": "https://...", "OLD": null}, "merge": true}
```

It writes `$WCP_DIR/agents/NAME.conf` (mode 0600), the file `agent config get`
reads. Keys are `[A-Za-z_][A-Za-z0-9_]{0,63}` (at most 64); values are one line
of at most 4096 bytes. `null` removes a key. Without `merge` the file becomes
exactly `values`; with it the other keys stay, so a panel can change one setting
without holding the secrets it does not show. The agent must be installed. The
file is replaced atomically under a per-agent lock; the same request again
reports `changed: false`. The answer lists key names (`keys`, `removed`) and
**never a value**; errors never contain one either. The engine checks syntax and
size, not which keys an agent reads.
