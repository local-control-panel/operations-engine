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
