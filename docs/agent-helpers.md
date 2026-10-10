# Agent helper subcommands

`ops-engine agent heartbeat|lock|log` are the shared helpers for agent scripts,
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

`WCP_DRY_RUN=1` skips the heartbeat and log writes (a dry run must not look
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
