#!/usr/bin/env bash
# wcp-agent: error-log-digest
# wcp-agent-version: 1.0.0
# wcp-agent-description: Daily digest of grouped WordPress debug.log entries and Caddy 5xx responses across every site

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
SITES_ROOT="${SITES_ROOT:-/var/www}"
export WCP_DIR SITES_ROOT
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/error-log-digest.heartbeat"' EXIT

python3 - << 'PYEOF'
import glob, json, os, re, sys, time

WCP_DIR     = os.environ.get("WCP_DIR", "/root/.wcp")
SITES_ROOT  = os.environ.get("SITES_ROOT", "/var/www")
LOG_FILE    = os.path.join(WCP_DIR, "logs", "error-digest.log")
NOTIFY_FILE = os.path.join(WCP_DIR, "notify.conf")
OFFSETS_FILE = os.path.join(WCP_DIR, "error-digest-offsets.json")

MAX_MESSAGE_LEN = 120

sys.path.insert(0, os.path.join(WCP_DIR, "agents"))
from wcp_agent_lib import log_entry as _log_entry, notify as _notify, run, run_argv


def sh_esc(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def run_cmd(cmd, timeout=60):
    return run(cmd, timeout=timeout)


def log_entry(entry):
    _log_entry(LOG_FILE, entry)


try:
    with open(OFFSETS_FILE) as f:
        offsets = json.load(f)
except Exception:
    offsets = {}

groups = {}  # (site, message) -> {"count": int, "first_seen": ts, "last_seen": ts}


def record(site, message, now):
    message = message.strip()[:MAX_MESSAGE_LEN]
    key = (site, message)
    g = groups.get(key)
    if g is None:
        groups[key] = {"count": 1, "first_seen": now, "last_seen": now}
    else:
        g["count"] += 1
        g["last_seen"] = now


now = int(time.time())

# ── WordPress debug.log per site ────────────────────────────────────────────
for debug_log in sorted(glob.glob(os.path.join(SITES_ROOT, "*", "public", "wp-content", "debug.log"))):
    domain = debug_log.split(os.sep)[-4]
    key = f"wp:{domain}"
    prev_offset = offsets.get(key, 0)

    try:
        size = os.path.getsize(debug_log)
    except OSError:
        continue
    if size < prev_offset:
        prev_offset = 0

    if size > prev_offset:
        with open(debug_log, "r", errors="replace") as f:
            f.seek(prev_offset)
            new_content = f.read()
        for line in new_content.splitlines():
            if not line.strip():
                continue
            message = re.sub(r"^\[[^\]]*\]\s*", "", line)
            record(domain, message, now)

    offsets[key] = size

# ── Caddy 5xx entries inside every frankenphp* container ───────────────────
containers_out = run_cmd("docker ps --format '{{.Names}}'").stdout
containers = [c for c in containers_out.splitlines() if c.startswith("frankenphp")]

for container in containers:
    logfiles_out = run_cmd(f"docker exec {sh_esc(container)} sh -c 'ls /var/log/caddy/*.log 2>/dev/null'").stdout
    for logfile in [l for l in logfiles_out.splitlines() if l.strip()]:
        key = f"caddy:{container}:{logfile}"
        prev_offset = offsets.get(key, 0)

        # Passed as a plain argv element (no shell, no nested `sh -c`
        # string) so a logfile name can never break out of quoting.
        size_out = run_argv(["docker", "exec", container, "wc", "-c", logfile]).stdout.strip()
        try:
            size = int(size_out.split()[0]) if size_out else 0
        except (ValueError, IndexError):
            size = 0
        if size < prev_offset:
            prev_offset = 0

        if size > prev_offset:
            new_content = run_argv(
                ["docker", "exec", container, "tail", "-c", f"+{prev_offset + 1}", logfile]
            ).stdout
            for line in new_content.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                status = entry.get("status")
                if not isinstance(status, int) or status < 500:
                    continue
                host = entry.get("request", {}).get("host", container)
                record(host, f"HTTP {status}", now)

        offsets[key] = size

with open(OFFSETS_FILE, "w") as f:
    json.dump(offsets, f)

group_list = [
    {"site": site, "message": message, **stats}
    for (site, message), stats in groups.items()
]
group_list.sort(key=lambda g: g["count"], reverse=True)
total_errors = sum(g["count"] for g in group_list)

log_entry({"ts": now, "total_errors": total_errors, "groups": group_list})

# ── Notification ─────────────────────────────────────────────────────────────
is_failure = total_errors > 0
top = group_list[:5]
sites_hit = len(set(g["site"] for g in group_list))
summary_text = f"Error digest: {total_errors} grouped error(s) across {sites_hit} site(s)"

_notify(
    NOTIFY_FILE,
    is_failure=is_failure,
    is_success=not is_failure,
    summary_text=summary_text,
    event_payload={
        "event": "error_digest",
        "timestamp": now,
        "total_errors": total_errors,
        "top_groups": top,
    },
    username="WCP Error Digest",
)

print(f"Error digest: {total_errors} grouped error(s)")
PYEOF
