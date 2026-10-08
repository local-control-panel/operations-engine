#!/usr/bin/env bash
# wcp-agent: resource-alert
# wcp-agent-version: 1.0.0
# wcp-agent-description: CPU/RAM/Disk threshold monitor - writes alerts to /root/.wcp/resource-alerts.jsonl

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
export WCP_DIR
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/resource-alert.heartbeat"' EXIT

PROC_STAT="${PROC_STAT:-/proc/stat}"
PROC_MEMINFO="${PROC_MEMINFO:-/proc/meminfo}"
export PROC_STAT PROC_MEMINFO

python3 - << 'PYEOF'
import os, re, sys, time

WCP_DIR      = os.environ.get("WCP_DIR", "/root/.wcp")
PROC_STAT    = os.environ["PROC_STAT"]
PROC_MEMINFO = os.environ["PROC_MEMINFO"]
CONF_FILE    = os.path.join(WCP_DIR, "resource-alert.conf")
LOG_FILE     = os.path.join(WCP_DIR, "resource-alerts.jsonl")
STATE_FILE   = os.path.join(WCP_DIR, "resource-alert.state")
NOTIFY_FILE  = os.path.join(WCP_DIR, "notify.conf")
MAX_LINES    = 10000

sys.path.insert(0, os.path.join(WCP_DIR, "agents"))
from wcp_agent_lib import log_entry as _log_entry, notify as _notify, read_json, run, write_json

os.makedirs(WCP_DIR, exist_ok=True)
open(LOG_FILE, "a").close()

conf = read_json(CONF_FILE, {}) or {}
cpu_pct = int(conf.get("cpu_pct", 90))
ram_pct = int(conf.get("ram_pct", 90))
disk_pct = int(conf.get("disk_pct", 90))
cooldown_min = int(conf.get("cooldown_min", 30))

now = int(time.time())
cooldown_sec = cooldown_min * 60

state = read_json(STATE_FILE, {}) or {}
last_cpu = int(state.get("last_cpu", 0))
last_ram = int(state.get("last_ram", 0))
last_disk = int(state.get("last_disk", 0))


def emit(metric, value, threshold, mount=None):
    entry = {"metric": metric, "value": value, "threshold": threshold, "ts": now}
    if mount is not None:
        entry["mount"] = mount
    _log_entry(LOG_FILE, entry, max_lines=MAX_LINES)

    summary = f"Resource alert: {metric} at {value}% (threshold {threshold}%)"
    if mount is not None:
        summary += f" on {mount}"
    _notify(
        NOTIFY_FILE,
        is_failure=True,
        is_success=False,
        summary_text=summary,
        event_payload={"event": "resource_alert", **entry},
        username="WCP Resource Alert",
    )


# ── CPU - use /proc/stat for a 1-second sample ───────────────────────────────

def read_cpu_fields():
    with open(PROC_STAT) as f:
        for line in f:
            if line.startswith("cpu "):
                fields = line.split()[1:]
                idle = int(fields[3]) if len(fields) > 3 else 0
                total = sum(int(x) for x in fields)
                return total, idle
    return 0, 0


total1, idle1 = read_cpu_fields()
time.sleep(1)
total2, idle2 = read_cpu_fields()
d_total = total2 - total1
d_idle = idle2 - idle1
cpu_val = (d_total - d_idle) * 100 // d_total if d_total != 0 else 0

if cpu_val >= cpu_pct and now - last_cpu >= cooldown_sec:
    emit("cpu", cpu_val, cpu_pct)
    last_cpu = now

# ── RAM - from /proc/meminfo ─────────────────────────────────────────────────

mem_total = mem_avail = None
with open(PROC_MEMINFO) as f:
    for line in f:
        if line.startswith("MemTotal:"):
            mem_total = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            mem_avail = int(line.split()[1])

if mem_total is not None and mem_total > 0 and mem_avail is not None:
    ram_used = mem_total - mem_avail
    ram_val = ram_used * 100 // mem_total
    if ram_val >= ram_pct and now - last_ram >= cooldown_sec:
        emit("ram", ram_val, ram_pct)
        last_ram = now

# ── Disk - check all non-tmpfs mountpoints, alert on worst ──────────────────

r = run("df -x tmpfs -x devtmpfs -x overlay --output=source,size,used,avail,pcent,target", timeout=30)
worst_disk = 0
worst_mount = ""
for line in r.stdout.splitlines()[1:]:
    parts = line.split()
    if len(parts) < 6:
        continue
    pct_str = parts[4].rstrip("%")
    if not pct_str.isdigit():
        continue
    pct = int(pct_str)
    if pct > worst_disk:
        worst_disk = pct
        worst_mount = parts[5]

if worst_disk >= disk_pct and now - last_disk >= cooldown_sec:
    emit("disk", worst_disk, disk_pct, mount=worst_mount)
    last_disk = now

# ── Persist updated state ────────────────────────────────────────────────────

write_json(STATE_FILE, {"last_cpu": last_cpu, "last_ram": last_ram, "last_disk": last_disk})
PYEOF
