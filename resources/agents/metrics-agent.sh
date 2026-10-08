#!/usr/bin/env bash
# wcp-agent: metrics-agent
# wcp-agent-version: 1.1.0
# wcp-agent-description: Collects system metrics every minute, rotating into monthly files (3-month retention)

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
export WCP_DIR
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/metrics-agent.heartbeat"' EXIT
METRICS_DIR="${METRICS_DIR:-$WCP_DIR/metrics}"
export METRICS_DIR

# Proc file paths - overridable for testing
PROC_STAT="${PROC_STAT:-/proc/stat}"
PROC_LOADAVG="${PROC_LOADAVG:-/proc/loadavg}"
PROC_NET_DEV="${PROC_NET_DEV:-/proc/net/dev}"
PROC_UPTIME="${PROC_UPTIME:-/proc/uptime}"
export PROC_STAT PROC_LOADAVG PROC_NET_DEV PROC_UPTIME

python3 - << 'PYEOF'
import glob, json, os, re, sys, time

METRICS_DIR   = os.environ["METRICS_DIR"]
PROC_STAT     = os.environ["PROC_STAT"]
PROC_LOADAVG  = os.environ["PROC_LOADAVG"]
PROC_NET_DEV  = os.environ["PROC_NET_DEV"]
PROC_UPTIME   = os.environ["PROC_UPTIME"]

sys.path.insert(0, os.path.join(os.environ.get("WCP_DIR", "/root/.wcp"), "agents"))
from wcp_agent_lib import run

os.makedirs(METRICS_DIR, exist_ok=True)


def run_cmd(cmd, timeout=10):
    return run(cmd, timeout=timeout)


# ── CPU (via /proc/stat diff over 0.5s) ─────────────────────────────────────

def read_cpu_stat():
    with open(PROC_STAT) as f:
        for line in f:
            if line.startswith("cpu "):
                fields = line.split()
                nums = [int(x) for x in fields[1:8]] + [0] * max(0, 7 - (len(fields) - 1))
                total = sum(nums[:7])
                idle = nums[3] + nums[4]
                return total, idle
    return 0, 0


t1, i1 = read_cpu_stat()
time.sleep(0.5)
t2, i2 = read_cpu_stat()
dt = t2 - t1
di = i2 - i1
cpu = round((dt - di) * 100 / dt, 1) if dt > 0 else 0.0

# ── RAM (MB) ─────────────────────────────────────────────────────────────────

free_out = run_cmd("free -m").stdout.splitlines()
ram_used, ram_total = 0, 0
if len(free_out) > 1:
    parts = free_out[1].split()
    ram_used = int(parts[2])
    ram_total = int(parts[1])

# ── Disk / (GB) ───────────────────────────────────────────────────────────────

df_out = run_cmd("df -BG /").stdout.splitlines()
disk_used, disk_total = 0, 0
if len(df_out) > 1:
    parts = df_out[1].split()
    disk_used = int(re.sub(r"[^0-9]", "", parts[2]))
    disk_total = int(re.sub(r"[^0-9]", "", parts[1]))

# ── Load ──────────────────────────────────────────────────────────────────────

with open(PROC_LOADAVG) as f:
    load_fields = f.read().split()
load1, load5, load15 = float(load_fields[0]), float(load_fields[1]), float(load_fields[2])

# ── Net (cumulative bytes since boot) ────────────────────────────────────────

net_rx = net_tx = 0
with open(PROC_NET_DEV) as f:
    lines = f.readlines()
for line in lines[2:]:
    parts = line.split()
    if len(parts) < 10:
        continue
    net_rx += int(parts[1])
    net_tx += int(parts[9])

# ── Containers ────────────────────────────────────────────────────────────────

def container_count(argv):
    r = run_cmd(argv)
    if r.returncode != 0:
        return 0
    return len([l for l in r.stdout.splitlines() if l.strip()])


containers_running = container_count("docker ps -q 2>/dev/null")
containers_total = container_count("docker ps -aq 2>/dev/null")
containers_stopped = containers_total - containers_running

# ── Uptime (seconds) ──────────────────────────────────────────────────────────

with open(PROC_UPTIME) as f:
    uptime_sec = int(float(f.read().split()[0]))

# ── Write ─────────────────────────────────────────────────────────────────────

ts = int(time.time())
month = time.strftime("%Y-%m")
out_file = os.path.join(METRICS_DIR, f"metrics-{month}.jsonl")

entry = {
    "ts": ts, "cpu": cpu, "ru": ram_used, "rt": ram_total,
    "du": disk_used, "dt": disk_total, "l1": load1, "l5": load5, "l15": load15,
    "rx": net_rx, "tx": net_tx, "cr": containers_running, "cs": containers_stopped,
    "up": uptime_sec,
}
with open(out_file, "a") as f:
    f.write(json.dumps(entry, separators=(",", ":")) + "\n")

# ── Rotate: keep only last 3 months ──────────────────────────────────────────

now = time.localtime()
cutoff_year, cutoff_month = now.tm_year, now.tm_mon - 3
while cutoff_month <= 0:
    cutoff_month += 12
    cutoff_year -= 1
cutoff = f"{cutoff_year:04d}-{cutoff_month:02d}"

for f in glob.glob(os.path.join(METRICS_DIR, "metrics-*.jsonl")):
    m = re.search(r"metrics-(.*)\.jsonl$", os.path.basename(f))
    if m and m.group(1) < cutoff:
        os.remove(f)
PYEOF
