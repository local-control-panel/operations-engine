#!/usr/bin/env bash
# wcp-agent: bruteforce-guard
# wcp-agent-version: 1.0.0
# wcp-agent-description: Fail2Ban-style brute-force protection for wp-login and general Caddy abuse. Bans by splicing a `remote_ip` block into every site's Caddyfile instead of iptables, since containerized (Docker bridge + published-port) traffic is NAT'd through DOCKER-USER/FORWARD, not INPUT, so classic fail2ban bans never actually apply.
#
# Run modes:
#   bash bruteforce-guard.sh              - scan logs, ban offenders, expire old bans, apply
#   bash bruteforce-guard.sh --apply-only - skip detection, just re-apply current ban list
#                                            (used by the app for immediate manual unban)

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
export WCP_DIR
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/bruteforce-guard.heartbeat"' EXIT

CADDYFILE_GLOB="${CADDYFILE_GLOB:-/etc/frankenphp*/Caddyfile.d/*.caddyfile}"
export CADDYFILE_GLOB

APPLY_ONLY=0
[[ "${1:-}" == "--apply-only" ]] && APPLY_ONLY=1
export APPLY_ONLY

python3 - << 'PYEOF'
import glob, json, os, re, sys, time

WCP_DIR        = os.environ.get("WCP_DIR", "/root/.wcp")
CADDYFILE_GLOB = os.environ["CADDYFILE_GLOB"]
APPLY_ONLY     = os.environ.get("APPLY_ONLY", "0") == "1"

# bruteforce-active-bans.txt and bruteforce-config.env are NOT owned by this
# script alone - src-tauri/src/commands/bruteforce.rs reads/writes them
# directly (bans.txt via a plain read + a remote `grep -v` unban command;
# config.env as the KEY=VALUE file it writes from bruteforce:config:set), so
# their on-disk formats must stay exactly as they are. Only the offsets file
# is purely internal to this script.
CONFIG_FILE  = os.path.join(WCP_DIR, "bruteforce-config.env")
OFFSETS_FILE = os.path.join(WCP_DIR, "bruteforce-offsets.json")
HITS_FILE    = os.path.join(WCP_DIR, "bruteforce-hits.json")
BANS_FILE    = os.path.join(WCP_DIR, "bruteforce-active-bans.txt")
EVENTS_FILE  = os.path.join(WCP_DIR, "bruteforce-events.jsonl")
NOTIFY_FILE  = os.path.join(WCP_DIR, "notify.conf")

BAN_BEGIN = "# bruteforce-ban-begin"
BAN_END = "# bruteforce-ban-end"

sys.path.insert(0, os.path.join(WCP_DIR, "agents"))
from wcp_agent_lib import log_entry as _log_entry, notify as _notify, read_json, run, run_argv, shell_quote, write_json

os.makedirs(WCP_DIR, exist_ok=True)
open(BANS_FILE, "a").close()
open(EVENTS_FILE, "a").close()
if not os.path.exists(OFFSETS_FILE):
    write_json(OFFSETS_FILE, {})
if not os.path.exists(HITS_FILE):
    write_json(HITS_FILE, [])

now = int(time.time())

# ── Config (defaults, overridden by bruteforce-config.env if present) ───────

def read_env_file(path):
    kv = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return kv


def get_bool(kv, key, default):
    v = kv.get(key)
    return default if v is None else v == "true"


def get_int(kv, key, default):
    try:
        return int(kv[key])
    except (KeyError, ValueError):
        return default


kv = read_env_file(CONFIG_FILE)
WP_LOGIN_ENABLED = get_bool(kv, "WP_LOGIN_ENABLED", True)
WP_LOGIN_MAX_RETRIES = get_int(kv, "WP_LOGIN_MAX_RETRIES", 5)
WP_LOGIN_FINDTIME_MIN = get_int(kv, "WP_LOGIN_FINDTIME_MIN", 10)
WP_LOGIN_BANTIME_MIN = get_int(kv, "WP_LOGIN_BANTIME_MIN", 60)
CADDY_ENABLED = get_bool(kv, "CADDY_ENABLED", True)
CADDY_MAX_RETRIES = get_int(kv, "CADDY_MAX_RETRIES", 20)
CADDY_FINDTIME_MIN = get_int(kv, "CADDY_FINDTIME_MIN", 10)
CADDY_BANTIME_MIN = get_int(kv, "CADDY_BANTIME_MIN", 60)

IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IPV6_CHARS_RE = re.compile(r"^[0-9a-fA-F:]+$")


def is_valid_ip(ip):
    # client_ip/remote_ip is normally the raw TCP peer address (never
    # attacker-controlled), but if trusted-proxies is ever misconfigured to
    # trust a header-spoofable upstream, it could reflect an arbitrary
    # X-Forwarded-For value instead. Since this value gets spliced verbatim
    # into every site's live Caddyfile, anything that isn't a real IP must be
    # rejected before it reaches the hits/bans files.
    m = IPV4_RE.match(ip)
    if m:
        return all(int(o) <= 255 for o in m.groups())
    return ":" in ip and bool(IPV6_CHARS_RE.match(ip))


def read_bans():
    bans = []
    with open(BANS_FILE) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 4:
                bans.append({"ip": parts[0], "jail": parts[1],
                             "banned_at": int(parts[2]), "expires_at": int(parts[3])})
    return bans


def write_bans(bans):
    with open(BANS_FILE, "w") as f:
        for b in bans:
            f.write(f"{b['ip']} {b['jail']} {b['banned_at']} {b['expires_at']}\n")


def log_event(entry):
    _log_entry(EVENTS_FILE, entry)


bans = read_bans()
banned_ip_set = {b["ip"] for b in bans}


def ban_ip(ip, jail, banmin, hits):
    if ip in banned_ip_set:
        return
    expires = now + banmin * 60
    bans.append({"ip": ip, "jail": jail, "banned_at": now, "expires_at": expires})
    banned_ip_set.add(ip)
    write_bans(bans)
    log_event({"ts": now, "action": "ban", "ip": ip, "jail": jail, "hits": hits})
    _notify(
        NOTIFY_FILE,
        is_failure=True,
        is_success=False,
        summary_text=f"Banned {ip} ({jail} jail, {hits} hits)",
        event_payload={"event": "bruteforce_ban", "ts": now, "ip": ip, "jail": jail, "hits": hits},
        username="WCP Bruteforce Guard",
    )


if not APPLY_ONLY:
    # ── 1. Tail new Caddy access-log lines from every FrankenPHP container ──
    offsets = read_json(OFFSETS_FILE, {}) or {}
    hits = read_json(HITS_FILE, []) or []

    containers_out = run("docker ps --format '{{.Names}}'").stdout
    containers = [c for c in containers_out.splitlines() if c.startswith("frankenphp")]

    for container in containers:
        logfiles_out = run(f"docker exec {shell_quote(container)} sh -c 'ls /var/log/caddy/*.log 2>/dev/null'").stdout
        for logfile in [l for l in logfiles_out.splitlines() if l.strip()]:
            key = f"{container}:{logfile}"
            prev_offset = int(offsets.get(key, 0))

            # Passed as a plain argv element (no shell, no nested `sh -c`
            # string) so a filename can never break out of quoting.
            size_out = run_argv(["docker", "exec", container, "wc", "-c", logfile]).stdout.strip()
            try:
                cur_size = int(size_out.split()[0]) if size_out else 0
            except (ValueError, IndexError):
                cur_size = 0

            if cur_size < prev_offset:
                prev_offset = 0

            if cur_size > prev_offset:
                new_lines = run_argv(
                    ["docker", "exec", container, "tail", "-c", f"+{prev_offset + 1}", logfile]
                ).stdout
                for line in new_lines.splitlines():
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    req = entry.get("request", {}) if isinstance(entry, dict) else {}
                    ip = req.get("client_ip") or req.get("remote_ip")
                    if not ip or not is_valid_ip(ip):
                        continue
                    method = req.get("method")
                    uri = req.get("uri") or ""
                    status = entry.get("status")

                    if WP_LOGIN_ENABLED and method == "POST" and "wp-login.php" in uri:
                        hits.append({"ts": now, "jail": "wp_login", "ip": ip})
                    elif CADDY_ENABLED and status in (401, 403, 404):
                        hits.append({"ts": now, "jail": "caddy", "ip": ip})

            offsets[key] = cur_size

    write_json(OFFSETS_FILE, offsets)

    # ── 2. Prune hits older than the widest configured find-time window ─────
    max_find_min = max(WP_LOGIN_FINDTIME_MIN, CADDY_FINDTIME_MIN)
    cutoff = now - max_find_min * 60
    hits = [h for h in hits if h["ts"] >= cutoff]
    write_json(HITS_FILE, hits)

    # ── 3. Evaluate thresholds per jail, ban offenders ───────────────────────
    def counts_for(jail, find_min):
        jail_cutoff = now - find_min * 60
        counts = {}
        for h in hits:
            if h["jail"] == jail and h["ts"] >= jail_cutoff:
                counts[h["ip"]] = counts.get(h["ip"], 0) + 1
        return counts

    if WP_LOGIN_ENABLED:
        for ip, count in counts_for("wp_login", WP_LOGIN_FINDTIME_MIN).items():
            if count >= WP_LOGIN_MAX_RETRIES:
                ban_ip(ip, "wp_login", WP_LOGIN_BANTIME_MIN, count)

    if CADDY_ENABLED:
        for ip, count in counts_for("caddy", CADDY_FINDTIME_MIN).items():
            if count >= CADDY_MAX_RETRIES:
                ban_ip(ip, "caddy", CADDY_BANTIME_MIN, count)

# ── 4. Expire old bans ────────────────────────────────────────────────────────
bans = read_bans()
active, expired = [], []
for b in bans:
    (active if b["expires_at"] >= now else expired).append(b)
for b in expired:
    log_event({"ts": now, "action": "expire", "ip": b["ip"], "jail": b["jail"]})
write_bans(active)

# ── 5. Rebuild the shared ban block and splice into every site Caddyfile ────
banned_ips = " ".join(sorted({b["ip"] for b in active}))


def strip_old_block(lines):
    out = []
    skip = False
    for line in lines:
        if BAN_BEGIN in line:
            skip = True
            continue
        if BAN_END in line:
            skip = False
            continue
        if skip:
            continue
        out.append(line)
    return out


def insert_block(lines, ips):
    out = []
    inserted = False
    comment_re = re.compile(r"^[ \t]*#")
    for line in lines:
        out.append(line)
        if not inserted and "{" in line and not comment_re.match(line):
            out.append(f"    {BAN_BEGIN}")
            out.append(f"    @bf_banned remote_ip {ips}")
            out.append("    respond @bf_banned 403")
            out.append(f"    {BAN_END}")
            inserted = True
    return out


def apply_block(path):
    with open(path) as f:
        original = f.read()
    lines = strip_old_block(original.splitlines())
    if banned_ips:
        lines = insert_block(lines, banned_ips)
    new_content = "\n".join(lines) + ("\n" if lines else "")
    if new_content == original:
        return False
    with open(path, "w") as f:
        f.write(new_content)
    return True


changed = False
for path in glob.glob(CADDYFILE_GLOB):
    if os.path.isfile(path) and apply_block(path):
        changed = True

# ── 6. Reload Caddy only if something actually changed ──────────────────────
if changed:
    containers_out = run("docker ps --format '{{.Names}}'").stdout
    for container in [c for c in containers_out.splitlines() if c.startswith("frankenphp")]:
        run(f"docker exec {shell_quote(container)} caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1")
PYEOF
