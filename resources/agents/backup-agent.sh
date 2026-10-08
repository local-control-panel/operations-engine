#!/usr/bin/env bash
# wcp-agent: backup-agent
# wcp-agent-version: 1.1.1
# wcp-agent-description: DB + file backups to S3/B2/R2 with Slack/Discord/webhook notifications

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
export WCP_DIR
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/backup-agent.heartbeat"' EXIT

python3 - "$@" << 'PYEOF'
import argparse, fcntl, gzip, hashlib, json, os, re, shutil, sys, time, uuid

SAFE_DB_NAME = re.compile(r"^[A-Za-z0-9_-]+$")

WCP_DIR    = os.environ.get("WCP_DIR", "/root/.wcp")
BACKUP_DIR = os.path.join(WCP_DIR, "backups")
LOG_FILE   = os.path.join(WCP_DIR, "logs", "backup-agent.log")
CONF_FILE  = os.path.join(WCP_DIR, "backup.conf")
NOTIFY_FILE = os.path.join(WCP_DIR, "notify.conf")
RCLONE_CONF = os.path.join(WCP_DIR, "rclone.conf")

sys.path.insert(0, os.path.join(WCP_DIR, "agents"))
from wcp_agent_lib import log_entry as _log_entry, notify as _notify, run, database_dump_command, sql_digest

os.makedirs(BACKUP_DIR, exist_ok=True)
parser = argparse.ArgumentParser()
parser.add_argument("--job-id")
args = parser.parse_args()
# ponytail: serialize all backup jobs; per-job locks only if throughput requires it.
lock = open(os.path.join(BACKUP_DIR, ".lock"), "a")
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit("Another backup is running; retry after it completes")


def sh_esc(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def run_cmd(cmd, timeout=3600):
    return run("bash -o pipefail -c " + sh_esc(cmd), timeout=timeout)


def log_entry(entry):
    _log_entry(LOG_FILE, entry)


try:
    with open(CONF_FILE) as f:
        conf = json.load(f)
except Exception as e:
    print(f"ERROR: Cannot read {CONF_FILE}: {e}", file=sys.stderr)
    sys.exit(1)

jobs = conf.get("jobs", [])
if args.job_id is not None:
    jobs = [job for job in jobs if str(job.get("id")) == args.job_id and job.get("enabled", True)]
    if not jobs:
        sys.exit("Unknown or disabled backup job")
succeeded = 0
failed = 0
job_results = []

for job in jobs:
    if not job.get("enabled", True):
        continue

    job_id   = str(job.get("id", ""))
    job_name = job.get("name", job_id)
    job_type = job.get("job_type", "db")
    remote_name = job["remote_name"]
    bucket      = job["bucket"]
    prefix      = job.get("prefix", "backups").strip("/")
    remote_dest = f"{remote_name}:{bucket}/{prefix}" if prefix else f"{remote_name}:{bucket}"
    remote_ret  = int(job.get("remote_retention_days", 30))

    start_ts  = time.time()
    status    = "ok"
    error_msg = None
    size_bytes = 0

    generation = str(time.time_ns()) + "-" + uuid.uuid4().hex
    namespace = hashlib.sha256(job_id.encode()).hexdigest()
    job_dir = os.path.join(BACKUP_DIR, namespace)
    staging = os.path.join(job_dir, generation + ".partial")
    payload_dir = os.path.join(staging, "data")
    remote_root = remote_dest + "/jobs/" + namespace
    remote_snapshot = remote_root + "/" + generation
    manifest = {"version": 2, "job_id": job_id, "job_type": job_type, "created": int(start_ts), "databases": [], "verified": True, "restore_verified": False}
    try:
        os.makedirs(payload_dir)
        if job_type == "db":
            db_type   = job.get("db_type", "mariadb")
            manifest["db_type"] = db_type
            container = job.get("container", db_type)
            password  = job.get("db_password", "")
            database  = job.get("database", "*")
            local_ret = int(job.get("local_retention_days", 7))

            if database == "*":
                if db_type == "mariadb":
                    r = run_cmd(
                        f"docker exec {sh_esc(container)} mariadb -uroot -p{sh_esc(password)} "
                        f"-N -e 'SHOW DATABASES'"
                    )
                    skip = {"information_schema", "performance_schema", "mysql", "sys"}
                    dbs = [d.strip() for d in r.stdout.splitlines() if d.strip() and d.strip() not in skip]
                else:
                    r = run_cmd(
                        f"docker exec -e PGPASSWORD={sh_esc(password)} {sh_esc(container)} psql -U postgres -At "
                        f"-c 'SELECT datname FROM pg_database WHERE datistemplate = false'"
                    )
                    dbs = [d.strip() for d in r.stdout.splitlines() if d.strip()]

                if r.returncode != 0:
                    raise RuntimeError("Database discovery failed")
                if not dbs:
                    raise RuntimeError("Database discovery returned no databases")
                # Auto-discovered names become part of a backup file path
                # below; postgres in particular allows near-arbitrary quoted
                # identifiers, so anything outside a safe charset (which
                # could otherwise write outside BACKUP_DIR) is dropped
                # rather than dumped.
                safe = [d for d in dbs if SAFE_DB_NAME.match(d)]
                for d in set(dbs) - set(safe):
                    print(f"[ERR] skipping unsafe database name {d!r}", file=sys.stderr)
                if len(safe) != len(dbs):
                    raise RuntimeError("Database coverage incomplete: unsupported database name")
                dbs = safe
            else:
                dbs = [database]

            for db in dbs:
                if not SAFE_DB_NAME.fullmatch(db):
                    raise RuntimeError("Unsupported database name")
                ts_str = time.strftime("%Y%m%d_%H%M%S")
                fname  = f"{db}_{ts_str}.sql.gz"
                fpath  = os.path.join(payload_dir, fname)

                cmd = database_dump_command(db_type, container, password, db) + f" | gzip > {sh_esc(fpath)}"

                r = run_cmd(cmd)
                if r.returncode != 0:
                    raise RuntimeError(f"Dump failed for {db}: {r.stderr.strip()[:300]}")

                r = run_cmd(f"gzip -t {sh_esc(fpath)}")
                if r.returncode != 0:
                    raise RuntimeError(f"Integrity check failed for {fname}")

                with gzip.open(fpath, "rb") as dump:
                    sql_hash = sql_digest(dump)
                with open(fpath, "rb") as artifact:
                    hasher = hashlib.sha256()
                    for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                        hasher.update(chunk)
                    digest = hasher.hexdigest()
                manifest["databases"].append({"database": db, "file": fname, "sha256": digest, "sql_sha256": sql_hash})
                size_bytes += os.path.getsize(fpath)

        elif job_type == "files":
            src_path = job.get("path", "")
            excludes = job.get("exclude", [])
            exclude_args = " ".join(f"--exclude {sh_esc(e)}" for e in excludes)
            if not os.path.isdir(src_path):
                raise RuntimeError("Backup source directory does not exist")
            # ponytail: full snapshots require local disk equal to source size; add incremental storage only when capacity requires it.
            r = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} copy {sh_esc(src_path)} {sh_esc(payload_dir)} {exclude_args}")
            if r.returncode != 0:
                raise RuntimeError("File snapshot failed")
        else:
            raise RuntimeError("Unsupported backup job type")

        # Publish the completion marker only after a full content comparison.
        for action in ("copy", "check --download"):
            r = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} {action} {sh_esc(payload_dir)} {sh_esc(remote_snapshot + '/data')}")
            if r.returncode != 0:
                raise RuntimeError("Snapshot upload/verification failed")
        manifest["files"] = {}
        for root, _, names in os.walk(payload_dir):
            for name in names:
                path = os.path.join(root, name)
                hasher = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        hasher.update(chunk)
                manifest["files"][os.path.relpath(path, payload_dir)] = hasher.hexdigest()
        marker = os.path.join(staging, "manifest.json")
        with open(marker, "w") as f:
            json.dump(manifest, f)
        r = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} copyto {sh_esc(marker)} {sh_esc(remote_snapshot + '/manifest.json')}")
        if r.returncode != 0:
            raise RuntimeError("Snapshot publication failed")
        os.rename(staging, os.path.join(job_dir, generation))

        # Retention is bounded to completed generations of this job, never file mtimes.
        if remote_ret > 0:
            r = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} lsf --dirs-only {sh_esc(remote_root)}")
            if r.returncode != 0:
                raise RuntimeError("Snapshot retention listing failed")
            candidates = []
            for name in r.stdout.splitlines():
                name = name.rstrip("/")
                if not re.fullmatch(r"[0-9]+-[0-9a-f]{32}", name) or name == generation:
                    continue
                if int(name.split("-")[0]) / 1_000_000_000 >= start_ts - remote_ret * 86400:
                    continue
                target = remote_root + "/" + name
                old = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} cat {sh_esc(target + '/manifest.json')}")
                if old.returncode != 0:
                    continue  # Incomplete uploads are never retention candidates.
                data = json.loads(old.stdout)
                if data.get("job_id") != job_id or data.get("verified") is not True:
                    continue
                candidates.append((name, data))
            restored = [name for name, data in candidates if data.get("restore_verified") is True]
            protected = max(restored) if restored else None
            for name, data in candidates:
                if job_type == "db" and (protected is None or name == protected):
                    continue
                target = remote_root + "/" + name
                r = run_cmd(f"rclone --config {sh_esc(RCLONE_CONF)} purge {sh_esc(target)}")
                if r.returncode != 0:
                    raise RuntimeError("Snapshot retention failed")
        local_ret = int(job.get("local_retention_days", 7))
        local_restored = []
        for name in os.listdir(job_dir):
            if re.fullmatch(r"[0-9]+-[0-9a-f]{32}", name):
                with open(os.path.join(job_dir, name, "manifest.json")) as f:
                    if json.load(f).get("restore_verified") is True:
                        local_restored.append(name)
        protected_local = max(local_restored) if local_restored else None
        for name in os.listdir(job_dir):
            if job_type == "db" and (protected_local is None or name == protected_local):
                continue
            if name == generation or not re.fullmatch(r"[0-9]+-[0-9a-f]{32}", name):
                continue
            if local_ret > 0 and int(name.split("-")[0]) / 1_000_000_000 < start_ts - local_ret * 86400:
                shutil.rmtree(os.path.join(job_dir, name))

    except Exception as e:
        shutil.rmtree(staging, ignore_errors=True)
        status    = "error"
        error_msg = str(e)
        failed   += 1
        print(f"[ERR] {job_name}: {error_msg}", file=sys.stderr)
    else:
        succeeded += 1
        dur = int(time.time() - start_ts)
        print(f"[OK]  {job_name} ({dur}s)")

    result: dict = {
        "ts":         int(time.time()),
        "job_id":     job_id,
        "job_name":   job_name,
        "job_type":   job_type,
        "status":     status,
        "size_bytes": size_bytes,
        "duration_s": int(time.time() - start_ts),
    }
    if error_msg:
        result["error"] = error_msg
    log_entry(result)
    job_results.append(result)


# ── Notifications ─────────────────────────────────────────────────────────────
total = len(job_results)
summary_text = f"Backup: {succeeded}/{total} succeeded"
if failed > 0:
    summary_text += f", {failed} failed"

_notify(
    NOTIFY_FILE,
    is_failure=failed > 0,
    is_success=succeeded > 0,
    summary_text=summary_text,
    event_payload={
        "event":     "backup_complete",
        "timestamp": int(time.time()),
        "summary":   {"total": total, "succeeded": succeeded, "failed": failed},
        "jobs":      job_results,
    },
    username="WCP Backups",
)

print(f"Backup done: {succeeded} succeeded, {failed} failed")
sys.exit(1 if failed > 0 else 0)
PYEOF
