#!/usr/bin/env bash
# wcp-agent: backup-restore-drill
# wcp-agent-version: 1.1.0
# wcp-agent-description: Restores the latest DB backup into a throwaway container and compares restored schema/data with the immutable snapshot

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
export WCP_DIR
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/backup-restore-drill.heartbeat"' EXIT

python3 - << 'PYEOF'
import fcntl, gzip, hashlib, json, os, re, sys, tempfile, time
from pathlib import Path

WCP_DIR = Path(os.environ.get("WCP_DIR", "/root/.wcp"))
sys.path.insert(0, str(WCP_DIR / "agents"))
from wcp_agent_lib import log_entry, notify, run, shell_quote, database_dump_command, sql_digest

backup_dir = WCP_DIR / "backups"
backup_dir.mkdir(parents=True, exist_ok=True)
lock = open(backup_dir / ".lock", "a")
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit("A backup or restore drill is already running")


def checked(command):
    result = run("bash -o pipefail -c " + shell_quote(command), timeout=1800)
    if result.returncode:
        raise RuntimeError(f"Restore verification command failed (exit {result.returncode})")
    return result.stdout.strip()


conf_path = WCP_DIR / "backup.conf"
if not conf_path.exists():
    sys.exit(0)
with open(conf_path) as f:
    jobs = [j for j in json.load(f).get("jobs", []) if j.get("job_type", "db") == "db" and j.get("enabled", True)]
if not jobs:
    sys.exit(0)
state_path = WCP_DIR / "restore-drill.state"
try:
    previous = json.loads(state_path.read_text())["last_index"]
except (OSError, ValueError, KeyError):
    previous = -1
index = (previous + 1) % len(jobs)
state_path.write_text(json.dumps({"last_index": index}))
job = jobs[index]
job_id = str(job["id"])
start = time.time()
result = {"ts": int(start), "job_id": job_id, "job_name": job.get("name", job_id),
          "database": job.get("database", "*"), "status": "error", "databases_verified": []}
try:
    root = backup_dir / hashlib.sha256(job_id.encode()).hexdigest()
    markers = sorted(root.glob("*/manifest.json"))
    markers = [p for p in markers if re.fullmatch(r"[0-9]+-[0-9a-f]{32}", p.parent.name)]
    if not markers:
        raise RuntimeError("No completed snapshot manifest; legacy dumps require manual verification")
    marker = markers[-1]
    manifest = json.loads(marker.read_text())
    entries = manifest["databases"]
    if manifest.get("job_id") != job_id or not entries:
        raise RuntimeError("Invalid or empty snapshot coverage")
    if job.get("database", "*") != "*" and [e["database"] for e in entries] != [job["database"]]:
        raise RuntimeError("Snapshot database coverage mismatch")
    db_type = job.get("db_type", "mariadb")
    image = checked("docker inspect --format '{{.Config.Image}}' " + shell_quote(job["container"]))
    if not image:
        raise RuntimeError("Database image is unknown")
    for entry in entries:
        database = entry["database"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", database) or Path(entry["file"]).name != entry["file"]:
            raise RuntimeError("Invalid snapshot path/database")
        dump = marker.parent / "data" / entry["file"]
        with open(dump, "rb") as f:
            digest = hashlib.sha256()
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != entry["sha256"]:
            raise RuntimeError("Snapshot checksum mismatch")
        with gzip.open(dump, "rb") as f:
            if sql_digest(f) != entry["sql_sha256"]:
                raise RuntimeError("SQL snapshot checksum mismatch")
        name = "wcp-drill-" + os.urandom(12).hex()
        password = os.urandom(24).hex()
        try:
            env = "MARIADB_ROOT_PASSWORD" if db_type == "mariadb" else "POSTGRES_PASSWORD"
            db_env = "MARIADB_DATABASE" if db_type == "mariadb" else "POSTGRES_DB"
            checked(f"docker run -d --name {name} -e {env}={password} -e {db_env}={shell_quote(database)} {shell_quote(image)}")
            for attempt in range(30):
                probe = (f"docker exec -e MYSQL_PWD={password} {name} mariadb -uroot {shell_quote(database)} -e 'SELECT 1'" if db_type == "mariadb"
                         else f"docker exec -e PGPASSWORD={password} {name} psql -v ON_ERROR_STOP=1 -U postgres {shell_quote(database)} -c 'SELECT 1'")
                if run(probe, timeout=5).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Throwaway database did not become ready")
            client = (f"docker exec -i -e MYSQL_PWD={password} {name} mariadb -uroot {shell_quote(database)}" if db_type == "mariadb"
                      else f"docker exec -i -e PGPASSWORD={password} {name} psql -v ON_ERROR_STOP=1 -U postgres {shell_quote(database)}")
            checked(f"gunzip -c {shell_quote(str(dump))} | {client}")
            with tempfile.TemporaryDirectory(dir=backup_dir) as temp:
                restored = Path(temp) / "restored.sql"
                checked(database_dump_command(db_type, name, password, database) + " > " + shell_quote(str(restored)))
                with open(restored, "rb") as f:
                    if sql_digest(f) != entry["sql_sha256"]:
                        raise RuntimeError("Restored schema/data differs from the SQL snapshot")
            result["databases_verified"].append(database)
        finally:
            checked(f"docker rm -f {name}")
    manifest["restore_verified"] = True
    marker.write_text(json.dumps(manifest))
    prefix = job.get("prefix", "backups").strip("/")
    remote = f"{job['remote_name']}:{job['bucket']}" + ("/" + prefix if prefix else "")
    remote += "/jobs/" + root.name + "/" + marker.parent.name + "/manifest.json"
    checked("rclone --config " + shell_quote(str(WCP_DIR / "rclone.conf")) + " copyto " + shell_quote(str(marker)) + " " + shell_quote(remote))
    result["status"] = "ok"
except Exception as e:
    result["error"] = str(e)
result["duration_s"] = int(time.time() - start)
log_entry(str(WCP_DIR / "logs/restore-drill.log"), result)
notify(str(WCP_DIR / "notify.conf"), is_failure=result["status"] != "ok", is_success=result["status"] == "ok",
       summary_text=f"Restore drill: {result['status']}", event_payload=result, username="WCP Restore Drill")
sys.exit(0 if result["status"] == "ok" else 1)
PYEOF
