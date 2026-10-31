#!/data/data/com.termux/files/usr/bin/python
import os, sys, json, time, hashlib, subprocess, fcntl
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
EVID = BASE / "evidence"
CHECK = BASE / "checkpoints"
BASELINE = CHECK / "guard_files_baseline.json"
STATE = CHECK / "guard_state.json"
ALERTS = EVID / "guard_alerts.jsonl"
PIDFILE = EVID / "guard.pid"

TARGETS = [
    "hardening_guard.py", "fortress.py", "shieldtrace.py",
    "start_defense.sh", "hardening_audit.py",
    "defence_mode.py", "shieldtrace.py.bak"
]

def now():
    return datetime.now(timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()

def snapshot():
    result = {}
    for name in TARGETS:
        p = BASE / name
        if p.is_file():
            result[name] = digest(p)
    return result

def write_json(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def notify(title, message):
    cmd = shutil_which("termux-notification")
    if cmd:
        try:
            subprocess.run(
                [cmd, "--title", title, "--content", message],
                timeout=5, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

def shutil_which(name):
    from shutil import which
    return which(name)

def log_event(kind, details):
    previous = "0" * 64
    if ALERTS.exists():
        try:
            with ALERTS.open() as f:
                for line in f:
                    row = json.loads(line)
                    previous = row["event_sha256"]
        except Exception:
            previous = "UNREADABLE_PREVIOUS_LOG"

    row = {
        "time": now(),
        "event": kind,
        "details": details,
        "previous_event_hash": previous
    }
    raw = json.dumps(row, sort_keys=True, separators=(",", ":"))
    row["event_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    fd = os.open(ALERTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")

def check_once():
    baseline = json.loads(BASELINE.read_text())
    expected = baseline["files"]
    current = snapshot()
    problems = {}

    for name, expected_hash in expected.items():
        actual = current.get(name)
        if actual is None:
            problems[name] = "MISSING"
        elif actual != expected_hash:
            problems[name] = "HASH_CHANGED"

    old = {}
    try:
        old = json.loads(STATE.read_text()).get("problems", {})
    except Exception:
        pass

    if problems != old:
        if problems:
            log_event("INTEGRITY_WARNING", problems)
            notify("ShieldTrace: file integrity warning",
                   ", ".join(k + "=" + v for k, v in problems.items())[:400])
            print("[ALERT] File missing or changed:", problems, flush=True)
        elif old:
            log_event("BASELINE_MATCH_RESTORED", {"status": "files match baseline"})
            notify("ShieldTrace", "Tracked files match the saved baseline again.")
            print("[OK] Tracked files match baseline again.", flush=True)
        write_json(STATE, {"time": now(), "problems": problems})
    return problems

def main():
    os.umask(0o077)
    EVID.mkdir(mode=0o700, parents=True, exist_ok=True)
    CHECK.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(EVID, 0o700)
    os.chmod(CHECK, 0o700)

    if not BASELINE.is_file():
        message = "CRITICAL: integrity baseline missing; refusing to create a replacement."
        print("[ALERT]", message, flush=True)
        try:
            log_event("BASELINE_MISSING", {"path": str(BASELINE)})
            notify("ShieldTrace: critical integrity alert", message)
        except Exception:
            pass
        raise SystemExit(2)
    print("[OK] Existing baseline preserved; not overwritten.")

    if "--watch" not in sys.argv:
        check_once()
        return

    lock_path = EVID / "guard.lock"
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        print("[INFO] Integrity watchdog already running; exiting.", flush=True)
        return

    print("[OK] Integrity watchdog running; checks every 60 seconds.", flush=True)
    health_path = CHECK / "guard_health.json"
    last_success = None

    while True:
        checked_at = now()
        try:
            problems = check_once()
            last_success = now()
            health = {
                "status": "WARNING" if problems else "OK",
                "last_check": checked_at,
                "last_success": last_success,
                "problem_count": len(problems),
                "problems": problems,
                "pid": os.getpid()
            }
            write_json(health_path, health)
            print("[HEALTH]", health["status"],
                  "last_success=" + last_success, flush=True)

        except Exception as exc:
            print("[ERROR] Check failed:", repr(exc), flush=True)
            try:
                log_event("CHECK_FAILED", {"error": repr(exc)})
            except Exception:
                pass
            try:
                write_json(health_path, {
                    "status": "ERROR",
                    "last_check": checked_at,
                    "last_success": last_success,
                    "error": repr(exc),
                    "pid": os.getpid()
                })
            except Exception as health_exc:
                print("[ERROR] Health status write failed:",
                      repr(health_exc), flush=True)

        time.sleep(60)

if __name__ == "__main__":
    main()
