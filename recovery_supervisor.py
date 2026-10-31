import os
import sys
import time
import json
import fcntl
import signal
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path.home() / "shieldtrace"
EVID = ROOT / "evidence"

MODULES = {
    "defense": {
        "pidfile": EVID / "defense.pid",
        "log": EVID / "background.log",
    },
    "guard": {
        "pidfile": EVID / "guard.pid",
        "log": EVID / "hardening_guard.log",
    },
    "thermal": {
        "pidfile": EVID / "thermal.pid",
        "log": EVID / "thermal_monitor.log",
    },
}

LOCK = EVID / "recovery_supervisor.lock"
LOG = EVID / "recovery_supervisor.log"
HEALTH = EVID / "recovery_health.json"


def log(message):
    stamp = datetime.now(timezone.utc).isoformat()
    line = f"{stamp} | {message}"
    print(line, flush=True)
    with LOG.open("a") as f:
        f.write(line + "\n")


def read_cmdline(pid):
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\0", b" ").decode(errors="replace").strip()
    except (OSError, PermissionError):
        return ""


def matches(kind, cmd):
    if kind == "defense":
        return "import fortress" in cmd and "fortress.safe_auto_defense()" in cmd
    if kind == "guard":
        return "hardening_guard.py" in cmd and "--watch" in cmd
    if kind == "thermal":
        return "thermal_monitor.py" in cmd
    return False


def find_processes(kind):
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        cmd = read_cmdline(pid)
        if cmd and matches(kind, cmd):
            found.append(pid)
    return sorted(set(found))


def read_pid(path):
    try:
        value = path.read_text().strip()
        return int(value) if value.isdigit() else None
    except (OSError, ValueError):
        return None


def inspect(kind):
    info = MODULES[kind]
    saved_pid = read_pid(info["pidfile"])
    saved_cmd = read_cmdline(saved_pid) if saved_pid else ""
    saved_valid = bool(saved_cmd and matches(kind, saved_cmd))
    found = find_processes(kind)

    return {
        "pidfile_pid": saved_pid,
        "pidfile_valid": saved_valid,
        "matching_pids": found,
        "status": "RUNNING" if found else "STOPPED",
        "duplicate_count": max(0, len(found) - 1),
    }


def launch(kind):
    info = MODULES[kind]
    log(f"{kind}: recovery requested")

    with info["log"].open("a") as output:
        if kind == "defense":
            result = subprocess.run(
                ["bash", str(ROOT / "start_defense.sh")],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=25,
            )
            log(f"defense: launcher exit={result.returncode}")

        elif kind == "guard":
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "hardening_guard.py"), "--watch"],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            log(f"guard: launch requested pid={proc.pid}")

        elif kind == "thermal":
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "thermal_monitor.py")],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            log(f"thermal: launch requested pid={proc.pid}")

    time.sleep(2)
    current = find_processes(kind)
    if current:
        info["pidfile"].write_text(str(current[0]) + "\n")
        log(f"{kind}: verified pid={current[0]}")
    else:
        log(f"{kind}: recovery failed; no matching process found")


def check_once(recover=False):
    report = {
        "time": datetime.now(timezone.utc).isoformat(),
        "mode": "recovery" if recover else "diagnostic",
        "modules": {},
    }

    for kind in MODULES:
        state = inspect(kind)
        report["modules"][kind] = state

        log(
            f"{kind}: {state['status']} "
            f"pidfile={state['pidfile_pid']} "
            f"matches={state['matching_pids']} "
            f"duplicates={state['duplicate_count']}"
        )

        if recover and not state["matching_pids"]:
            try:
                launch(kind)
            except Exception as exc:
                log(f"{kind}: ERROR during recovery: {exc}")

        elif recover and state["duplicate_count"]:
            log(f"{kind}: ALERT duplicate processes; no process killed")

        elif recover and state["matching_pids"]:
            actual = state["matching_pids"][0]
            if state["pidfile_pid"] != actual or not state["pidfile_valid"]:
                MODULES[kind]["pidfile"].write_text(str(actual) + "\n")
                log(f"{kind}: PID file corrected to {actual}")

    HEALTH.write_text(json.dumps(report, indent=2) + "\n")


def main():
    EVID.mkdir(parents=True, exist_ok=True)

    mode = sys.argv[1] if len(sys.argv) > 1 else "--once"
    if mode not in ("--once", "--watch"):
        print("Usage: python recovery_supervisor.py [--once|--watch]")
        return 2

    lock_fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Recovery Supervisor already running; exiting.")
        os.close(lock_fd)
        return 1

    if mode == "--once":
        check_once(recover=False)
        return 0

    log("Recovery Supervisor started; interval=15 seconds")
    try:
        while True:
            check_once(recover=True)
            time.sleep(15)
    except KeyboardInterrupt:
        log("Recovery Supervisor stopped by user")
    finally:
        os.close(lock_fd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
