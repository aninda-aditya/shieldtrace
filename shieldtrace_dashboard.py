#!/usr/bin/env python3
import os
import sys
import json
import time
import signal
import hashlib
import tempfile
import subprocess
import select
import termios
import tty
from pathlib import Path
from datetime import datetime, timezone

HOME = Path.home()
ROOT = HOME / "shieldtrace"
EVIDENCE = ROOT / "evidence"
CHECKPOINTS = ROOT / "checkpoints"

DEFENSE_PID = EVIDENCE / "defense.pid"
GUARD_PID = EVIDENCE / "guard.pid"
DEFENSE_LOG = EVIDENCE / "background.log"
GUARD_LOG = EVIDENCE / "hardening_guard.log"
ALERT_LOG = EVIDENCE / "guard_alerts.jsonl"

STORAGE_SCRIPT = ROOT / "storage_monitor.py"
GUARD_SCRIPT = ROOT / "hardening_guard.py"
DEFENSE_SCRIPT = ROOT / "start_defense.sh"
THERMAL_PID = EVIDENCE / "thermal.pid"
THERMAL_LOG = EVIDENCE / "thermal_monitor.log"
THERMAL_SCRIPT = ROOT / "thermal_monitor.py"
RECOVERY_SCRIPT = ROOT / "recovery_supervisor.py"
RECOVERY_PID = EVIDENCE / "recovery_supervisor.pid"
RECOVERY_LOG = EVIDENCE / "recovery_supervisor.log"
RECOVERY_HEALTH = EVIDENCE / "recovery_health.json"
BASELINE = CHECKPOINTS / "storage_baseline.json"

RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"

NOTICE = "Dashboard initialized."
LAST_SCAN = "Not run from dashboard yet."
LAST_TEST = "Not run yet."
SCAN_PROC = None
SCAN_LOG = EVIDENCE / "storage_scan_dashboard.log"



def now():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def read_pid(path):
    try:
        value = int(path.read_text().strip())
        return value if value > 1 else None
    except (OSError, ValueError):
        return None


def process_info(path, kind):
    """Only mark a process verified when its command line matches."""
    pid = read_pid(path)
    if pid is None:
        return "STOPPED / NO PID", None

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "STALE PID", pid
    except PermissionError:
        return "UNKNOWN / PERMISSION", pid
    except OSError:
        return "UNKNOWN", pid

    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        cmd = raw.replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        return "RUNNING / UNVERIFIED", pid

    if not cmd:
        return "UNKNOWN / CMDLINE", pid

    if kind == "defense":
        matches = "fortress" in cmd and "safe_auto_defense" in cmd
    elif kind == "guard":
        matches = "hardening_guard.py" in cmd and "--watch" in cmd
    elif kind == "thermal":
        matches = "thermal_monitor.py" in cmd
    else:
        matches = False

    if matches:
        return "RUNNING / VERIFIED", pid
    return "PID EXISTS / MISMATCH", pid


def tail(path, count=4):
    try:
        lines = path.read_text(errors="replace").splitlines()
        return lines[-count:] or ["(log is empty)"]
    except OSError:
        return ["(log unavailable)"]


def baseline_count():
    try:
        data = json.loads(BASELINE.read_text())
        return len(data.get("files", {}))
    except (OSError, ValueError, TypeError):
        return None


def color_status(text):
    upper = text.upper()
    if "VERIFIED" in upper:
        return GREEN + text + RESET
    if "STOPPED" in upper:
        return YELLOW + text + RESET
    if "STALE" in upper or "MISMATCH" in upper:
        return RED + text + RESET
    return YELLOW + text + RESET


def line(text=""):
    print(text)



def integrity_summary():
    import hashlib

    # This fingerprint belongs to guard_baseline.json,
    # not storage_baseline.json used by the Downloads scanner.
    guard_baseline = CHECKPOINTS / "guard_baseline.json"
    anchor = CHECKPOINTS / "guard_baseline.sha256"
    audit = EVIDENCE / "integrity_audit.jsonl"
    alerts = EVIDENCE / "guard_alerts.jsonl"

    result = "NOT INITIALIZED"
    last_check = "No recorded check"
    last_result = "NOT RECORDED"

    try:
        if not guard_baseline.is_file():
            result = "BASELINE MISSING"
        elif not anchor.is_file():
            result = "NOT INITIALIZED"
        else:
            current = hashlib.sha256(guard_baseline.read_bytes()).hexdigest()
            saved = anchor.read_text(encoding="ascii").strip().lower()
            if len(saved) != 64 or any(c not in "0123456789abcdef" for c in saved):
                result = "ANCHOR INVALID"
            else:
                result = "MATCH" if current == saved else "MISMATCH"
    except (OSError, ValueError):
        result = "UNKNOWN / READ ERROR"

    try:
        entries = audit.read_text(errors="replace").splitlines()
        if entries:
            item = json.loads(entries[-1])
            last_check = item.get("timestamp_utc", "Timestamp unavailable")
            last_result = item.get("result", "UNKNOWN")
    except (OSError, ValueError, TypeError):
        pass

    try:
        alert_count = len(alerts.read_text(errors="replace").splitlines())
    except OSError:
        alert_count = 0

    return result, last_check, last_result, alert_count


def render():
    refresh_scan_status()
    os.system("clear")
    width = 68
    title = " SHIELDTRACE // MOBILE DEFENSE OPERATIONS "
    line(CYAN + BOLD + "=" * width + RESET)
    line(CYAN + BOLD + title.center(width) + RESET)
    line(GREEN + BOLD + "ANINDA ADITYA".center(width) + RESET)
    line(CYAN + "=" * width + RESET)
    line(f" Local time : {now()}")
    line(f" Project    : {ROOT}")
    line(" Platform   : Android / Termux / non-root")
    line(BLUE + "-" * width + RESET)

    d_status, d_pid = process_info(DEFENSE_PID, "defense")
    g_status, g_pid = process_info(GUARD_PID, "guard")
    h_status, h_pid = process_info(THERMAL_PID, "thermal")
    recovery_pids = find_recovery_processes()
    recovery_pid = recovery_pids[0] if len(recovery_pids) == 1 else None
    recovery_status = (
        "RUNNING / VERIFIED" if recovery_pid else
        "DUPLICATE DETECTED" if len(recovery_pids) > 1 else
        "STOPPED"
    )
    health_time = "Not available"
    try:
        health = json.loads(RECOVERY_HEALTH.read_text())
        health_time = health.get("time", "Unknown")
    except (OSError, ValueError, TypeError):
        pass
    count = baseline_count()

    # Keep all keyboard controls visible on small Termux screens.
    line(BOLD + " [ QUICK CONTROLS ]" + RESET)
    line(" [S] Scan [T] Tamper [D] Defense [X] Stop")
    line(" [W] Watchdog [V] Stop [A] Arsenal")
    line(" [H] Thermal Monitor (toggle)")
    line(" [C] Recovery Supervisor (toggle)")
    line(" [R] Refresh [Q] Quit")
    line(BLUE + "-" * width + RESET)

    line(BOLD + " [ LIVE OPERATIONS ]" + RESET)
    line(f" Defense : {color_status(d_status)} PID={d_pid or '-'}")
    line(f" Watchdog: {color_status(g_status)} PID={g_pid or '-'}")
    line(f" Thermal : {color_status(h_status)} PID={h_pid or '-'}")
    line(f" Recovery: {color_status(recovery_status)} PID={recovery_pid or '-'}")
    line(f" Recovery check: {health_time[:25]}")
    line(f" Baseline: {count if count is not None else 'INVALID'} files")
    line(f" Last scan: {LAST_SCAN}")
    line(f" Tamper: {LAST_TEST}")
    line(BLUE + "-" * width + RESET)

    integrity, checked, last_result, alert_count = integrity_summary()
    status_color = GREEN if integrity == "MATCH" else RED if integrity in ("MISMATCH", "ANCHOR INVALID", "BASELINE MISSING") else YELLOW
    line(BOLD + " [ EVIDENCE INTEGRITY ]" + RESET)
    line(f" Baseline: {status_color}{integrity}{RESET}")
    line(f" Audit: {last_result} | Alerts: {alert_count}")
    line(f" Checked: {checked}")
    line(DIM + " Privileged tampering is not prevented." + RESET)

    line(BOLD + " [ RECENT LOGS ]" + RESET)
    for item in tail(DEFENSE_LOG, 1):
        line(" D: " + item[:width - 5])
    for item in tail(GUARD_LOG, 1):
        line(" W: " + item[:width - 5])
    for item in tail(ALERT_LOG, 1):
        line(" A: " + item[:width - 5])
    for item in tail(RECOVERY_LOG, 1):
        line(" R: " + item[:width - 5])

    line(BLUE + "-" * width + RESET)
    line(" " + NOTICE[:width - 2])
    line(DIM + " Auto-refresh: 5 seconds | Press a key." + RESET)


def run_storage_scan():
    """Start scan in a child process so the dashboard stays responsive."""
    global NOTICE, SCAN_PROC

    if SCAN_PROC is not None and SCAN_PROC.poll() is None:
        NOTICE = "Storage scan is already running in background."
        return

    if not STORAGE_SCRIPT.is_file():
        NOTICE = "storage_monitor.py not found."
        return

    try:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        with SCAN_LOG.open("w") as log:
            SCAN_PROC = subprocess.Popen(
                [sys.executable, str(STORAGE_SCRIPT)],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        NOTICE = f"Storage scan started in background (PID {SCAN_PROC.pid})."
    except OSError as exc:
        SCAN_PROC = None
        NOTICE = f"Could not start storage scan: {exc}"


def refresh_scan_status():
    global SCAN_PROC, LAST_SCAN, NOTICE

    if SCAN_PROC is None:
        return

    code = SCAN_PROC.poll()
    if code is None:
        NOTICE = f"Storage scan running in background (PID {SCAN_PROC.pid})."
        return

    try:
        lines = SCAN_LOG.read_text(errors="replace").splitlines()
        summary = " | ".join(lines[-5:]) if lines else "(no output)"
    except OSError:
        summary = "(scan log unavailable)"

    LAST_SCAN = now()
    NOTICE = f"Storage scan finished, exit={code}: {summary}"
    SCAN_PROC = None

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_tamper_test():
    """Test hashing only inside a disposable temporary directory."""
    global NOTICE, LAST_TEST
    try:
        with tempfile.TemporaryDirectory(prefix="shieldtrace_test_") as folder:
            test_file = Path(folder) / "canary.txt"
            test_file.write_text("shieldtrace test version one\n")
            before = digest(test_file)

            test_file.write_text("shieldtrace test version two\n")
            after = digest(test_file)

            passed = before != after
            LAST_TEST = ("PASS" if passed else "FAIL") + " at " + now()
            NOTICE = (
                "PASS: isolated file change detected."
                if passed else
                "FAIL: isolated test did not detect the change."
            )
    except OSError as exc:
        LAST_TEST = "ERROR at " + now()
        NOTICE = f"Tamper test error: {exc}"


def start_defense():
    global NOTICE
    if not DEFENSE_SCRIPT.is_file():
        NOTICE = "start_defense.sh not found; no action taken."
        return
    status, _ = process_info(DEFENSE_PID, "defense")
    if status == "RUNNING / VERIFIED":
        NOTICE = "Defense is already verified as running."
        return
    try:
        result = subprocess.run(
            ["bash", str(DEFENSE_SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=20,
        )
        NOTICE = (result.stdout + result.stderr).strip()[-400:]
        if not NOTICE:
            NOTICE = f"Launcher exit code: {result.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        NOTICE = f"Could not run defense launcher: {exc}"


def start_guard():
    global NOTICE
    if not GUARD_SCRIPT.is_file():
        NOTICE = "hardening_guard.py not found."
        return

    status, _ = process_info(GUARD_PID, "guard")
    if status == "RUNNING / VERIFIED":
        NOTICE = "Integrity watchdog is already verified as running."
        return

    try:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        with GUARD_LOG.open("a") as log:
            proc = subprocess.Popen(
                [sys.executable, str(GUARD_SCRIPT), "--watch"],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        GUARD_PID.write_text(str(proc.pid) + "\n")
        time.sleep(0.4)
        status, pid = process_info(GUARD_PID, "guard")
        NOTICE = f"Watchdog launch PID={proc.pid}; status={status}."
    except OSError as exc:
        NOTICE = f"Could not start watchdog: {exc}"


def start_thermal():
    global NOTICE
    if not THERMAL_SCRIPT.is_file():
        NOTICE = "Thermal monitor script not found."
        return
    status, _ = process_info(THERMAL_PID, "thermal")
    if status == "RUNNING / VERIFIED":
        NOTICE = "Thermal Monitor is already running."
        return
    try:
        with THERMAL_LOG.open("a") as log:
            proc = subprocess.Popen(
                [sys.executable, str(THERMAL_SCRIPT)],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        THERMAL_PID.write_text(str(proc.pid) + "\n")
        time.sleep(0.3)
        status, pid = process_info(THERMAL_PID, "thermal")
        NOTICE = f"Thermal launch PID={proc.pid}; status={status}."
    except Exception as exc:
        NOTICE = f"Thermal launch failed: {exc}"


def toggle_thermal():
    status, _ = process_info(THERMAL_PID, "thermal")
    if status == "RUNNING / VERIFIED":
        stop_verified(THERMAL_PID, "thermal")
    else:
        start_thermal()


def find_recovery_processes():
    found = []
    try:
        entries = Path("/proc").iterdir()
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmd = (entry / "cmdline").read_bytes().replace(
                    b"\0", b" "
                ).decode(errors="replace")
            except OSError:
                continue
            if (
                "recovery_supervisor.py" in cmd
                and "--watch" in cmd
            ):
                found.append(pid)
    except OSError:
        pass
    return sorted(set(found))


def toggle_recovery():
    global NOTICE
    pids = find_recovery_processes()

    if len(pids) > 1:
        NOTICE = f"Multiple Recovery Supervisors detected: {pids}. No signal sent."
        return

    if len(pids) == 1:
        pid = pids[0]
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
                b"\0", b" "
            ).decode(errors="replace")
            if "recovery_supervisor.py" not in cmd or "--watch" not in cmd:
                NOTICE = "Recovery PID verification failed; no signal sent."
                return
            RECOVERY_PID.write_text(str(pid) + "\n")
            os.kill(pid, signal.SIGTERM)
            NOTICE = f"SIGTERM sent to verified Recovery Supervisor PID {pid}."
        except OSError as exc:
            NOTICE = f"Could not stop Recovery Supervisor: {exc}"
        return

    if not RECOVERY_SCRIPT.is_file():
        NOTICE = "recovery_supervisor.py not found."
        return

    try:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        with RECOVERY_LOG.open("a") as output:
            proc = subprocess.Popen(
                [sys.executable, str(RECOVERY_SCRIPT), "--watch"],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        RECOVERY_PID.write_text(str(proc.pid) + "\n")
        time.sleep(0.5)
        current = find_recovery_processes()
        if proc.pid in current:
            NOTICE = f"Recovery Supervisor started and verified: PID {proc.pid}."
        else:
            NOTICE = f"Recovery launch requested; verification pending. PID={proc.pid}"
    except OSError as exc:
        NOTICE = f"Could not start Recovery Supervisor: {exc}"


def stop_verified(path, kind):
    global NOTICE
    status, pid = process_info(path, kind)
    if status != "RUNNING / VERIFIED" or pid is None:
        NOTICE = f"Refused to stop process: {status}. No signal sent."
        return

    try:
        os.kill(pid, signal.SIGTERM)
        NOTICE = f"SIGTERM sent to verified {kind} PID {pid}."
        time.sleep(0.3)
        new_status, _ = process_info(path, kind)
        if new_status != "RUNNING / VERIFIED":
            NOTICE += f" Current status: {new_status}."
    except OSError as exc:
        NOTICE = f"Stop request failed: {exc}"


def main():
    global NOTICE
    if not sys.stdin.isatty():
        print("Run this dashboard directly in an interactive Termux terminal.")
        return 2

    old_settings = termios.tcgetattr(sys.stdin.fileno())
    try:
        tty.setcbreak(sys.stdin.fileno())
        while True:
            render()
            started = time.monotonic()
            key = ""

            # Refresh every 5 seconds; keyboard remains responsive.
            while time.monotonic() - started < 5:
                ready, _, _ = select.select([sys.stdin], [], [], 0.25)
                if ready:
                    key = sys.stdin.read(1).lower()
                    break

            if not key:
                continue
            if key == "a":
                arsenal = ROOT / "tool_arsenal.py"
                if arsenal.is_file():
                    # Restore normal terminal input for the child menu.
                    termios.tcsetattr(
                        sys.stdin.fileno(), termios.TCSADRAIN, old_settings
                    )
                    try:
                        subprocess.run(
                            [sys.executable, str(arsenal)],
                            cwd=str(ROOT)
                        )
                    finally:
                        # Restore dashboard's responsive keyboard mode.
                        tty.setcbreak(sys.stdin.fileno())

                    NOTICE = "Tool Arsenal session ended."
                else:
                    NOTICE = "tool_arsenal.py not found."
            elif key == "q":
                break
            elif key == "r":
                NOTICE = "Manual refresh."
            elif key == "s":
                run_storage_scan()
            elif key == "t":
                safe_tamper_test()
            elif key == "d":
                start_defense()
            elif key == "x":
                stop_verified(DEFENSE_PID, "defense")
            elif key == "w":
                start_guard()
            elif key == "v":
                stop_verified(GUARD_PID, "guard")
            elif key == "h":
                toggle_thermal()
            elif key == "c":
                toggle_recovery()
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
        print(RESET + "\033[2J\033[HShieldTrace dashboard closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
