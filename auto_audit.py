#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path.home() / "shieldtrace"
EVIDENCE = ROOT / "evidence"
CHECKPOINTS = ROOT / "checkpoints"
AUDIT_LOG = EVIDENCE / "auto_audit.jsonl"

REQUIRED_DIRS = [EVIDENCE, CHECKPOINTS]
PY_FILES = list(ROOT.glob("*.py"))
PID_FILES = {
    "defense": EVIDENCE / "defense.pid",
    "guard": EVIDENCE / "guard.pid",
}

def now():
    return datetime.now(timezone.utc).isoformat()

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def log_event(event):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def process_matches(pid, expected):
    cmd = Path(f"/proc/{pid}/cmdline")
    try:
        raw = cmd.read_bytes().replace(b"\0", b" ").decode(errors="replace")
        if expected == "defense":
            return "fortress" in raw and "safe_auto_defense" in raw
        if expected == "guard":
            return "hardening_guard.py" in raw and "--watch" in raw
    except (OSError, PermissionError):
        pass
    return False

def main():
    print("\n=== SHIELDTRACE AUTOMATIC AUDIT ===")
    print("Time:", now())
    results = []
    repairs = []

    # Required directories
    for folder in REQUIRED_DIRS:
        if not folder.exists():
            folder.mkdir(parents=True, exist_ok=True)
            repairs.append(f"Created missing directory: {folder.name}")
            results.append(("DIRECTORY", "FIXED", folder.name))
        else:
            results.append(("DIRECTORY", "OK", folder.name))

    # Python syntax check without writing .pyc files
    for path in sorted(ROOT.glob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
            results.append(("PYTHON_SYNTAX", "OK", path.name))
        except Exception as exc:
            results.append(("PYTHON_SYNTAX", "FAIL", f"{path.name}: {exc}"))

    # Baseline integrity: never rewrite the anchor automatically
    baseline = CHECKPOINTS / "guard_baseline.json"
    anchor = CHECKPOINTS / "guard_baseline.sha256"
    if baseline.is_file() and anchor.is_file():
        actual = sha256(baseline)
        expected = anchor.read_text(encoding="utf-8").strip().split()[0]
        if actual == expected:
            results.append(("BASELINE", "MATCH", actual))
        else:
            results.append(("BASELINE", "MISMATCH", "Manual investigation required"))
    else:
        results.append(("BASELINE", "MISSING", "Baseline or anchor missing; not recreated"))

    # Verify defense and watchdog PID files
    for name, pidfile in PID_FILES.items():
        if not pidfile.exists():
            results.append(("PROCESS", "PID_FILE_MISSING", name))
            continue

        try:
            pid_text = pidfile.read_text(encoding="utf-8").strip()
            pid = int(pid_text)
        except Exception:
            pid = -1

        if pid > 0 and process_matches(pid, name):
            results.append(("PROCESS", "RUNNING_VERIFIED", f"{name}: PID {pid}"))
        else:
            # Preserve stale PID file as evidence; archive rather than delete.
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            archived = pidfile.with_name(f"{pidfile.name}.stale.{stamp}.{os.getpid()}")
            try:
                os.replace(pidfile, archived)
                repairs.append(f"Archived stale PID file: {archived.name}")
                results.append(("PROCESS", "STALE_ARCHIVED", name))
            except OSError as exc:
                results.append(("PROCESS", "STALE_NOT_ARCHIVED", f"{name}: {exc}"))

    # Record results
    for category, status, detail in results:
        print(f"[{status}] {category}: {detail}")
        log_event({
            "time": now(),
            "category": category,
            "status": status,
            "detail": detail,
        })

    for item in repairs:
        print("[SAFE-FIX]", item)

    failures = sum(1 for _, status, _ in results
                   if status in ("FAIL", "MISMATCH", "MISSING",
                                 "STALE_NOT_ARCHIVED"))

    print("\n=== AUDIT SUMMARY ===")
    print("Checks:", len(results))
    print("Safe fixes:", len(repairs))
    print("Issues requiring attention:", failures)
    print("Audit log:", AUDIT_LOG)

    if failures:
        print("Status: REVIEW REQUIRED")
        return 2

    print("Status: AUDIT COMPLETED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
