import os, sys, json, hashlib, time, subprocess
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
EVID = BASE / "evidence"
CHECK = BASE / "checkpoints"
STATE = CHECK / "integrity_state.json"
REPORT = EVID / "hardening_audit.jsonl"

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def private(path, directory=False):
    try:
        os.chmod(path, 0o700 if directory else 0o600)
    except OSError:
        pass

def append_report(item):
    with REPORT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())

def main():
    BASE.mkdir(exist_ok=True)
    EVID.mkdir(exist_ok=True)
    CHECK.mkdir(exist_ok=True)
    for d in (BASE, EVID, CHECK):
        private(d, True)

    targets = [
        BASE / "fortress.py",
        BASE / "shieldtrace.py",
        BASE / "start_defense.sh",
        BASE / "defence_mode.py",
        BASE / "shieldtrace.py.bak",
    ]
    current = {}
    for p in targets:
        if p.is_file():
            current[str(p.relative_to(BASE))] = sha(p.read_bytes())
            private(p)

    if STATE.exists():
        try:
            old = json.loads(STATE.read_text(encoding="utf-8"))
            previous = old.get("files", {})
            changes = {
                k: {"previous": previous.get(k), "current": v}
                for k, v in current.items()
                if previous.get(k) != v
            }
            missing = sorted(set(previous) - set(current))
            status = "CHANGED_OR_MISSING" if changes or missing else "UNCHANGED"
        except Exception as e:
            changes, missing = {"state_error": str(e)}, []
            status = "STATE_UNREADABLE"
    else:
        changes, missing, status = {}, [], "INITIAL_BASELINE"

    # Checkpoint records the current state; it is not a digital signature.
    state = {
        "time": utc(),
        "files": current,
        "previous_checkpoint_sha256": (
            sha(STATE.read_bytes()) if STATE.exists() else None
        ),
        "note": "Local checkpoint only; an attacker with write access may alter it."
    }
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    private(tmp)
    os.replace(tmp, STATE)
    private(STATE)

    pidfile = EVID / "defense.pid"
    pid = None
    process_ok = False
    try:
        raw = pidfile.read_text().strip()
        if raw.isdigit():
            pid = int(raw)
            cmdline = Path(f"/proc/{pid}/cmdline")
            if cmdline.exists():
                cmd = cmdline.read_bytes().replace(b"\0", b" ").decode(errors="replace")
                process_ok = "import fortress; fortress.safe_auto_defense()" in cmd
    except OSError:
        pass

    report = {
        "time": utc(),
        "integrity_status": status,
        "changed_files": changes,
        "missing_files": missing,
        "defense_pid": pid,
        "defense_process_verified": process_ok,
        "limitations": [
            "Local checkpoints are not attacker-proof.",
            "Non-root Termux cannot inspect all Android processes or app-private data.",
            "A verified process does not prove the phone is malware-free."
        ]
    }
    append_report(report)

    print("=== ShieldTrace Defensive Hardening Audit ===")
    print("Integrity:", status)
    print("Tracked files:", len(current))
    print("Defense process verified:", process_ok)
    if changes:
        print("Changed files:", json.dumps(changes, indent=2))
    if missing:
        print("Missing tracked files:", ", ".join(missing))
    print("Checkpoint:", STATE)
    print("Audit log:", REPORT)
    print("Note: first run creates a baseline; later code changes need review.")
    print("No process was stopped and no existing evidence log was deleted.")

if __name__ == "__main__":
    main()
