#!/data/data/com.termux/files/usr/bin/python
import os
import json
import hashlib
import fcntl
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
EVID = BASE / "evidence"
SOURCE = EVID / "android_audit_latest.json"
ARCHIVE = EVID / "android_archive"
EVENTS = EVID / "android_archive_events.jsonl"
LOCK = EVID / "android_archive.lock"

os.umask(0o077)
ARCHIVE.mkdir(parents=True, exist_ok=True)

def utc_now():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")

def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":")
    ).encode()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def append_event(event):
    previous = "GENESIS"

    if EVENTS.exists():
        lines = EVENTS.read_text().splitlines()
        if lines:
            last = json.loads(lines[-1])
            claimed = last.pop("event_sha256", None)
            if claimed != sha256(canonical(last)):
                raise RuntimeError("Previous event hash mismatch")
            previous = claimed

    event["previous_event_sha256"] = previous
    event["event_sha256"] = sha256(canonical(event))

    with EVENTS.open("a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())

def main():
    if not SOURCE.is_file():
        raise RuntimeError("Android audit report not found")

    raw = SOURCE.read_bytes()
    report = json.loads(raw)

    expected = report.get("report_sha256")
    content = dict(report)
    content.pop("report_sha256", None)
    actual = sha256(canonical(content))

    if not expected or expected != actual:
        raise RuntimeError(
            f"REPORT HASH MISMATCH: expected={expected}, actual={actual}"
        )

    stamp = utc_now()
    digest = sha256(raw)
    name = f"android_audit_{stamp}_{digest[:12]}.json"

    snapshot = ARCHIVE / name
    checksum = ARCHIVE / f"{name}.sha256"

    # Exclusive creation: never overwrite an existing snapshot.
    with snapshot.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

    try:
        with checksum.open("x") as f:
            f.write(f"{digest}  {name}\n")
            f.flush()
            os.fsync(f.fileno())

        append_event({
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "action": "ANDROID_AUDIT_ARCHIVED",
            "snapshot": name,
            "snapshot_sha256": digest,
            "report_internal_sha256": expected,
            "verification": "MATCH"
        })

    except Exception:
        # Preserve the snapshot for investigation; never silently delete it.
        raise

    print("[OK] Evidence archived.")
    print("Snapshot:", snapshot)
    print("SHA-256:", digest)
    print("Internal report hash: MATCH")
    print("Event log:", EVENTS)

if __name__ == "__main__":
    EVID.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            main()
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
