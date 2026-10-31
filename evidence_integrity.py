#!/usr/bin/env python3
import os
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path.home() / "shieldtrace"
CHECKPOINTS = ROOT / "checkpoints"
EVIDENCE = ROOT / "evidence"

BASELINE = CHECKPOINTS / "guard_baseline.json"
ANCHOR = CHECKPOINTS / "guard_baseline.sha256"
AUDIT = EVIDENCE / "integrity_audit.jsonl"
ALERTS = EVIDENCE / "guard_alerts.jsonl"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def main():
    if not BASELINE.is_file():
        print("ERROR: baseline file missing; no changes made.")
        return 2

    try:
        # Check that baseline contains valid JSON and expected fields.
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
        if data.get("algorithm") != "SHA-256" or not isinstance(data.get("files"), dict):
            raise ValueError("unexpected baseline structure")
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: baseline invalid: {exc}")
        return 2

    current_hash = sha256_file(BASELINE)
    created_anchor = False

    if not ANCHOR.exists():
        # First run: establish a local reference; this is not independent proof.
        ANCHOR.write_text(current_hash + "\n", encoding="ascii")
        os.chmod(ANCHOR, 0o600)
        result = "ANCHOR_CREATED"
        detail = "Local reference created; compare with a separately saved copy."
        created_anchor = True
    else:
        try:
            saved_hash = ANCHOR.read_text(encoding="ascii").strip()
        except OSError as exc:
            print(f"ERROR: cannot read anchor: {exc}")
            return 2

        if len(saved_hash) != 64 or any(c not in "0123456789abcdef" for c in saved_hash.lower()):
            result = "ANCHOR_INVALID"
            detail = "Saved fingerprint is malformed."
        elif saved_hash.lower() == current_hash:
            result = "MATCH"
            detail = "Baseline matches the saved local fingerprint."
        else:
            result = "MISMATCH"
            detail = "Baseline differs from the saved fingerprint; cause is unknown."

    record = {
        "timestamp_utc": utc_now(),
        "event": "baseline_integrity_check",
        "result": result,
        "baseline_path": str(BASELINE),
        "sha256": current_hash,
        "detail": detail,
    }
    append_jsonl(AUDIT, record)

    if result in ("MISMATCH", "ANCHOR_INVALID"):
        append_jsonl(ALERTS, record)

    print(f"Result : {result}")
    print(f"SHA-256: {current_hash}")
    print(f"Audit  : {AUDIT}")
    if created_anchor:
        print("NOTE   : First-run anchor created locally; not independently trusted.")
    print(detail)

    return 1 if result in ("MISMATCH", "ANCHOR_INVALID") else 0


if __name__ == "__main__":
    sys.exit(main())
