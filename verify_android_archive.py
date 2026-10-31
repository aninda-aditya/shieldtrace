#!/data/data/com.termux/files/usr/bin/python
import json
import hashlib
from pathlib import Path

EVENTS = Path.home() / "shieldtrace/evidence/android_archive_events.jsonl"
ARCHIVE = Path.home() / "shieldtrace/evidence/android_archive"

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def main():
    if not EVENTS.is_file():
        raise SystemExit("[ERROR] Event log not found")

    previous = "GENESIS"
    count = 0

    for number, line in enumerate(EVENTS.read_text().splitlines(), 1):
        if not line.strip():
            continue

        event = json.loads(line)
        claimed = event.pop("event_sha256", None)

        if event.get("previous_event_sha256") != previous:
            raise SystemExit(f"[ALERT] Chain link mismatch at event {number}")

        actual = digest(event)
        if claimed != actual:
            raise SystemExit(f"[ALERT] Event hash mismatch at event {number}")

        snapshot = ARCHIVE / event["snapshot"]
        sidecar = ARCHIVE / f'{event["snapshot"]}.sha256'

        if not snapshot.is_file() or not sidecar.is_file():
            raise SystemExit(f"[ALERT] Snapshot or checksum missing at event {number}")

        expected_file_hash = sidecar.read_text().split()[0]
        actual_file_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()

        if expected_file_hash != actual_file_hash:
            raise SystemExit(f"[ALERT] Snapshot checksum mismatch at event {number}")

        if actual_file_hash != event["snapshot_sha256"]:
            raise SystemExit(f"[ALERT] Event snapshot hash mismatch at event {number}")

        previous = claimed
        count += 1

    print("[OK] Event chain verified.")
    print("Verified events:", count)
    print("Final event hash:", previous)

if __name__ == "__main__":
    main()
