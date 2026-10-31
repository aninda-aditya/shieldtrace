#!/usr/bin/env python3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
ROOT = Path.home() / "storage" / "shared" / "Download"
STATE_DIR = PROJECT / "checkpoints"
STATE_FILE = STATE_DIR / "storage_baseline.json"
EVIDENCE_DIR = PROJECT / "evidence" / "storage_scans"

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def scan():
    results = {}
    errors = []

    for path in ROOT.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            rel = str(path.relative_to(ROOT))
            stat = path.stat()
            results[rel] = {
                "size": stat.st_size,
                "sha256": sha256_file(path),
            }
        except OSError as exc:
            errors.append(f"{path}: {exc}")

    return results, errors

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--accept", action="store_true",
                        help="Rewrite baseline with current state (audited)")
    args, _ = parser.parse_known_args()

    if not ROOT.is_dir():
        raise SystemExit(f"Downloads folder unavailable: {ROOT}")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    started = datetime.now(timezone.utc)
    current, errors = scan()

    added, removed, changed = [], [], []
    baseline_created = False

    if not STATE_FILE.exists():
        state = {
            "created_utc": started.isoformat(),
            "files": current,
        }
        STATE_FILE.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n"
        )
        baseline_created = True
        print(f"Baseline created: {len(current)} files")
        print(f"Location: {STATE_FILE}")
    else:
        baseline = json.loads(STATE_FILE.read_text())
        previous = baseline.get("files", {})
        old_keys, new_keys = set(previous), set(current)

        added = sorted(new_keys - old_keys)
        removed = sorted(old_keys - new_keys)
        changed = sorted(
            key for key in old_keys & new_keys
            if previous[key] != current[key]
        )

        print(f"Scanned: {len(current)} files")
        print(f"New: {len(added)}")
        print(f"Missing: {len(removed)}")
        print(f"Changed: {len(changed)}")

        for label, items in (
            ("NEW", added), ("MISSING", removed), ("CHANGED", changed)
        ):
            for item in items:
                print(f"[{label}] {item}")

        print("Baseline was not modified.")

    if args.accept and not baseline_created:
        old_copy = None
        if STATE_FILE.exists():
            stamp_old = started.strftime("%Y%m%d_%H%M%S_%f")
            old_copy = STATE_FILE.with_name(f"storage_baseline.accepted_old.{stamp_old}.json")
            old_copy.write_text(STATE_FILE.read_text())
        state = {
            "created_utc": started.isoformat(),
            "accepted_utc": started.isoformat(),
            "files": current,
        }
        STATE_FILE.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n"
        )
        print(f"[ACCEPT] Baseline rewritten: {len(current)} files")
        print(f"[ACCEPT] Previous baseline archived: {old_copy}")

    if errors:
        print(f"\nUnreadable items: {len(errors)}")
        for error in errors[:20]:
            print(f"[READ ERROR] {error}")

    report = {
        "timestamp_utc": started.isoformat(),
        "scan_root": str(ROOT),
        "baseline_file": str(STATE_FILE),
        "baseline_created": baseline_created,
        "baseline_preserved": not baseline_created,
        "summary": {
            "scanned": len(current),
            "new": len(added),
            "missing": len(removed),
            "changed": len(changed),
            "read_errors": len(errors),
        },
        "new_files": added,
        "missing_files": removed,
        "changed_files": changed,
        "read_errors": errors,
        "file_inventory": current,
    }

    stamp = started.strftime("%Y%m%d_%H%M%S_%f")
    report_path = EVIDENCE_DIR / f"storage_scan_{stamp}.json"
    raw = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    report_path.write_text(raw, encoding="utf-8")

    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    checksum_path = Path(str(report_path) + ".sha256")
    checksum_path.write_text(
        f"{digest}  {report_path.name}\n", encoding="ascii"
    )

    print(f"\n[JSON EVIDENCE] {report_path}")
    print(f"[SHA256] {digest}")
    print(f"[CHECKSUM] {checksum_path}")

if __name__ == "__main__":
    main()
