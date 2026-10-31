#!/data/data/com.termux/files/usr/bin/bash
EV="$HOME/shieldtrace/evidence/android_archive_events.jsonl"
if [ -f "$EV" ] && [ -s "$EV" ]; then
  last="$(tail -n 1 "$EV" | python -c 'import sys,json; print(json.loads(sys.stdin.read()).get("event_sha256",""))')"
  echo "========================================"
  echo "  EXTERNAL ANCHOR (copy off-device now)"
  echo "========================================"
  echo "Final event hash: $last"
  echo "Verify later with: python verify_android_archive.py"
else
  echo "No archive events yet."
fi
