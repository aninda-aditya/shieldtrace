#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
umask 077

GREEN=$'\033[92m'; YELLOW=$'\033[93m'; CYAN=$'\033[96m'
BOLD=$'\033[1m'; RESET=$'\033[0m'

info() { printf '%s[*]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok()   { printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

[ -d "/data/data/com.termux/files/usr" ] || die "Termux only."

info "Installing dependencies (python, termux-api, git, curl)..."
pkg install -y python termux-api git curl >/dev/null 2>&1 || warn "pkg install partial."
command -v python >/dev/null || die "python not found."

if command -v pm >/dev/null 2>&1; then
  if ! pm list packages 2>/dev/null | grep -q "com.termux.api"; then
    warn "Termux:API app missing. Install: https://f-droid.org/packages/com.termux.api/"
  else
    ok "Termux:API app detected."
  fi
fi

SRC="$(cd "$(dirname "$0")" && pwd)"
DST="$HOME/shieldtrace"

if [ "$SRC" = "$DST" ]; then
  info "Already in $DST, skipping copy."
else
  info "Installing to $DST ..."
  mkdir -p "$DST"
  for f in "$SRC"/*.py "$SRC"/*.sh; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    if [ -e "$DST/$base" ] && ! cmp -s "$f" "$DST/$base"; then
      warn "Keeping existing $base."
      continue
    fi
    cp "$f" "$DST/$base"
  done
fi

mkdir -p "$DST/evidence" "$DST/checkpoints"
chmod 700 "$DST/evidence" "$DST/checkpoints"

info "Verifying Python syntax..."
fail=0
for f in "$DST"/*.py; do
  if ! python -m py_compile "$f" 2>/dev/null; then
    warn "Syntax error: $(basename "$f")"
    fail=$((fail+1))
  fi
done
[ "$fail" -eq 0 ] && ok "All Python compiled." || warn "$fail failed."

for f in "$DST"/*.sh; do
  bash -n "$f" 2>/dev/null || warn "Bash error: $(basename "$f")"
done
ok "Bash syntax checked."

if [ ! -f "$DST/checkpoints/guard_baseline.json" ]; then
  info "Creating initial baseline..."
  python - <<'PY' || true
import hashlib, json
from pathlib import Path
from datetime import datetime, timezone
root = Path.home() / "shieldtrace"
ck = root / "checkpoints"
files = {}
for p in sorted(list(root.glob("*.py")) + list(root.glob("*.sh"))):
    if p.is_file():
        files[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
baseline = {"algorithm": "SHA-256", "created_utc": datetime.now(timezone.utc).isoformat(), "files": files}
(ck / "guard_baseline.json").write_text(json.dumps(baseline, indent=2, sort_keys=True))
print(f"baseline written: {len(files)} files")
PY
  ok "Baseline created."
else
  ok "Baseline exists - untouched."
fi

chmod +x "$DST"/*.sh "$DST"/*.py 2>/dev/null || true

echo
printf '%s========================================%s\n' "$BOLD" "$RESET"
printf '%s  ShieldTrace installed%s\n' "$BOLD" "$RESET"
printf '%s========================================%s\n' "$BOLD" "$RESET"
echo "  Location : $DST"
echo "  Evidence : $DST/evidence"
echo "  Baseline : $DST/checkpoints/guard_baseline.json"
echo
echo "  Next steps:"
echo "    1. ~/shieldtrace/auto_audit.py"
echo "    2. ~/shieldtrace/shieldtrace_dashboard.py"
echo "    3. ~/shieldtrace/guardian.py --init"
echo
echo "  Uninstall:  ~/shieldtrace/UNINSTALL.sh"
echo "  Full wipe:  ~/shieldtrace/UNINSTALL.sh --purge"
echo

command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock 2>/dev/null || true

ok "Done."
