#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

DST="$HOME/shieldtrace"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

GREEN=$'\033[92m'; YELLOW=$'\033[93m'; RESET=$'\033[0m'
info() { printf '[*] %s\n' "$*"; }
ok()   { printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }

[ -d "$DST" ] || { warn "$DST not found."; exit 0; }

stop_if_matches() {
  local pidfile="$1" needle="$2" label="$3"
  [ -f "$pidfile" ] || return 0
  local pid; pid="$(cat "$pidfile" 2>/dev/null || true)"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || { info "$label: stale PID $pid."; return 0; }
  local cmd=""
  [ -r "/proc/$pid/cmdline" ] && cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  if [[ "$cmd" == *"$needle"* ]]; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 0.5
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    ok "$label: stopped PID $pid"
  else
    warn "$label: PID $pid mismatch, not killed."
  fi
}

info "Stopping verified processes..."
stop_if_matches "$DST/evidence/defense.pid"              "safe_auto_defense"       "defense"
stop_if_matches "$DST/evidence/guard.pid"                "hardening_guard.py"      "watchdog"
stop_if_matches "$DST/evidence/thermal.pid"              "thermal_monitor.py"      "thermal"
stop_if_matches "$DST/evidence/recovery_supervisor.pid"  "recovery_supervisor.py"  "recovery"
stop_if_matches "$DST/evidence/guardian.pid"             "guardian.py"             "guardian"

command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock 2>/dev/null || true

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
for f in defense guard thermal recovery_supervisor guardian; do
  p="$DST/evidence/$f.pid"
  [ -f "$p" ] && mv -- "$p" "$p.removed.$stamp" && ok "archived $f.pid"
done

if [ "$PURGE" -eq 1 ]; then
  warn "PURGE will DELETE $DST including evidence."
  printf 'Type PURGE to confirm: '
  read -r answer
  if [ "$answer" = "PURGE" ]; then
    rm -rf -- "$DST"
    ok "$DST removed."
  else
    warn "Not confirmed; keeping $DST."
  fi
else
  ok "Evidence kept at $DST/evidence and $DST/checkpoints."
  info "Full wipe: $0 --purge"
fi
