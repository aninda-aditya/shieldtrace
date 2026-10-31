#!/data/data/com.termux/files/usr/bin/bash
set -u
umask 077

BASE="$HOME/shieldtrace"
PIDFILE="$BASE/evidence/defense.pid"
LOGFILE="$BASE/evidence/background.log"

cd "$BASE" || exit 1
mkdir -p "$BASE/evidence"
chmod 700 "$BASE/evidence"

is_shieldtrace_running() {
    local pid="$1"
    local cmd

    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [[ -r "/proc/$pid/cmdline" ]] || return 1

    cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" || return 1
    [[ "$cmd" == *"import fortress; fortress.safe_auto_defense()"* ]]
}

if [ -f "$PIDFILE" ]; then
    oldpid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if is_shieldtrace_running "$oldpid"; then
        echo "ShieldTrace auto-defense already running (PID $oldpid)."
        exit 0
    fi
    stale="${PIDFILE}.stale.$(date -u +%Y%m%dT%H%M%SZ).$$"
    mv -- "$PIDFILE" "$stale" || {
        echo "ERROR: Could not archive stale PID file."
        exit 1
    }
    echo "Archived stale PID file: $stale"
fi

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: Python not found."
    exit 1
fi

if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock >/dev/null 2>&1 || true
fi

nohup python -u -c \
'import fortress; fortress.safe_auto_defense()' \
>> "$LOGFILE" 2>&1 </dev/null &

pid=$!
printf '%s\n' "$pid" > "$PIDFILE"
chmod 600 "$PIDFILE"

sleep 2

if is_shieldtrace_running "$pid"; then
    echo "ShieldTrace auto-defense started and process verified."
    echo "PID: $pid"
    echo "Log: $LOGFILE"
else
    if [ "$(cat "$PIDFILE" 2>/dev/null)" = "$pid" ]; then
        rm -f "$PIDFILE"
    fi
    echo "ERROR: ShieldTrace did not pass process verification."
    tail -n 25 "$LOGFILE"
    exit 1
fi
