from pathlib import Path
from datetime import datetime
import shutil
import py_compile

p = Path("shieldtrace_dashboard.py")
s = p.read_text()

if "THERMAL_PID" in s or "def start_thermal(" in s:
    raise SystemExit("ABORT: Thermal patch already exists. Inspect the file first.")

def rep(old, new, count=1):
    global s
    found = s.count(old)
    if found != count:
        raise SystemExit(f"ABORT: expected {count} matches, found {found}: {old[:60]!r}")
    s = s.replace(old, new)

rep(
    'DEFENSE_SCRIPT = ROOT / "start_defense.sh"\n',
    'DEFENSE_SCRIPT = ROOT / "start_defense.sh"\n'
    'THERMAL_PID = EVIDENCE / "thermal.pid"\n'
    'THERMAL_LOG = EVIDENCE / "thermal_monitor.log"\n'
    'THERMAL_SCRIPT = ROOT / "thermal_monitor.py"\n'
)

rep(
    '    if kind == "defense":\n'
    '        matches = "fortress" in cmd and "safe_auto_defense" in cmd\n'
    '    else:\n'
    '        matches = "hardening_guard.py" in cmd and "--watch" in cmd\n',
    '    if kind == "defense":\n'
    '        matches = "fortress" in cmd and "safe_auto_defense" in cmd\n'
    '    elif kind == "guard":\n'
    '        matches = "hardening_guard.py" in cmd and "--watch" in cmd\n'
    '    elif kind == "thermal":\n'
    '        matches = "thermal_monitor.py" in cmd\n'
    '    else:\n'
    '        matches = False\n'
)

rep(
    '    d_status, d_pid = process_info(DEFENSE_PID, "defense")\n'
    '    g_status, g_pid = process_info(GUARD_PID, "guard")\n'
    '    count = baseline_count()\n\n'
    '    d_status, d_pid = process_info(DEFENSE_PID, "defense")\n'
    '    g_status, g_pid = process_info(GUARD_PID, "guard")\n'
    '    count = baseline_count()\n',
    '    d_status, d_pid = process_info(DEFENSE_PID, "defense")\n'
    '    g_status, g_pid = process_info(GUARD_PID, "guard")\n'
    '    h_status, h_pid = process_info(THERMAL_PID, "thermal")\n'
    '    count = baseline_count()\n'
)

rep(
    '    line(" [W] Watchdog [V] Stop [A] Arsenal")\n',
    '    line(" [W] Watchdog [V] Stop [A] Arsenal")\n'
    '    line(" [H] Thermal Monitor (toggle)")\n'
)

rep(
    '    line(f" Watchdog: {color_status(g_status)} PID={g_pid or \'-\'}")\n',
    '    line(f" Watchdog: {color_status(g_status)} PID={g_pid or \'-\'}")\n'
    '    line(f" Thermal : {color_status(h_status)} PID={h_pid or \'-\'}")\n'
)

functions = '''def start_thermal():
    global NOTICE
    if not THERMAL_SCRIPT.is_file():
        NOTICE = "Thermal monitor script not found."
        return
    status, _ = process_info(THERMAL_PID, "thermal")
    if status == "RUNNING / VERIFIED":
        NOTICE = "Thermal Monitor is already running."
        return
    try:
        with THERMAL_LOG.open("a") as log:
            proc = subprocess.Popen(
                [sys.executable, str(THERMAL_SCRIPT)],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        THERMAL_PID.write_text(str(proc.pid) + "\\\\n")
        time.sleep(0.3)
        status, pid = process_info(THERMAL_PID, "thermal")
        NOTICE = f"Thermal launch PID={proc.pid}; status={status}."
    except Exception as exc:
        NOTICE = f"Thermal launch failed: {exc}"


def toggle_thermal():
    status, _ = process_info(THERMAL_PID, "thermal")
    if status == "RUNNING / VERIFIED":
        stop_verified(THERMAL_PID, "thermal")
    else:
        start_thermal()


'''

rep('def stop_verified(path, kind):\n', functions + 'def stop_verified(path, kind):\n')

rep(
    '            elif key == "v":\n'
    '                stop_verified(GUARD_PID, "guard")\n',
    '            elif key == "v":\n'
    '                stop_verified(GUARD_PID, "guard")\n'
    '            elif key == "h":\n'
    '                toggle_thermal()\n'
)

tmp = Path("shieldtrace_dashboard.py.thermal_check")
tmp.write_text(s)
py_compile.compile(str(tmp), doraise=True)

backup = p.with_name("shieldtrace_dashboard.py.pre_thermal_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak")
shutil.copy2(p, backup)
p.write_text(s)
py_compile.compile(str(p), doraise=True)

tmp.unlink(missing_ok=True)
print("PATCH SUCCESS")
print("Backup:", backup)
print("Dashboard syntax: OK")
