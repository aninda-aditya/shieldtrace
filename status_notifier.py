#!/usr/bin/env python3
import subprocess
import time
import os
from pathlib import Path

ROOT = Path.home() / "shieldtrace"
EVIDENCE = ROOT / "evidence"
ALERTS = EVIDENCE / "guardian_alerts.jsonl"

def get_alert_count():
    if ALERTS.exists():
        return len(ALERTS.read_text().splitlines())
    return 0

def update_dashboard():
    pid_file = EVIDENCE / "guardian.pid"
    guardian_status = "Stopped"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            guardian_status = "Active"
        except (OSError, ValueError):
            pass

    alerts = get_alert_count()
    title = "ShieldTrace Dashboard"
    content = f"Guardian: {guardian_status} | Alerts: {alerts} | Shield is UP"
    
    cmd = [
        "termux-notification",
        "--id", "shieldtrace_dash",
        "--title", title,
        "--content", content,
        "--priority", "low",
        "--ongoing",
        "--icon", "security"
    ]
    
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

if __name__ == "__main__":
    print("[*] Dashboard started. Check your notification bar.")
    try:
        while True:
            update_dashboard()
            time.sleep(60) # Updates every 1 minute
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
