#!/usr/bin/env python3
import os, json, time, hashlib, subprocess, shutil
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
OUT = BASE / "evidence"
LOG = OUT / "defence_events.jsonl"
INTERVAL = 60

BASE.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)
os.umask(0o077)

def run(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or p.stderr).strip() or "(empty)"
    except Exception as e:
        return "UNAVAILABLE: " + type(e).__name__

def prop(name):
    return run(["getprop", name])

def setting(namespace, key):
    return run(["settings", "get", namespace, key])

def now():
    return datetime.now(timezone.utc).isoformat()

def notify(title, message):
    print(f"\n[DEFENCE ALERT] {title}\n{message}\n")
    if shutil.which("termux-notification"):
        run(["termux-notification", "--title", title, "--content", message[:200]])

def record(kind, data):
    entry = {"time": now(), "event": kind, "data": data}
    raw = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        LOG.chmod(0o600)
    except OSError:
        pass

def check():
    return {
        "model": prop("ro.product.model"),
        "android": prop("ro.build.version.release"),
        "security_patch": prop("ro.build.version.security_patch"),
        "verified_boot": prop("ro.boot.verifiedbootstate"),
        "bootloader_locked": prop("ro.boot.flash.locked"),
        "selinux": run(["getenforce"]),
        "adb_enabled": setting("global", "adb_enabled"),
        "developer_options": setting("global", "development_settings_enabled"),
        "unknown_sources_legacy": setting("secure", "install_non_market_apps"),
        "network_interfaces": run(["ip", "-brief", "addr"]),
        "network_routes": run(["ip", "route"]),
        "visible_sockets": run(["ss", "-H", "-tun"]),
    }

def assess(s):
    warnings = []
    patch = s["security_patch"]

    if patch in ("", "UNAVAILABLE: FileNotFoundError", "(empty)", "null"):
        warnings.append("Security patch level could not be read; check Android Settings.")
    elif patch[:4].isdigit():
        try:
            if (datetime.now().date() -
                datetime.strptime(patch[:10], "%Y-%m-%d").date()).days > 180:
                warnings.append("Reported security patch is over 180 days old; check for system updates.")
        except ValueError:
            warnings.append("Security patch value needs manual verification.")

    if s["selinux"].lower().startswith("permissive"):
        warnings.append("SELinux reports permissive mode; investigate this unexpected configuration.")

    if s["adb_enabled"] == "1":
        warnings.append("ADB debugging is enabled. Turn it off when you do not need it.")

    if s["developer_options"] == "1":
        warnings.append("Developer options are enabled. Review whether you still need them.")

    if s["verified_boot"].lower() == "orange":
        warnings.append("Boot state reports orange/unlocked. Confirm your device's bootloader status.")
    elif s["verified_boot"].lower() == "red":
        warnings.append("Boot verification reports red. Investigate urgently using official support.")

    if s["bootloader_locked"] == "0":
        warnings.append("Bootloader reports unlocked. Confirm this is expected for your device.")

    if s["unknown_sources_legacy"] == "1":
        warnings.append("Legacy unknown-sources setting is enabled; review app installation permissions.")

    return warnings

def main():
    print("ShieldTrace — Always-on Defence Mode")
    print("Checks every", INTERVAL, "seconds. Stop with Ctrl+C.")
    print("Log:", LOG)
    previous = None

    try:
        while True:
            state = check()
            warnings = assess(state)

            if previous is None:
                record("defence_started", {"initial_state": state})
                print("Initial security snapshot saved.")
            elif state != previous:
                record("security_state_changed", {
                    "previous": previous, "current": state
                })
                notify("Device/network state changed",
                       "Review the saved evidence. A change does not automatically mean an attack.")

            for warning in warnings:
                key = hashlib.sha256(warning.encode()).hexdigest()
                if key not in (previous or {}).get("_reported_warning_hashes", []):
                    record("security_review_warning", {"warning": warning})
                    notify("Security review needed", warning)

            # Store warning hashes only in memory to avoid repeated alerts.
            state["_reported_warning_hashes"] = [
                hashlib.sha256(w.encode()).hexdigest() for w in warnings
            ]
            previous = state

            if not warnings:
                print(f"[{now()}] Checks complete; no configured warning detected.")
            else:
                print(f"[{now()}] {len(warnings)} item(s) need review.")

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        record("defence_stopped", {"reason": "Ctrl+C"})
        print("\nDefence mode stopped. Logs retained.")

if __name__ == "__main__":
    main()
