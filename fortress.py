#!/usr/bin/env python3
import os, json, time, hashlib, subprocess, shutil, socket, fcntl
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
OUT = BASE / "evidence"
LOG = OUT / "fortress_events.jsonl"
INTERVAL = 60
BASE.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)
os.umask(0o077)

def now():
    return datetime.now(timezone.utc).isoformat()

def run(args, timeout=6):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or p.stderr).strip() or "(empty)"
    except Exception as e:
        return f"UNAVAILABLE: {type(e).__name__}: {e}"

def prop(name):
    return run(["getprop", name])

def snapshot():
    return {
        "time": now(),
        "model": prop("ro.product.model"),
        "android": prop("ro.build.version.release"),
        "patch": prop("ro.build.version.security_patch"),
        "verified_boot": prop("ro.boot.verifiedbootstate"),
        "bootloader_locked": prop("ro.boot.flash.locked"),
        "interfaces": run(["ip", "-brief", "addr"]),
        "routes": run(["ip", "route"]),
        "neighbors": run(["ip", "neigh"]),
        "sockets": run(["ss", "-H", "-tun"]),
    }

def record(kind, details):
    previous = "0" * 64
    if LOG.exists():
        try:
            last = json.loads(LOG.read_text(encoding="utf-8").splitlines()[-1])
            previous = last.get("hash", previous)
        except Exception:
            pass
    entry = {
        "time": now(),
        "event": kind,
        "details": details,
        "previous_hash": previous
    }
    raw = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        LOG.chmod(0o600)
    except OSError:
        pass
    print("[LOG]", kind)

def alert(title, message):
    print("\n" + "!" * 52)
    print("FORTRESS ALERT:", title)
    print(message)
    print("!" * 52 + "\n")
    if shutil.which("termux-notification"):
        run(["termux-notification", "--title", title, "--content", message[:200]])

def hardening_check():
    s = snapshot()
    findings = []
    patch = s["patch"]
    if len(patch) >= 10 and patch[:4].isdigit():
        try:
            age = (datetime.now().date() -
                   datetime.strptime(patch[:10], "%Y-%m-%d").date()).days
            if age > 180:
                findings.append(f"Security patch is {age} days old: check official system updates.")
        except ValueError:
            findings.append("Security patch date needs manual verification.")
    else:
        findings.append("Could not read security patch date reliably.")

    if s["verified_boot"].lower() == "orange":
        findings.append("Boot state reports orange; check whether bootloader is unlocked.")
    elif s["verified_boot"].lower() == "red":
        findings.append("Boot verification reports red; seek official device support.")

    if s["bootloader_locked"] == "0":
        findings.append("Bootloader reports unlocked; verify this is expected.")

    adb = run(["settings", "get", "global", "adb_enabled"])
    if adb.strip() == "1":
        findings.append("ADB debugging appears enabled; disable it when not needed.")
    elif adb.strip() not in ("0", "(empty)"):
        findings.append("ADB status could not be read; check Developer options manually.")

    print("\n=== DEVICE SECURITY CHECK ===")
    print("Model:", s["model"])
    print("Android:", s["android"])
    print("Security patch:", s["patch"])
    print("Verified boot:", s["verified_boot"])
    print("Bootloader locked:", s["bootloader_locked"])
    print("ADB status:", adb)
    if findings:
        for f in findings:
            print("[REVIEW]", f)
        record("hardening_review", {"findings": findings, "snapshot": s})
    else:
        print("No configured warning detected. This does not prove the phone is secure.")
        record("hardening_check", {"result": "no configured warning", "snapshot": s})
    return s

def save_snapshot():
    s = snapshot()
    name = "snapshot_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    path = OUT / name
    path.write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    Path(str(path) + ".sha256").write_text(f"{digest}  {name}\n")
    record("evidence_snapshot", {"file": name, "sha256": digest, "snapshot": s})
    print("Evidence:", path)
    print("SHA256:", digest)

def verify_log():
    if not LOG.exists():
        print("No event log yet.")
        return
    previous = "0" * 64
    count = 0
    try:
        for n, line in enumerate(LOG.read_text(encoding="utf-8").splitlines(), 1):
            item = json.loads(line)
            digest = item.pop("hash")
            if item.get("previous_hash") != previous:
                raise ValueError(f"Chain mismatch at line {n}")
            raw = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if hashlib.sha256(raw.encode()).hexdigest() != digest:
                raise ValueError(f"Hash mismatch at line {n}")
            previous = digest
            count += 1
        print(f"OK: verified {count} event(s).")
        print("This detects many edits, but is not a digital signature.")
    except Exception as e:
        print("VERIFY FAILED:", e)

def emergency():
    print("""
=== SAFE EMERGENCY RESPONSE ===
1. Save evidence first if safe to do so.
2. Suspicious Wi-Fi: turn Wi-Fi off in Quick Settings.
3. Suspected network incident: turn off mobile data too if needed.
4. Airplane mode also interrupts calls/SMS; use only if appropriate.
5. Review unfamiliar apps and their Accessibility, VPN, Device admin,
   SMS, microphone and location permissions in Android Settings.
6. Install updates only through official Android/Vivo update settings.
7. Change important account passwords from a trusted device and enable 2FA.
8. If compromise seems serious, contact official support.
This script cannot automatically isolate all traffic or remove malware.
""")
    record("emergency_guidance_shown", {})

def sockets_available(value):
    low = str(value).lower()
    return not any(marker in low for marker in (
        "unavailable:",
        "permission denied",
        "cannot open netlink socket",
        "operation not permitted",
    ))


def monitor():
    print(f"Monitoring every {INTERVAL}s. Keep Termux open; Ctrl+C stops.")
    old = snapshot()
    old_sockets = (
        set(old["sockets"].splitlines())
        if sockets_available(old["sockets"]) else None
    )
    record("monitor_started", old)

    if old_sockets is None:
        print("[INFO] Socket visibility limited; socket comparison paused.")

    try:
        while True:
            time.sleep(INTERVAL)
            cur = snapshot()
            changes = {}

            for key in ("interfaces", "routes"):
                if cur[key] != old[key]:
                    changes[key] = {"before": old[key], "after": cur[key]}

            if not sockets_available(cur["sockets"]):
                if old_sockets is not None:
                    record("socket_visibility_unavailable", {
                        "message": cur["sockets"]
                    })
                    print("[INFO] Socket access unavailable; skipping comparison.")
                old_sockets = None
            else:
                sockets = set(cur["sockets"].splitlines())
                if old_sockets is None:
                    old_sockets = sockets
                    record("socket_visibility_restored", {
                        "visible_socket_lines": len(sockets),
                        "note": "Fresh baseline; no socket-change alert."
                    })
                    print("[INFO] Socket baseline refreshed.")
                else:
                    added = sorted(sockets - old_sockets)
                    removed = sorted(old_sockets - sockets)
                    if added:
                        changes["new_visible_sockets"] = added
                    if removed:
                        record("visible_sockets_removed", {"entries": removed})
                    old_sockets = sockets

            if changes:
                record("network_state_change", changes)
                alert(
                    "Network state changed",
                    "Review the saved log. A change alone does not prove an attack."
                )
                for x in changes.get("new_visible_sockets", [])[:10]:
                    print(" +", x)

            old = cur
    except KeyboardInterrupt:
        record("monitor_stopped", {"reason": "Ctrl+C"})
        print("\\nMonitoring stopped.")


def safe_auto_defense():
    lock_path = OUT / "defense.lock"
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        print("[INFO] Auto-defense already running; exiting.")
        return
    print("\\n=== SAFE AUTO-DEFENSE ===")
    print("Checks visible network changes every", INTERVAL, "seconds.")
    print("This does not prove an attack or remove malware.")
    try:
        hardening_check()
        old = snapshot()
        old_sockets = (
            set(old["sockets"].splitlines())
            if sockets_available(old["sockets"]) else None
        )
        record("safe_auto_defense_started", {
            "interval_seconds": INTERVAL,
            "baseline_time": old["time"],
            "socket_visibility": "available" if old_sockets is not None else "limited"
        })
        if old_sockets is None:
            print("[INFO] Socket visibility limited; socket comparison paused.")
        print("Monitoring active. Press Ctrl+C to stop.")

        while True:
            time.sleep(INTERVAL)
            cur = snapshot()
            changes = {}

            for key in ("interfaces", "routes", "neighbors"):
                if cur.get(key) != old.get(key):
                    changes[key] = {
                        "before": old.get(key), "after": cur.get(key)
                    }

            if not sockets_available(cur["sockets"]):
                if old_sockets is not None:
                    record("socket_visibility_unavailable", {
                        "message": cur["sockets"]
                    })
                    print("[INFO] Socket access unavailable; skipping comparison.")
                old_sockets = None
            else:
                sockets = set(cur["sockets"].splitlines())
                if old_sockets is None:
                    old_sockets = sockets
                    record("socket_visibility_restored", {
                        "visible_socket_lines": len(sockets),
                        "note": "Fresh baseline; no socket-change alert."
                    })
                    print("[INFO] Socket baseline refreshed.")
                else:
                    added = sorted(sockets - old_sockets)
                    removed = sorted(old_sockets - sockets)
                    if added:
                        changes["new_visible_sockets"] = added
                    if removed:
                        changes["visible_sockets_removed"] = removed
                    old_sockets = sockets

            if changes:
                record("safe_auto_defense_network_change", changes)
                alert(
                    "Network state changed",
                    "Review the evidence log. A change alone does not prove malware."
                )
            else:
                print("[OK]", now(), "- no change detected in monitored state")
            old = cur

    except KeyboardInterrupt:
        record("safe_auto_defense_stopped", {"reason": "Ctrl+C"})
        print("\\nSafe Auto-Defense stopped.")

def deep_audit():
    print("\n=== SHIELDTRACE DEEP AUDIT ===")
    print("Read-only checks; results depend on Android permissions.")

    checks = {
        "android_version": ["getprop", "ro.build.version.release"],
        "security_patch": ["getprop", "ro.build.version.security_patch"],
        "verified_boot": ["getprop", "ro.boot.verifiedbootstate"],
        "bootloader_locked": ["getprop", "ro.boot.flash.locked"],
        "third_party_packages": ["pm", "list", "packages", "-3"],
        "running_processes": ["ps", "-A"],
        "accessibility_services": [
            "settings", "get", "secure",
            "enabled_accessibility_services"
        ],
        "accessibility_enabled": [
            "settings", "get", "secure", "accessibility_enabled"
        ],
        "always_on_vpn": [
            "settings", "get", "secure", "always_on_vpn_app"
        ],
        "adb_enabled": ["settings", "get", "global", "adb_enabled"],
        "network_interfaces": ["ip", "-brief", "addr"],
        "network_routes": ["ip", "route"],
        "visible_sockets": ["ss", "-H", "-tun"],
    }

    report = {"time": now(), "checks": {}}
    for name, command in checks.items():
        result = run(command, timeout=8)
        result = result[:6000]
        report["checks"][name] = result
        print("\n---", name, "---")
        print(result)

    record("deep_audit", report)
    print("\nAudit saved to the evidence log.")
    print("Review unfamiliar apps and enabled services manually.")
    print("A result or connection alone does not prove an attack.")

def menu():
    while True:
        print("""
========== SHIELDTRACE FORTRESS ==========
1. Device security / weakness check
2. Start automatic network monitoring
3. Save evidence snapshot
4. Verify evidence log
5. Emergency defence instructions
6. Exit
7. Start Safe Auto-Defense
8. Run Deep Audit
==========================================
""", flush=True)
        try:
            choice = input("Choose 1-6: ").strip()
            if choice == "1":
                hardening_check()
            elif choice == "2":
                monitor()
            elif choice == "3":
                save_snapshot()
            elif choice == "4":
                verify_log()
            elif choice == "5":
                emergency()
            elif choice == "6":
                print("Fortress closed.")
                break
            elif choice == "7":
                safe_auto_defense()
            elif choice == "8":
                deep_audit()
            else:
                print("Enter a number from 1 to 6.")
        except KeyboardInterrupt:
            print("\\nInterrupted.")
            continue
        except Exception as e:
            import traceback
            traceback.print_exc()
        if choice != "6":
            try:
                input("\\nResult shown above. Press Enter to return to menu...")
            except (KeyboardInterrupt, EOFError):
                print()

if __name__ == "__main__":
    menu()
