#!/usr/bin/env python3
import os, sys, time, json, hashlib, shutil, subprocess, socket
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / "shieldtrace"
EVIDENCE = BASE / "evidence"
LOG = EVIDENCE / "events.jsonl"
INTERVAL = 10
previous_hash = "0" * 64

BASE.mkdir(exist_ok=True)
EVIDENCE.mkdir(exist_ok=True)

def now():
    return datetime.now(timezone.utc).isoformat()

def run(args, timeout=4):
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return (p.stdout or p.stderr).strip()
    except Exception as e:
        return f"[unavailable: {type(e).__name__}: {e}]"

def snapshot():
    return {
        "time": now(),
        "interfaces": run(["ip", "-brief", "addr"]),
        "routes": run(["ip", "route"]),
        "neighbors": run(["ip", "neigh"]),
        "sockets": run(["ss", "-H", "-tun"]),
    }

def save_event(kind, details):
    global previous_hash
    record = {
        "time": now(),
        "event": kind,
        "details": details,
        "previous_record_sha256": previous_hash,
    }
    canonical = json.dumps(
        record, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    record["record_sha256"] = digest
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    previous_hash = digest
    print(f"[LOGGED] {kind} | SHA256 {digest[:16]}…")

def alert(title, message):
    print("\n" + "!" * 58)
    print("SECURITY ALERT:", title)
    print(message)
    print("!" * 58 + "\n")
    # Optional Android notification, if Termux:API is installed.
    if shutil.which("termux-notification"):
        run([
            "termux-notification",
            "--title", f"ShieldTrace: {title}",
            "--content", message[:200]
        ])

def network_help():
    print("""
নিজের নেটওয়ার্ক বিচ্ছিন্ন করার নিরাপদ উপায়:
  • Wi-Fi: Quick Settings খুলে Wi-Fi বন্ধ করো।
  • Mobile data: Quick Settings > Mobile data বন্ধ করো।
  • Airplane mode: প্রয়োজন হলে চালু করো; এতে কল/SMS-ও বন্ধ হতে পারে।
  • সন্দেহজনক Wi-Fi হলে সেটি Forget করো এবং রাউটারের পাসওয়ার্ড বদলাও।
Android/OriginOS অনুমতি না দিলে এই non-root স্ক্রিপ্ট নিজে থেকে
নেটওয়ার্ক বন্ধ করতে পারে না। বিচ্ছিন্ন করার আগে জরুরি প্রমাণ সংরক্ষণ করো।
""")

def verify_log():
    if not LOG.exists():
        print("এখনও কোনো evidence log নেই:", LOG)
        return
    prev = "0" * 64
    good = 0
    try:
        for line_no, line in enumerate(LOG.read_text(encoding="utf-8").splitlines(), 1):
            r = json.loads(line)
            digest = r.pop("record_sha256")
            if r.get("previous_record_sha256") != prev:
                raise ValueError(f"record {line_no}: chain mismatch")
            actual = hashlib.sha256(
                json.dumps(r, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if actual != digest:
                raise ValueError(f"record {line_no}: hash mismatch")
            prev = digest
            good += 1
        print(f"OK: {good} record(s) verified; hash chain intact.")
        print("Note: this detects many later edits, but is not a digital signature.")
    except Exception as e:
        print("VERIFY FAILED:", e)

def collect_evidence():
    data = snapshot()
    path = EVIDENCE / ("snapshot_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json")
    raw = json.dumps(data, indent=2, ensure_ascii=False)
    path.write_text(raw, encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (Path(str(path) + ".sha256")).write_text(
        f"{digest}  {path.name}\n", encoding="utf-8"
    )
    save_event("manual_evidence_snapshot", {
        "file": str(path), "sha256": digest, "snapshot": data
    })
    print("Evidence saved:", path)
    print("SHA256:", digest)

def monitor():
    print("ShieldTrace AutoDefend — automatic monitoring")
    print("Interval:", INTERVAL, "seconds")
    print("Evidence log:", LOG)
    print("Stop with Ctrl+C. Keep Termux open for best results.")

    save_event("monitor_started", {
        "device_model": run(["getprop", "ro.product.model"]),
        "android_version": run(["getprop", "ro.build.version.release"]),
        "termux_uid": run(["id"]),
    })

    def sockets_available(value):
        low = value.lower()
        return not any(marker in low for marker in (
            "[unavailable:",
            "permission denied",
            "cannot open netlink socket",
            "operation not permitted",
        ))

    old = snapshot()
    save_event("baseline_snapshot", old)

    old_sockets = (
        set(old["sockets"].splitlines())
        if sockets_available(old["sockets"]) else None
    )
    old_interfaces = old["interfaces"]
    old_routes = old["routes"]
    socket_state = "available" if old_sockets is not None else "unavailable"

    if old_sockets is None:
        print("[INFO] Socket visibility is limited; socket-change alerts are paused.")

    try:
        while True:
            time.sleep(INTERVAL)
            cur = snapshot()

            if cur["interfaces"] != old_interfaces:
                save_event("network_interface_change", {
                    "before": old_interfaces, "after": cur["interfaces"]
                })
                alert(
                    "Network interface changed",
                    "Interface status changed. This may be normal when connectivity changes."
                )
                network_help()

            if cur["routes"] != old_routes:
                save_event("route_change", {
                    "before": old_routes, "after": cur["routes"]
                })
                alert(
                    "Network route changed",
                    "Routing changed. Check whether you intentionally changed networks."
                )
                network_help()

            current_available = sockets_available(cur["sockets"])

            if not current_available:
                if socket_state != "unavailable":
                    save_event("socket_visibility_unavailable", {
                        "message": cur["sockets"]
                    })
                    print("[INFO] Cannot reliably read sockets; skipping socket comparison.")
                socket_state = "unavailable"
            else:
                sockets = set(cur["sockets"].splitlines())

                if old_sockets is None:
                    old_sockets = sockets
                    save_event("socket_visibility_restored", {
                        "visible_socket_lines": len(sockets),
                        "note": "New baseline established; no change alert generated."
                    })
                    print("[INFO] Socket baseline refreshed.")
                else:
                    added = sorted(sockets - old_sockets)
                    removed = sorted(old_sockets - sockets)

                    if added:
                        save_event("new_visible_sockets", {"entries": added})
                        alert(
                            "New visible network socket(s)",
                            f"{len(added)} socket line(s) appeared. New connections alone do not prove an attack."
                        )
                        for item in added[:12]:
                            print("  +", item)
                        if len(added) > 12:
                            print(f"  ... and {len(added)-12} more")
                        network_help()

                    if removed:
                        save_event("socket_disappeared", {"entries": removed})

                    old_sockets = sockets

                socket_state = "available"

            old_interfaces = cur["interfaces"]
            old_routes = cur["routes"]

    except KeyboardInterrupt:
        save_event("monitor_stopped", {"reason": "Ctrl+C"})
        print("\nMonitoring stopped. Evidence retained.")

def menu():
    while True:
        print("""
========== ShieldTrace AutoDefend ==========
1. Start automatic monitoring
2. Save a current evidence snapshot
3. Verify evidence log integrity
4. Show network-disconnect instructions
5. Exit
============================================
""")
        choice = input("Choose 1-5: ").strip()
        if choice == "1":
            monitor()
        elif choice == "2":
            collect_evidence()
        elif choice == "3":
            verify_log()
        elif choice == "4":
            network_help()
        elif choice == "5":
            print("Bye.")
            return
        else:
            print("Please enter 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    menu()
