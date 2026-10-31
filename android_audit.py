#!/data/data/com.termux/files/usr/bin/python
import os, json, time, shutil, subprocess, hashlib
from pathlib import Path
from datetime import datetime, timezone

BASE = Path.home() / "shieldtrace"
EVID = BASE / "evidence"
EVID.mkdir(parents=True, exist_ok=True)
os.umask(0o077)

def run(args, timeout=5):
    try:
        p = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout
        )
        return {
            "ok": p.returncode == 0,
            "output": p.stdout.strip()[:5000],
            "error": p.stderr.strip()[:1000]
        }
    except Exception as e:
        return {"ok": False, "error": repr(e)}

def prop(key):
    r = run(["getprop", key])
    return r.get("output", "") if r["ok"] else None

def read(path):
    try:
        return Path(path).read_text(errors="replace")[:5000]
    except Exception as e:
        return None

def main():
    report = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "device": {
            "android_version": prop("ro.build.version.release"),
            "sdk": prop("ro.build.version.sdk"),
            "security_patch": prop("ro.build.version.security_patch"),
            "fingerprint": prop("ro.build.fingerprint"),
            "manufacturer": prop("ro.product.manufacturer"),
            "model": prop("ro.product.model")
        },
        "memory": read("/proc/meminfo"),
        "uptime": read("/proc/uptime"),
        "storage": run(["df", "-h", str(Path.home())]),
        "battery": run(["dumpsys", "battery"]),
        "network_interfaces": [],
        "accessible_processes": [],
        "permissions": {},
        "limitations": [
            "Non-root Android cannot read all protected system files.",
            "Other apps private data is not accessible.",
            "Process and network visibility is limited by Android."
        ]
    }

    # Use iproute2: direct sysfs access may be blocked by Android.
    net_result = run(["ip", "-brief", "link"])
    report["network_interfaces"] = []
    report["network_interfaces_source"] = "ip -brief link"
    if net_result.get("ok"):
        for line in net_result.get("output", "").splitlines():
            fields = line.split()
            if fields:
                report["network_interfaces"].append(fields[0])
    else:
        report["network_interfaces_error"] = net_result.get("error", "unavailable")

    # Read only visible process metadata; do not inspect process memory.
    proc_root = Path("/proc")
    try:
        for p in proc_root.iterdir():
            if p.name.isdigit() and len(report["accessible_processes"]) < 300:
                cmd = p / "cmdline"
                try:
                    args = cmd.read_bytes().split(b"\0")
                    name = next(
                        (x.decode(errors="replace") for x in args if x),
                        ""
                    )
                    if name:
                        report["accessible_processes"].append({
                            "pid": int(p.name),
                            "name": name[:160]
                        })
                except (PermissionError, OSError):
                    continue
    except Exception as e:
        report["process_scan_error"] = repr(e)

    shared = Path.home() / "storage/shared"
    report["permissions"]["shared_storage"] = {
        "available": shared.exists(),
        "readable": os.access(shared, os.R_OK),
        "path": str(shared)
    }

    enforce_path = Path("/sys/fs/selinux/enforce")
    policy_path = Path("/sys/fs/selinux/policyvers")

    def read_protected(path):
        try:
            return path.read_text().strip()
        except Exception:
            return None

    enforce_value = read_protected(enforce_path)
    if enforce_value == "1":
        selinux_status = "ENFORCING"
    elif enforce_value == "0":
        selinux_status = "PERMISSIVE"
    else:
        selinux_status = "UNKNOWN"

    report["selinux"] = {
        "filesystem_present": Path("/sys/fs/selinux").exists(),
        "process_context": run(["id", "-Z"]),
        "enforcement": selinux_status,
        "enforcement_raw": enforce_value,
        "policy_version": read_protected(policy_path),
        "note": "UNKNOWN means Termux could not read the protected status."
    }

    report["commands"] = {
        "ip_address": run(["ip", "-brief", "address"]),
        "ip_route": run(["ip", "route"])
    }

    raw = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["report_sha256"] = hashlib.sha256(raw.encode()).hexdigest()

    latest = EVID / "android_audit_latest.json"
    tmp = latest.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, latest)

    print("[OK] Android audit completed.")
    print("Device:", report["device"]["manufacturer"],
          report["device"]["model"])
    print("Android:", report["device"]["android_version"])
    print("Security patch:", report["device"]["security_patch"])
    print("Network interfaces:", len(report["network_interfaces"]))
    print("Accessible processes:", len(report["accessible_processes"]))
    print("Shared storage readable:",
          report["permissions"]["shared_storage"]["readable"])
    print("Report:", latest)
    print("SHA-256:", report["report_sha256"])

if __name__ == "__main__":
    main()
