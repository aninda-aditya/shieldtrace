#!/usr/bin/env python3
import os, re, json, hashlib, shutil, subprocess
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence" / "tool_arsenal"
EVENTS = ROOT / "evidence" / "tool_arsenal_events.jsonl"
EVIDENCE.mkdir(parents=True, exist_ok=True)

TOOLS = [
    ("nmap", "Nmap"),
    ("python", "Python"),
    ("ssh", "SSH"),
    ("clang", "Clang"),
    ("git", "Git"),
    ("curl", "Curl"),
    ("wget", "Wget"),
    ("whois", "Whois"),
    ("dig", "Dig"),
    ("traceroute", "Traceroute"),
    ("nc", "Netcat"),
    ("openssl", "OpenSSL"),
    ("ffmpeg", "FFmpeg"),
]

def now():
    return datetime.now(timezone.utc).isoformat()

def log_event(event, details):
    record = {"time_utc": now(), "event": event, "details": details}
    with EVENTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def valid_host(value):
    return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value)) and \
        ".." not in value and not value.startswith("-")

def ask_host():
    host = input("Target hostname/IP (নিজের/অনুমোদিত): ").strip()
    if not valid_host(host):
        print("[!] Invalid hostname/IP")
        return None
    return host

def execute(name, args, timeout=30):
    if not shutil.which(name):
        print("[!] Tool not installed:", name)
        return

    print("\n[RUNNING]", name, " ".join(args[1:]))
    log_event("tool_started", {"tool": name, "args": args[1:]})

    try:
        p = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout
        )
        result = {
            "time_utc": now(),
            "tool": name,
            "command": args,
            "exit_code": p.returncode,
            "stdout": (p.stdout or "")[-20000:],
            "stderr": (p.stderr or "")[-10000:]
        }
    except subprocess.TimeoutExpired:
        result = {
            "time_utc": now(), "tool": name,
            "command": args, "exit_code": 124,
            "stdout": "", "stderr": "Execution timed out"
        }
    except OSError as exc:
        result = {
            "time_utc": now(), "tool": name,
            "command": args, "exit_code": 126,
            "stdout": "", "stderr": str(exc)
        }

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = EVIDENCE / f"{stamp}_{name}.json"
    raw = json.dumps(result, indent=2, ensure_ascii=False)
    path.write_text(raw, encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    Path(str(path) + ".sha256").write_text(
        f"{digest}  {path.name}\n", encoding="ascii"
    )

    log_event("tool_completed", {
        "tool": name, "exit_code": result["exit_code"],
        "evidence": path.name, "sha256": digest
    })

    print("\n===== RESULT =====")
    print("Exit code:", result["exit_code"])
    print(result["stdout"] or result["stderr"] or "(No output)")
    print("\n[ EVIDENCE ]", path)
    print("[ SHA256  ]", digest)

def run_tool(choice):
    if choice == "1":
        host = ask_host()
        if host:
            execute("nmap", [
                "nmap", "-sT", "-F", "-T2",
                "--max-retries", "1",
                "--host-timeout", "45s", host
            ], 55)

    elif choice == "2":
        execute("python", ["python", "--version"])

    elif choice == "3":
        print("SSH usage: ssh username@your-authorized-host")
        target = input("SSH destination (blank to cancel): ").strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+", target):
            log_event("ssh_session_requested", {"destination": target})
            subprocess.run([
                "ssh", "-o", "ConnectTimeout=8", target
            ])
            log_event("ssh_session_ended", {"destination": target})
        else:
            print("Cancelled / invalid destination.")

    elif choice == "4":
        execute("clang", ["clang", "--version"])

    elif choice == "5":
        execute("git", ["git", "--version"])

    elif choice == "6":
        url = input("HTTPS/HTTP URL: ").strip()
        parsed = urlparse(url)
        if parsed.scheme in ("https", "http") and parsed.hostname:
            execute("curl", ["curl", "-I", "--max-time", "20", url], 25)
        else:
            print("Invalid URL.")

    elif choice == "7":
        url = input("HTTPS/HTTP URL: ").strip()
        parsed = urlparse(url)
        if parsed.scheme in ("https", "http") and parsed.hostname:
            execute("wget", ["wget", "--spider", "--timeout=20", url], 25)
        else:
            print("Invalid URL.")

    elif choice == "8":
        host = ask_host()
        if host:
            execute("whois", ["whois", host], 25)

    elif choice == "9":
        host = ask_host()
        if host:
            execute("dig", ["dig", "+time=3", "+tries=1", host], 8)

    elif choice == "10":
        host = ask_host()
        if host:
            execute("traceroute", [
                "traceroute", "-m", "12", "-w", "2", host
            ], 30)

    elif choice == "11":
        host = ask_host()
        if host:
            port = input("TCP port (1-65535): ").strip()
            if port.isdigit() and 1 <= int(port) <= 65535:
                execute("nc", [
                    "nc", "-vz", "-w", "5", host, port
                ], 8)
            else:
                print("Invalid port.")

    elif choice == "12":
        host = ask_host()
        if host:
            execute("openssl", [
                "openssl", "s_client", "-connect", host + ":443",
                "-servername", host, "-brief"
            ], 15)

    elif choice == "13":
        execute("ffmpeg", ["ffmpeg", "-version"])

def menu():
    while True:
        print("""
========== SHIELDTRACE // TOOL ARSENAL ==========
 1. Nmap          8. Whois
 2. Python        9. Dig
 3. SSH          10. Traceroute
 4. Clang        11. Netcat
 5. Git          12. OpenSSL
 6. Curl         13. FFmpeg
 7. Wget

 S. Show tool status
 Q. Return to Dashboard
=================================================
Use network tools only on systems you own or have
explicit permission to test.
""")
        choice = input("Arsenal > ").strip().lower()
        if choice == "q":
            return
        elif choice == "s":
            for command, label in TOOLS:
                print(
                    "[+] " + label if shutil.which(command)
                    else "[-] " + label + " MISSING"
                )
        elif choice in [str(i) for i in range(1, 14)]:
            run_tool(choice)
        else:
            print("Invalid selection.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    menu()
