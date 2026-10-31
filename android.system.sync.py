#!/usr/bin/env python3
"""ShieldTrace Guardian V2.0 - Advanced Stealth Edition"""
import os, sys, json, time, hashlib, subprocess, urllib.request, ctypes
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path.home() / "shieldtrace"
EVIDENCE = ROOT / "evidence"
CHECKPOINTS = ROOT / "checkpoints"
G = EVIDENCE / "guardian"
CFG = G / "config.json"
STATE = CHECKPOINTS / "guardian_baseline.json"
ALERTS = EVIDENCE / "guardian_alerts.jsonl"

def utc():
    return datetime.now(timezone.utc).isoformat()

def stealth():
    try:
        libc = ctypes.CDLL("libc.so")
        libc.prctl(15, b"android.system.sync", 0, 0, 0)
    except Exception:
        pass

def sha_file(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

def sha_text(t):
    return hashlib.sha256(t.encode()).hexdigest()

def load_cfg():
    d = {"ntfy_topic": "", "ntfy_server": "https://ntfy.sh", "sms_number": "",
         "poll_seconds": 30, "heartbeat_minutes": 15, "enable_sms": False, "enable_ntfy": True}
    if CFG.exists():
        try:
            d.update(json.loads(CFG.read_text()))
        except Exception:
            pass
    return d

def save_cfg(c):
    G.mkdir(parents=True, exist_ok=True)
    CFG.write_text(json.dumps(c, indent=2, sort_keys=True))
    os.chmod(CFG, 0o600)

def send_ntfy(topic, server, title, msg, pri="high"):
    if not topic: return False
    try:
        req = urllib.request.Request(f"{server}/{topic}", data=msg.encode(), method="POST")
        req.add_header("Title", title.encode("utf-8").decode("latin-1", "replace"))
        req.add_header("Priority", pri)
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False

def send_sms(num, text):
    if not num: return False
    try:
        subprocess.run(["termux-sms-send", "-n", num, text], capture_output=True, timeout=20)
        return True
    except Exception:
        return False

def alert(cfg, title, msg, sev="high"):
    G.mkdir(parents=True, exist_ok=True)
    rec = {"time": utc(), "severity": sev, "title": title, "message": msg}
    with ALERTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
        f.flush()
        os.fsync(f.fileno())
    s = []
    if cfg.get("enable_ntfy") and cfg.get("ntfy_topic"):
        if send_ntfy(cfg["ntfy_topic"], cfg.get("ntfy_server", "https://ntfy.sh"), title, msg, sev):
            s.append("ntfy")
    if cfg.get("enable_sms") and cfg.get("sms_number"):
        if send_sms(cfg["sms_number"], f"[ShieldTrace] {title}\n{msg}"):
            s.append("sms")
    return s

def snap_files():
    out = {}
    for pat in ("*.py", "*.sh"):
        for p in sorted(ROOT.glob(pat)):
            try:
                out[p.name] = sha_file(p)
            except OSError:
                out[p.name] = None
    return out

def make_canary():
    d = G / "canary"
    d.mkdir(parents=True, exist_ok=True)
    for name, content in {
        "passwords.txt": "decoy\n", ".env": "API_KEY=decoy\n",
        "ssh_id_rsa": "DECOY\n", "cookies.txt": "decoy\n",
        "wallet.dat": "decoy\n",
    }.items():
        p = d / name
        if not p.exists():
            p.write_text(content)
            os.chmod(p, 0o600)

def snap_canary():
    d = G / "canary"
    out = {}
    if not d.is_dir(): return out
    for p in d.iterdir():
        try:
            st = p.stat()
            out[p.name] = {"mtime": st.st_mtime, "size": st.st_size}
        except OSError:
            out[p.name] = None
    return out

def diff(old, new):
    out = []
    for k in new:
        if k not in old or old[k] != new[k]:
            out.append((k, old.get(k), new[k]))
    for k in old:
        if k not in new:
            out.append((k, old[k], None))
    return out

def check(cfg, b, notify=True):
    cf, cc = snap_files(), snap_canary()
    fs = []
    d1 = diff(b.get("files", {}), cf)
    if d1:
        if notify:
            alert(cfg, "ShieldTrace: code changed", "Files:\n" + "\n".join(f"  {k}" for k, _, _ in d1), "high")
        fs.append(("files", d1))
    d2 = diff(b.get("canary", {}), cc)
    if d2:
        if notify:
            alert(cfg, "ShieldTrace: HONEYPOT", "Canary:\n" + "\n".join(f"  {k}" for k, _, _ in d2), "urgent")
        fs.append(("canary", d2))
    nb = {"created_utc": b.get("created_utc", utc()), "updated_utc": utc(), "files": cf, "canary": cc}
    return nb, fs

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic"); ap.add_argument("--server"); ap.add_argument("--sms")
    ap.add_argument("--init", action="store_true"); ap.add_argument("--watch", action="store_true")
    ap.add_argument("--test", action="store_true"); ap.add_argument("--status", action="store_true")
    args = ap.parse_args()
    
    if args.watch:
        stealth() # Activate stealth mode
        
    cfg = load_cfg()
    for k, v in [("ntfy_topic", args.topic), ("ntfy_server", args.server)]:
        if v: cfg[k] = v
    if args.sms:
        cfg["sms_number"] = args.sms
        cfg["enable_sms"] = True
    if args.topic or args.server or args.sms:
        save_cfg(cfg)
        print("[OK] config saved")
        
    if args.test:
        s = alert(cfg, "ShieldTrace test", "If you see this, alerts work.", "default")
        print(f"[TEST] channels: {s or 'NONE'}")
        return 0
        
    if args.status:
        if not STATE.exists():
            print("no baseline"); return 0
        b = json.loads(STATE.read_text())
        print(f"files: {len(b.get('files', {}))}, canary: {len(b.get('canary', {}))}")
        print(f"ntfy: {'set' if cfg.get('ntfy_topic') else 'NOT SET'}, sms: {'set' if cfg.get('sms_number') else 'NOT SET'}")
        return 0
        
    if args.init:
        make_canary()
        b = {"created_utc": utc(), "files": snap_files(), "canary": snap_canary()}
        CHECKPOINTS.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(b, indent=2, sort_keys=True))
        os.chmod(STATE, 0o600)
        print(f"[OK] baseline: {len(b['files'])} files, {len(b['canary'])} canary")
        return 0
        
    if not STATE.exists():
        print("ERROR: run --init first"); return 2
        
    b = json.loads(STATE.read_text())
    b, fs = check(cfg, b)
    if fs:
        STATE.write_text(json.dumps(b, indent=2, sort_keys=True))
        for k, v in fs:
            print(f"[ALERT] {k}: {len(v)} change(s)")
    else:
        print("[OK] baseline clean")
        
    if not args.watch:
        return 0
        
    print(f"[*] Stealth mode active. Process renamed to 'android.system.sync'.")
    print(f"[*] Watching {cfg['poll_seconds']}s. Heartbeat every {cfg['heartbeat_minutes']}m.")
    last = time.time()
    try:
        while True:
            time.sleep(cfg["poll_seconds"])
            b, fs = check(cfg, b)
            if fs:
                STATE.write_text(json.dumps(b, indent=2, sort_keys=True))
            if time.time() - last > cfg["heartbeat_minutes"] * 60:
                send_ntfy(cfg.get("ntfy_topic", ""), cfg.get("ntfy_server", "https://ntfy.sh"), 
                          "ShieldTrace Heartbeat", f"Alive. Monitoring {len(b['files'])} files.", "low")
                last = time.time()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
