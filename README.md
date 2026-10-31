# ShieldTrace

> A defensive monitoring and evidence-collection toolkit for **non-rooted Android** running **Termux**.

ShieldTrace helps you **notice** when things change on your phone: code edits, suspicious environment shifts, and honeypot triggers. It keeps a hash-chained audit log so that changes cannot be silently erased without detection.

**It is a detector, not a firewall.** Read [Limitations](#limitations) before relying on it.

---

## What it does

| Feature | Description |
|---|---|
| **Tamper-evident evidence chain** | Every archived record is hash-chained. `verify_android_archive.py` re-derives the chain end-to-end. |
| **Code integrity baseline** | SHA-256 baseline for every `.py`/`.sh` in your install. Detects changes and missing files. |
| **Off-device alerting** (`guardian.py`) | Sends alerts via **SMS** (Termux:API) and **ntfy.sh push** when changes are detected - so deleting local logs doesn't hide the attack. |
| **Honeypot canary** | Decoy files (`passwords.txt`, `.env`, `wallet.dat`) inside a private directory. Any touch -> urgent alert. |
| **Environment baseline** | Watches ADB state, developer-mode flag, and installed-package hash. |
| **Interactive dashboard** | Terminal UI: start/stop defense, watchdog, thermal monitor, recovery supervisor. |
| **Storage scanner** | Detects new/changed/missing files in `~/storage/shared/Download`. |
| **Tool arsenal** | Menu wrapper for `nmap`, `dig`, `whois`, `openssl`, `curl`, `nc`, etc. |

---

## What it does NOT do

- **It does not prevent malware.** It can only detect some changes after the fact.
- **It is not root-capable.** On non-root Termux, the OS blocks most inspection anyway.
- **It is not a substitute for Play Protect, antivirus, or good OPSEC.**
- **It does not protect against an attacker with write access to `~/shieldtrace`.** They can rewrite the baseline and chain consistently; only an off-device anchor defeats that.

If you need actual prevention, use a rooted device, verified boot, and an audited endpoint-security product.

---

## Requirements

- Android 7+ with **Termux** (F-Droid)
- **Termux:API** app (F-Droid) - required for SMS alerts and toasts
- Python 3.11+
- `termux-api` package (`pkg install termux-api`)
- Optional: `ntfy` app (F-Droid / Play) for push notifications

---

## Quick start

```bash
git clone https://github.com/YOURNAME/shieldtrace.git
cd shieldtrace
./install.sh
~/shieldtrace/auto_audit.py
~/shieldtrace/shieldtrace_dashboard.py
```

---

## Off-device alerting (guardian)

`guardian.py` watches for code changes, canary touches, ADB / developer-mode state change, and installed-package hash changes. Alerts are sent by **SMS** and **ntfy.sh push**, so erasing local logs does not hide the event.

### Setup

```bash
cd ~/shieldtrace
./guardian.py --topic "sh-$(head -c8 /dev/urandom | xxd -p)" --sms "+8801XXXXXXXXX"
./guardian.py --init
./guardian.py --test
nohup ./guardian.py --watch > evidence/guardian.log 2>&1 &
echo $! > evidence/guardian.pid
```

> **Never share your ntfy topic.** Anyone who knows it can subscribe to (and/or spoof) your alerts.

---

## Verifying the evidence chain

```bash
cd ~/shieldtrace
./verify_android_archive.py
./show_anchor.sh
```

Copy the final hash **off-device** (SMS yourself, paper, email). That hash is the only thing that makes evidence-chain truncation detectable.

---

## Limitations

- Non-root Termux cannot inspect other apps' `/proc` - duplicate-process detection is unreliable across users.
- Local checkpoints are **not** attacker-proof. Only an off-device anchor is.
- `cmdline` verification proves "a process with this argv exists" - not "the code it runs is unmodified."
- ADB / root access defeats every mitigation in this toolkit.

These are not bugs. They are the boundary of what non-root Android allows.

---

## Uninstall

```bash
cd ~/shieldtrace
./UNINSTALL.sh         # stops processes, keeps evidence
./UNINSTALL.sh --purge # also removes ~/shieldtrace entirely
```

---

## License

MIT - see [LICENSE](LICENSE).

---

## Disclaimer

This software is provided for **defensive monitoring on devices you own or are explicitly authorized to test.** The authors are not responsible for misuse, data loss, or false sense of security. It is not a commercial endpoint-security product.
