import json
import time
import os
import fcntl
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path.home() / "shieldtrace"
OUT = ROOT / "evidence" / "thermal_latest.json"
THERMAL = Path("/sys/class/thermal")

def read(path):
    try:
        return path.read_text().strip()
    except (OSError, PermissionError):
        return None

def scan():
    sensors = []

    for zone in sorted(THERMAL.glob("thermal_zone*")):
        name = read(zone / "type")
        raw = read(zone / "temp")

        if raw is None:
            continue

        try:
            value = int(raw)
        except ValueError:
            continue

        celsius = None
        status = "UNKNOWN"

        # Common Android thermal millidegree format.
        if 10000 <= value <= 120000:
            celsius = round(value / 1000, 1)
            status = "READABLE"

        sensors.append({
            "zone": zone.name,
            "name": name or "unknown",
            "raw": value,
            "celsius": celsius,
            "status": status
        })

    return sensors

def main():
    ROOT.mkdir(exist_ok=True)
    OUT.parent.mkdir(exist_ok=True)
    history = OUT.parent / "thermal_history.jsonl"

    lock_path = OUT.parent / "thermal.lock"
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Thermal Monitor already running; exiting.")
        os.close(lock_fd)
        return

    print("ShieldTrace Thermal Monitor: 5-second interval")
    print("Press CTRL+C to stop.")

    try:
        while True:
            sensors = scan()
            report = {
                "time": datetime.now(timezone.utc).isoformat(),
                "sensor_count": len(sensors),
                "sensors": sensors
            }

            temp = OUT.with_suffix(".tmp")
            temp.write_text(json.dumps(report, indent=2))
            temp.replace(OUT)

            with history.open("a") as f:
                f.write(json.dumps(report) + "\n")

            readable = [
                x for x in sensors
                if x["celsius"] is not None
            ]
            battery = next(
                (x["celsius"] for x in sensors
                 if x["name"] == "battery"
                 and x["celsius"] is not None),
                None
            )

            print(
                report["time"],
                "| sensors:", len(sensors),
                "| battery:", str(battery) + " C"
                if battery is not None else "UNKNOWN",
                flush=True
            )
            time.sleep(5)

    except KeyboardInterrupt:
        print("\nThermal Monitor stopped by user.")
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass

if __name__ == "__main__":
    main()
