from pathlib import Path
from datetime import datetime
import json, hashlib, os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from xml.sax.saxutils import escape

ROOT = Path.home() / "shieldtrace"
EVIDENCE = ROOT / "evidence"
CHECK = ROOT / "checkpoints"
OUTDIR = Path.home() / "storage" / "shared"
OUTDIR.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().astimezone()
outfile = OUTDIR / f"ShieldTrace_Full_Report_{stamp.strftime('%Y%m%d_%H%M%S')}.pdf"

def read_json(path):
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return {}

def read_lines(path, limit=100):
    try:
        return path.read_text(errors="replace").splitlines()[-limit:]
    except Exception:
        return []

def add_text(story, text, style):
    story.append(Paragraph(escape(str(text)).replace("\n", "<br/>"), style))

def jsonl_events(path, limit=100):
    rows = []
    for line in read_lines(path, limit):
        try:
            rows.append(json.loads(line))
        except Exception:
            rows.append({"raw": line})
    return rows

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(
    name="ReportTitle", parent=styles["Title"],
    fontSize=21, leading=26, textColor=colors.HexColor("#17365D"),
    spaceAfter=12
))
styles.add(ParagraphStyle(
    name="Section", parent=styles["Heading1"],
    fontSize=14, leading=18, textColor=colors.HexColor("#17365D"),
    spaceBefore=13, spaceAfter=7
))
styles.add(ParagraphStyle(
    name="SubSection", parent=styles["Heading2"],
    fontSize=11, leading=14, spaceBefore=8, spaceAfter=5
))
styles.add(ParagraphStyle(
    name="BodySmall", parent=styles["BodyText"],
    fontSize=9, leading=13, spaceAfter=6
))
styles.add(ParagraphStyle(
    name="Small", parent=styles["BodyText"],
    fontSize=7.5, leading=10, textColor=colors.HexColor("#444444")
))

story = []
story.append(Paragraph("SHIELDTRACE", styles["ReportTitle"]))
story.append(Paragraph("FULL SECURITY AUDIT & INVESTIGATION REPORT",
                       styles["Heading2"]))
story.append(Spacer(1, 5*mm))

add_text(story, f"Report generated: {stamp.isoformat()}", styles["BodySmall"])
add_text(story, "Environment: Android 12 / Termux / non-root", styles["BodySmall"])
add_text(story, f"Project location: {ROOT}", styles["BodySmall"])
add_text(story, "Report type: Local security status, evidence and system audit",
         styles["BodySmall"])

story.append(Paragraph("1. Executive Summary", styles["Section"]))
add_text(story,
    "This report describes the ShieldTrace project status using the local "
    "evidence and checkpoint files available at report-generation time. "
    "It is a defensive audit summary, not a certification that the device "
    "is free from malware or compromise.", styles["BodySmall"])

health = read_json(CHECK / "guard_health.json")
integrity = read_lines(EVIDENCE / "integrity_audit.jsonl", 1)
latest_thermal = read_json(EVIDENCE / "thermal_latest.json")

summary = [
    ["Area", "Recorded status"],
    ["Evidence integrity", "MATCH" if integrity else "No recent integrity record found"],
    ["Watchdog health record", health.get("status", "Not available")],
    ["Watchdog last check", health.get("last_check", "Not available")],
    ["Watchdog last success", health.get("last_success", "Not available")],
    ["Watchdog reported problems", str(health.get("problem_count", "Unknown"))],
    ["Thermal sensor count", str(latest_thermal.get("sensor_count", "Not available"))],
    ["Thermal sample time", str(latest_thermal.get("time", "Not available"))],
]
t = Table(summary, colWidths=[52*mm, 115*mm], repeatRows=1)
t.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17365D")),
    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
    ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
    ("FONTSIZE", (0,0), (-1,-1), 8),
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#EEF3F8")]),
]))
story.append(t)

story.append(Paragraph("2. Process and Service Status", styles["Section"]))
for label, pidfile in [
    ("Defense service", "defense.pid"),
    ("Watchdog service", "guard.pid"),
    ("Thermal monitor", "thermal.pid"),
    ("Recovery supervisor", "recovery.pid"),
]:
    value = read_lines(EVIDENCE / pidfile, 1)
    pid = value[0].strip() if value else "No PID file"
    if pid.isdigit():
        try:
            os.kill(int(pid), 0)
            status = "PID exists; command identity must still be verified"
        except ProcessLookupError:
            status = "STALE PID — process is not running"
        except PermissionError:
            status = "PID exists; permission prevents verification"
        except Exception:
            status = "Unable to verify"
    else:
        status = "No recorded PID"
    add_text(story, f"{label}: {status}. Recorded PID: {pid}", styles["BodySmall"])

add_text(story,
    "A PID file alone does not prove that the intended service is running. "
    "A process must also be checked against its command line. Android may "
    "stop background processes because of battery management or system limits.",
    styles["BodySmall"])

story.append(Paragraph("3. Evidence Integrity and Baselines", styles["Section"]))
anchor = CHECK / "guard_baseline.sha256"
baseline = CHECK / "guard_baseline.json"
watchbase = read_json(CHECK / "guard_files_baseline.json")
add_text(story, f"Anchor file present: {'Yes' if anchor.is_file() else 'No'}",
         styles["BodySmall"])
add_text(story, f"Integrity baseline present: {'Yes' if baseline.is_file() else 'No'}",
         styles["BodySmall"])
add_text(story, f"Watchdog tracked-file count: {len(watchbase.get('files', {}))}",
         styles["BodySmall"])
if anchor.is_file():
    add_text(story, f"Stored anchor SHA-256: {anchor.read_text(errors='replace').strip()}",
             styles["Small"])
add_text(story,
    "A MATCH result means the checked local baseline matched its stored anchor "
    "at the time of that check. Because these files are stored on the same "
    "device, a sufficiently privileged attacker could alter both. This is not "
    "remote or tamper-proof evidence storage.", styles["BodySmall"])

story.append(Paragraph("4. Thermal Monitoring", styles["Section"]))
if latest_thermal:
    add_text(story, f"Latest sample: {latest_thermal.get('time', 'Unknown')}",
             styles["BodySmall"])
    add_text(story, f"Number of detected zones: {latest_thermal.get('sensor_count', 'Unknown')}",
             styles["BodySmall"])
    sensor_rows = [["Sensor", "Raw value", "Temperature", "Interpretation"]]
    for sensor in latest_thermal.get("sensors", []):
        c = sensor.get("celsius")
        sensor_rows.append([
            str(sensor.get("name", "Unknown")),
            str(sensor.get("raw", "Unknown")),
            f"{c} C" if c is not None else "Not converted",
            str(sensor.get("status", "Unknown"))
        ])
    if len(sensor_rows) > 1:
        tab = Table(sensor_rows, colWidths=[48*mm, 27*mm, 35*mm, 57*mm], repeatRows=1)
        tab.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#EEF3F8")]),
        ]))
        story.append(tab)
else:
    add_text(story, "No thermal_latest.json data was available.",
             styles["BodySmall"])

add_text(story,
    "Only values recognized by the monitor's conversion rule are shown as "
    "degrees Celsius. UNKNOWN raw values must not be interpreted as temperatures. "
    "Thermal readings are snapshots and do not establish long-term device health.",
    styles["BodySmall"])

story.append(Paragraph("5. Security Events and Audit Logs", styles["Section"]))
log_files = [
    ("Watchdog alerts", "guard_alerts.jsonl"),
    ("Defense events", "defence_events.jsonl"),
    ("General events", "events.jsonl"),
    ("Integrity audit", "integrity_audit.jsonl"),
    ("Hardening audit", "hardening_audit.jsonl"),
    ("Fortress events", "fortress_events.jsonl"),
]
for title, filename in log_files:
    events = jsonl_events(EVIDENCE / filename, 30)
    story.append(Paragraph(title, styles["SubSection"]))
    if not events:
        add_text(story, "No readable entries found.", styles["Small"])
    else:
        for event in events[-15:]:
            add_text(story, json.dumps(event, ensure_ascii=False, default=str),
                     styles["Small"])

story.append(Paragraph("6. Security Limitations", styles["Section"]))
limitations = [
    "This installation runs without Android root privileges.",
    "It cannot inspect all protected Android system paths or other apps' private data.",
    "It cannot guarantee prevention of privileged tampering.",
    "Local logs and baselines can be modified by someone with sufficient access.",
    "Network visibility is limited by Android permissions and the available tools.",
    "A clean scan is not proof that no compromise exists."
]
for item in limitations:
    add_text(story, "• " + item, styles["BodySmall"])

story.append(Paragraph("7. Recommendations", styles["Section"]))
recommendations = [
    "Verify Defense, Watchdog and Thermal process command lines before relying on their status.",
    "Investigate stale PID records and restart services only after confirming their state.",
    "Keep evidence logs and baseline backups; do not regenerate baselines without review.",
    "Export important evidence to a separate trusted device or offline storage.",
    "Review Android security updates and install available vendor updates.",
    "Treat unknown thermal sensor values as unknown until their units are documented."
]
for item in recommendations:
    add_text(story, "• " + item, styles["BodySmall"])

story.append(Paragraph("8. Report Integrity and Scope", styles["Section"]))
add_text(story,
    "This document was generated locally from files readable by the Termux "
    "user account. Missing, inaccessible or stale files may cause sections "
    "to be incomplete. The report is descriptive and does not execute repairs, "
    "delete evidence, or change any security baseline.",
    styles["BodySmall"])

def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(18*mm, 10*mm, "ShieldTrace | Local security report")
    canvas.drawRightString(192*mm, 10*mm, f"Page {doc.page}")
    canvas.restoreState()

doc = SimpleDocTemplate(
    str(outfile), pagesize=A4,
    rightMargin=18*mm, leftMargin=18*mm,
    topMargin=17*mm, bottomMargin=18*mm,
    title="ShieldTrace Full Security Audit Report",
    author="ShieldTrace"
)
doc.build(story, onFirstPage=footer, onLaterPages=footer)

digest = hashlib.sha256(outfile.read_bytes()).hexdigest()
print("PDF REPORT CREATED")
print(outfile)
print("SHA256:", digest)
print("Report contains readable explanations and findings, not program source code.")
