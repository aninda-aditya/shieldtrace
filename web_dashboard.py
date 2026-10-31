#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
from pathlib import Path

PORT = 8080
ROOT = Path.home() / "shieldtrace"
EVIDENCE = ROOT / "evidence"
ALERTS = EVIDENCE / "guardian_alerts.jsonl"
PIDFILE = EVIDENCE / "guardian.pid"

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            # Check Guardian Status
            status = "Stopped (🔴)"
            if PIDFILE.exists():
                try:
                    pid = int(PIDFILE.read_text().strip())
                    os.kill(pid, 0)
                    status = "Active (🟢)"
                except:
                    pass
            
            # Count Alerts
            alerts_count = 0
            latest_alerts = []
            if ALERTS.exists():
                lines = ALERTS.read_text().splitlines()
                alerts_count = len(lines)
                latest_alerts = lines[-5:] # Show last 5

            html = f"""
            <html>
            <head>
                <title>ShieldTrace Live Dashboard</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta http-equiv="refresh" content="5">
                <style>
                    body {{ font-family: sans-serif; background: #121212; color: #00ffcc; padding: 20px; text-align: center; }}
                    h1 {{ color: #ffffff; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }}
                    .card {{ background: #1e1e1e; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 8px rgba(0,255,204,0.2); }}
                    .alert {{ background: #330000; color: #ff5555; padding: 10px; margin: 5px 0; border-radius: 5px; font-size: 12px; text-align: left; overflow-x: auto; white-space: pre-wrap; font-family: monospace; }}
                    .status {{ font-size: 24px; font-weight: bold; color: #ffffff; }}
                </style>
            </head>
            <body>
                <h1>🛡️ ShieldTrace Live</h1>
                <div class="card">
                    <div class="status">Guardian: {status}</div>
                    <p>Total Alerts: <b>{alerts_count}</b></p>
                </div>
                <div class="card" style="text-align: left;">
                    <h3 style="color:#fff; margin-top:0;">Recent Alerts (Latest 5)</h3>
            """
            for a in latest_alerts:
                html += f'<div class="alert">{a}</div>'
                
            html += """
                </div>
                <p style="color:#666; font-size:12px;">Auto-refreshes every 5 seconds</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            self.send_error(404)

print(f"[*] Web Dashboard running at: http://localhost:{PORT}")
print("[*] Open Chrome on your phone and go to http://localhost:8080")
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
