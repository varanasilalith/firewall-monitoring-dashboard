# Sentinel — Cybersecurity Firewall Monitoring Dashboard

A local learning project with a dark SOC-style interface, FastAPI backend, SQLite storage, sample firewall logs, basic rule-based alerts, search/filter, charts, and CSV export.

## Requirements
- Windows 10/11
- Python 3.10+ (Python 3.11 or 3.12 recommended)
- VS Code

## Install and run (PowerShell)
Open this folder in VS Code, then open Terminal → New Terminal:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload
```

If PowerShell blocks activation, run this for the current terminal only:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```
Or skip activation and use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

Open http://127.0.0.1:8000 in your browser. API docs: http://127.0.0.1:8000/docs

## Included endpoints
- `GET /api/health` — service status
- `GET /api/stats` — summary and chart data
- `GET /api/events` — events; optional `action`, `protocol`, `search`, `limit`
- `GET /api/alerts` — rule-based alerts
- `POST /api/events` — add a validated event (use only trusted local test data)
- `GET /api/export.csv` — export all events
- `POST /api/demo/reset` — restore sample events

## Quick tests (PowerShell)
With the server running, open a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
Invoke-RestMethod http://127.0.0.1:8000/api/stats
Invoke-RestMethod "http://127.0.0.1:8000/api/events?action=BLOCK"
Invoke-RestMethod http://127.0.0.1:8000/api/alerts
```

Test adding a blocked event:
```powershell
$event = @{
  src_ip = "192.0.2.55"
  dst_ip = "192.168.1.10"
  src_port = 40123
  dst_port = 22
  protocol = "TCP"
  action = "BLOCK"
  bytes = 0
  interface = "WAN"
  note = "Manual test event"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/events -ContentType "application/json" -Body $event
```

Export test:
```powershell
Invoke-WebRequest http://127.0.0.1:8000/api/export.csv -OutFile .\firewall-events.csv
```

Restore demo data:
```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/demo/reset
```

## How the demo works
- On first launch, the app seeds example records into `firewall.db`.
- Every 15 seconds the browser refreshes summary, alerts, and events.
- Rule-based examples flag three or more blocked connections from one source in the last 24 hours and blocked access to selected administrative ports.
- The IP ranges in sample data are documentation/example ranges. They are not evidence of real attackers.
- Alerts are triage signals only. A blocked connection does not prove a compromise.

## Limitations and safe use
This project starts with synthetic sample data and does **not** monitor your real Windows Firewall or a production firewall by itself. Live monitoring requires a properly configured log source/collector and appropriate access controls. The API has no authentication and is intended for localhost learning only; do not expose it to the public internet. For a real deployment add authentication, authorization, TLS, rate limiting, input/source validation, retention controls, and audited ingestion.

## Troubleshooting
- `py is not recognized`: install Python from python.org and enable “Add Python to PATH”, then reopen VS Code.
- Port 8000 is busy: `uvicorn main:app --reload --port 8010` and open port 8010.
- Chart.js or Google Fonts unavailable: the dashboard still loads, but charts/fonts may not render while offline because those assets use CDNs.
- To stop: press `Ctrl+C` in the terminal.
