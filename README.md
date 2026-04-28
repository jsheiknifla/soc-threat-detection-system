# 🛡️ SIEM ThreatWatch
### Intelligent Real-Time Threat Detection System for Windows

A mini SIEM (Security Information and Event Management) system that collects **real Windows Event Logs** from your machine, detects threats using rule-based logic, generates alerts, auto-blocks suspicious sources, and displays everything on a live dark-theme web dashboard.

---

## 📁 Project Structure

```
smei proj/
├── app.py                  ← Flask backend + real-time log watcher + threat engine
├── requirements.txt        ← Python dependencies
├── siem.db                 ← SQLite database (auto-created on first run)
├── templates/
│   └── index.html          ← Dashboard UI (dark theme)
└── static/
    ├── css/
    │   └── style.css       ← Dark theme styles + modal styles
    └── js/
        └── dashboard.js    ← Live charts, tables, click-to-detail modals
```

---

## ⚙️ Requirements

| Requirement | Version |
|---|---|
| Python | 3.10 or higher |
| Flask | 3.x |
| pywin32 | 311+ |
| OS | Windows 10 / 11 |

---

## 🚀 Setup & Run

### 1. Install dependencies
```bash
pip install flask pywin32
```

### 2. Run the server
```bash
cd "smei proj"
python app.py
```

### 3. Open the dashboard
```
http://127.0.0.1:5000
```

> The dashboard auto-refreshes every **8 seconds** with live data.

---

## 🔍 How It Works

### Log Collection (Real-Time)
- On startup, reads **all existing** events from `System` and `Application` Windows Event Logs
- Uses `win32evtlog.NotifyChangeEventLog` to get **instantly notified** when any new event is written to the log — no polling delay
- Each new event is stored in SQLite and immediately analyzed

### Threat Detection Engine
Every incoming event is checked against these rules:

| Event ID | Alert Type | Severity |
|---|---|---|
| 7045 | New Service Installed | High |
| 7040 | Service Config Changed | Medium |
| 104 | Event Log Cleared | Critical |
| 1102 | Audit Log Cleared | Critical |
| 6008 | Unexpected Shutdown | Critical |
| 41 | Kernel Power Failure | Critical |
| 1001 | Application Crash Report | High |
| 1000 | Application Crash | High |
| 1002 | Application Hang | High |
| 4625 | Failed Login | High |
| 4648 | Explicit Credential Use | High |
| 4719 | Audit Policy Changed | Critical |
| 4698 | Scheduled Task Created | High |
| 4702 | Scheduled Task Updated | Medium |
| 2097 | Firewall Rule Added | Medium |
| 2052 | Firewall Rule Deleted | High |
| 700/701 | Display Driver Warning | Low |

**Extra rule:** If the same provider generates **5+ errors within 2 minutes** → `Repeated Errors` High alert

### Auto-Blocking
Any alert with severity `Critical` automatically adds the source provider to the **Blocked Sources** list.

### Deduplication
- Same alert type from the same provider won't fire again within **5 minutes**
- Same log record won't be stored twice (tracked by `record_id`)

---

## 🖥️ Dashboard Features

| Section | Description |
|---|---|
| Stat Cards | Total logs, Info events, Errors/Warnings, Total alerts, Critical alerts, Blocked sources |
| Timeline Chart | Stacked bar chart — Info / Warning / Error events per minute |
| Alerts by Type | Doughnut chart of alert categories |
| Logs by Source | Horizontal bar chart of event volume per log source |
| Recent Alerts | Live table — click any row to see full alert details in a modal |
| Blocked Sources | Live table — click any row to see block reason and timestamp |
| Live Log Feed | Live table — click any row to see full event message in a modal |

### Click-to-Detail Modal
Every row in every table is **clickable**. Clicking opens a modal popup showing:
- Full timestamp, Event ID, Level, Provider, Log Name
- Complete raw message from the Windows Event Log

Press `Escape` or click outside the modal to close it.

---

## 🗄️ Database Schema

```sql
-- All collected Windows events
logs (id, timestamp, log_name, event_id, level, provider, message, record_id)

-- Generated threat alerts
alerts (id, timestamp, provider, alert_type, description, severity, event_id)

-- Auto-blocked sources (Critical alerts)
blocked (id, source, blocked_at, reason)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/api/stats` | Summary counts |
| GET | `/api/logs` | Last 100 log entries |
| GET | `/api/logs/<id>` | Single log detail |
| GET | `/api/alerts` | Last 100 alerts |
| GET | `/api/alerts/<id>` | Single alert detail |
| GET | `/api/blocked` | All blocked sources |
| GET | `/api/blocked/<id>` | Single blocked source detail |
| GET | `/api/chart/timeline` | Timeline chart data |
| GET | `/api/chart/alerts_by_type` | Alert type chart data |
| GET | `/api/chart/logs_by_source` | Log source chart data |

---

## ⚠️ Notes

- **Security log** (`Event ID 4625`, `4648`, etc.) requires **Administrator** privileges. Run as admin to capture login-related events.
- `System` and `Application` logs work without admin rights.
- The `siem.db` file is created automatically in the project folder on first run.
- To reset all data, stop the server, delete `siem.db`, and restart.

---

## 🛑 Stop the Server

Press `Ctrl + C` in the terminal window running `python app.py`.

---

## 👤 Author

Built as a SOC/SIEM learning project demonstrating real-time Windows log analysis, threat detection, and security dashboarding.
