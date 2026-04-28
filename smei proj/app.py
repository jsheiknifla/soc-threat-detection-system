from flask import Flask, jsonify, render_template
from datetime import datetime, timedelta
import sqlite3, threading, time, win32evtlog, win32event, win32api, pywintypes

app = Flask(__name__)
DB = "siem.db"
DB_LOCK = threading.Lock()

# ── Logs to watch (no admin needed) ───────────────────────────────────────────
WATCH_LOGS = ["System", "Application"]

# ── Threat rules: event_id -> (alert_type, severity, description) ──────────────
THREAT_RULES = {
    7045: ("New Service Installed",    "High",     "New service installed on system"),
    7040: ("Service Config Changed",   "Medium",   "Service start type was modified"),
    104:  ("Event Log Cleared",        "Critical", "System event log was cleared"),
    1102: ("Audit Log Cleared",        "Critical", "Security audit log was cleared"),
    6008: ("Unexpected Shutdown",      "Critical", "Previous system shutdown was unexpected"),
    41:   ("Kernel Power Failure",     "Critical", "System rebooted without clean shutdown"),
    1001: ("Application Crash Report", "High",     "Windows Error Reporting triggered"),
    1000: ("Application Crash",        "High",     "An application crashed"),
    1002: ("Application Hang",         "High",     "An application stopped responding"),
    4625: ("Failed Login",             "High",     "A login attempt failed"),
    4648: ("Explicit Credential Use",  "High",     "Logon using explicit credentials"),
    4719: ("Audit Policy Changed",     "Critical", "System audit policy was changed"),
    4698: ("Scheduled Task Created",   "High",     "A new scheduled task was created"),
    4702: ("Scheduled Task Updated",   "Medium",   "A scheduled task was updated"),
    2097: ("Firewall Rule Added",      "Medium",   "A firewall exception rule was added"),
    2052: ("Firewall Rule Deleted",    "High",     "A firewall rule was deleted"),
    701:  ("Display Driver Warning",   "Low",      "Win32k display driver warning"),
    700:  ("Display Driver Warning",   "Low",      "Win32k display driver warning"),
}

# ── DB ─────────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with DB_LOCK:
        with get_db() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS logs (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    log_name  TEXT NOT NULL,
                    event_id  INTEGER NOT NULL,
                    level     TEXT NOT NULL,
                    provider  TEXT NOT NULL,
                    message   TEXT NOT NULL,
                    record_id INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    provider    TEXT NOT NULL,
                    alert_type  TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    event_id    INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blocked (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    source     TEXT UNIQUE NOT NULL,
                    blocked_at TEXT NOT NULL,
                    reason     TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watcher_state (
                    log_name   TEXT PRIMARY KEY,
                    last_record INTEGER NOT NULL DEFAULT 0
                );
            """)

# ── Level mapping ──────────────────────────────────────────────────────────────
LEVEL_MAP = {
    win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
    win32evtlog.EVENTLOG_WARNING_TYPE:     "Warning",
    win32evtlog.EVENTLOG_ERROR_TYPE:       "Error",
    win32evtlog.EVENTLOG_AUDIT_SUCCESS:    "Audit Success",
    win32evtlog.EVENTLOG_AUDIT_FAILURE:    "Audit Failure",
}

# ── Store one event + run threat detection ─────────────────────────────────────
def store_event(log_name, evt):
    try:
        eid      = evt.EventID & 0xFFFF
        ts       = evt.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
        level    = LEVEL_MAP.get(evt.EventType, "Information")
        provider = evt.SourceName or ""
        record   = evt.RecordNumber

        # Build message from StringInserts
        parts = evt.StringInserts
        msg = " | ".join(parts) if parts else ""
        msg = msg[:300]

        with DB_LOCK:
            with get_db() as c:
                # skip if already stored (by record_id + log_name)
                exists = c.execute(
                    "SELECT 1 FROM logs WHERE log_name=? AND record_id=?",
                    (log_name, record)
                ).fetchone()
                if exists:
                    return

                c.execute(
                    "INSERT INTO logs (timestamp,log_name,event_id,level,provider,message,record_id) VALUES (?,?,?,?,?,?,?)",
                    (ts, log_name, eid, level, provider, msg, record)
                )

                # ── Threat detection ──────────────────────────────────────
                if eid in THREAT_RULES:
                    atype, severity, base_desc = THREAT_RULES[eid]
                    desc = f"{base_desc} | Provider: {provider} | {msg[:120]}"

                    # deduplicate: same provider+type within 5 min
                    recent = c.execute(
                        "SELECT 1 FROM alerts WHERE provider=? AND alert_type=? "
                        "AND timestamp > datetime('now','-5 minutes')",
                        (provider, atype)
                    ).fetchone()
                    if not recent:
                        c.execute(
                            "INSERT INTO alerts (timestamp,provider,alert_type,description,severity,event_id) "
                            "VALUES (?,?,?,?,?,?)",
                            (ts, provider, atype, desc, severity, eid)
                        )
                        if severity == "Critical":
                            c.execute(
                                "INSERT OR IGNORE INTO blocked (source,blocked_at,reason) VALUES (?,?,?)",
                                (provider, ts, atype)
                            )

                # ── Repeated errors rule ──────────────────────────────────
                if level in ("Error", "Critical"):
                    two_ago = (datetime.now() - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
                    cnt = c.execute(
                        "SELECT COUNT(*) FROM logs WHERE provider=? AND level IN ('Error','Critical') AND timestamp>?",
                        (provider, two_ago)
                    ).fetchone()[0]
                    if cnt >= 5:
                        recent2 = c.execute(
                            "SELECT 1 FROM alerts WHERE provider=? AND alert_type='Repeated Errors' "
                            "AND timestamp > datetime('now','-2 minutes')",
                            (provider,)
                        ).fetchone()
                        if not recent2:
                            c.execute(
                                "INSERT INTO alerts (timestamp,provider,alert_type,description,severity,event_id) "
                                "VALUES (?,?,?,?,?,?)",
                                (ts, provider, "Repeated Errors",
                                 f"{cnt} errors from '{provider}' in 2 minutes", "High", eid)
                            )

    except Exception as e:
        print(f"[store_event error] {e}")

# ── Per-log watcher thread ─────────────────────────────────────────────────────
def watch_log(log_name):
    """
    Opens the event log, reads all existing events once,
    then waits for new events using NotifyChangeEventLog — truly real-time.
    """
    print(f"[Watcher] Starting: {log_name}")
    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
    except Exception as e:
        print(f"[Watcher] Cannot open {log_name}: {e}")
        return

    # ── Step 1: load existing events (newest first, then reverse) ─────────────
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    existing = []
    try:
        while True:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            existing.extend(batch)
    except Exception:
        pass

    existing.reverse()  # oldest first
    for evt in existing:
        store_event(log_name, evt)
    print(f"[Watcher] {log_name}: loaded {len(existing)} existing events")

    # ── Step 2: watch for NEW events in real-time ──────────────────────────────
    # Create a Windows event handle that gets signalled when new log entries arrive
    notify_handle = win32event.CreateEvent(None, 0, 0, None)
    win32evtlog.NotifyChangeEventLog(handle, notify_handle)

    # Track the last record number we've seen
    with DB_LOCK:
        with get_db() as c:
            row = c.execute(
                "SELECT MAX(record_id) FROM logs WHERE log_name=?", (log_name,)
            ).fetchone()
            last_record = row[0] if row[0] else 0

    print(f"[Watcher] {log_name}: watching for new events (last record={last_record})...")

    fwd_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        try:
            # Wait up to 5 seconds for a new event signal
            rc = win32event.WaitForSingleObject(notify_handle, 5000)

            if rc == win32event.WAIT_OBJECT_0 or rc == win32event.WAIT_TIMEOUT:
                # Read any new events since last_record
                new_events = []
                try:
                    while True:
                        batch = win32evtlog.ReadEventLog(handle, fwd_flags, 0)
                        if not batch:
                            break
                        for evt in batch:
                            if evt.RecordNumber > last_record:
                                new_events.append(evt)
                except pywintypes.error as pe:
                    if pe.winerror == 38:  # ERROR_HANDLE_EOF — no more records
                        pass
                    else:
                        # Log was rotated or handle invalid — reopen
                        print(f"[Watcher] {log_name} handle error {pe.winerror}, reopening...")
                        try:
                            win32evtlog.CloseEventLog(handle)
                        except Exception:
                            pass
                        time.sleep(2)
                        try:
                            handle = win32evtlog.OpenEventLog(None, log_name)
                            win32evtlog.NotifyChangeEventLog(handle, notify_handle)
                        except Exception as re:
                            print(f"[Watcher] {log_name} reopen failed: {re}")
                        continue

                for evt in new_events:
                    store_event(log_name, evt)
                    if evt.RecordNumber > last_record:
                        last_record = evt.RecordNumber

                if new_events:
                    print(f"[Watcher] {log_name}: +{len(new_events)} new event(s)")

        except Exception as e:
            print(f"[Watcher] {log_name} loop error: {e}")
            time.sleep(3)

# ── Flask routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    with DB_LOCK:
        with get_db() as c:
            total    = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            errors   = c.execute("SELECT COUNT(*) FROM logs WHERE level IN ('Error','Critical','Warning')").fetchone()[0]
            info     = c.execute("SELECT COUNT(*) FROM logs WHERE level='Information'").fetchone()[0]
            alerts   = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            blocked  = c.execute("SELECT COUNT(*) FROM blocked").fetchone()[0]
            critical = c.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'").fetchone()[0]
    return jsonify(total=total, errors=errors, info=info, alerts=alerts, blocked=blocked, critical=critical)

@app.route("/api/logs")
def logs():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/logs/<int:lid>")
def log_detail(lid):
    with DB_LOCK:
        with get_db() as c:
            row = c.execute("SELECT * FROM logs WHERE id=?", (lid,)).fetchone()
    return jsonify(dict(row) if row else {})

@app.route("/api/alerts")
def alerts():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts/<int:aid>")
def alert_detail(aid):
    with DB_LOCK:
        with get_db() as c:
            row = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    return jsonify(dict(row) if row else {})

@app.route("/api/blocked")
def blocked_list():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute("SELECT * FROM blocked ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/blocked/<int:bid>")
def blocked_detail(bid):
    with DB_LOCK:
        with get_db() as c:
            row = c.execute("SELECT * FROM blocked WHERE id=?", (bid,)).fetchone()
    return jsonify(dict(row) if row else {})

@app.route("/api/chart/timeline")
def chart_timeline():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute("""
                SELECT strftime('%H:%M', timestamp) as t,
                       SUM(CASE WHEN level='Information' THEN 1 ELSE 0 END) as info,
                       SUM(CASE WHEN level IN ('Error','Critical') THEN 1 ELSE 0 END) as err,
                       SUM(CASE WHEN level='Warning' THEN 1 ELSE 0 END) as warn
                FROM logs
                GROUP BY strftime('%H:%M', timestamp)
                ORDER BY t DESC LIMIT 20
            """).fetchall()
    rows = list(reversed(rows))
    return jsonify(
        labels=[r["t"] for r in rows],
        info=[r["info"] for r in rows],
        error=[r["err"] for r in rows],
        warning=[r["warn"] for r in rows]
    )

@app.route("/api/chart/alerts_by_type")
def chart_alerts_by_type():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute(
                "SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC"
            ).fetchall()
    return jsonify(labels=[r["alert_type"] for r in rows], counts=[r["cnt"] for r in rows])

@app.route("/api/chart/logs_by_source")
def chart_logs_by_source():
    with DB_LOCK:
        with get_db() as c:
            rows = c.execute(
                "SELECT log_name, COUNT(*) as cnt FROM logs GROUP BY log_name ORDER BY cnt DESC"
            ).fetchall()
    return jsonify(labels=[r["log_name"] for r in rows], counts=[r["cnt"] for r in rows])

# ── Start ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    for log_name in WATCH_LOGS:
        t = threading.Thread(target=watch_log, args=(log_name,), daemon=True)
        t.start()
    print("=" * 55)
    print("  SIEM ThreatWatch  →  http://127.0.0.1:5000")
    print("  Watching: " + ", ".join(WATCH_LOGS))
    print("=" * 55)
    app.run(debug=False, use_reloader=False, port=5000)
