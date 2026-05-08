# siem_lite.py  (ready-to-run watcher + parser + detector + DB insert)
import os, time, re, csv, atexit
from datetime import datetime, timedelta
from collections import defaultdict, deque

# import DB helper (file in same scripts folder)
from siem_db import get_conn, init_db

BASE_DIR = os.path.dirname(__file__)
LOG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "auth_dummy.log"))
PARSED_CSV = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "parsed_logs.csv"))
ALERTS_CSV = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "alerts.csv"))
DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "siem_lite.db"))

# --- Database init ---
conn = get_conn(DB_PATH)
init_db(conn)

def close_conn():
    try:
        conn.close()
    except:
        pass
atexit.register(close_conn)

# --- patterns & sliding windows ---
ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

# detection windows: brute-force 60s window, 5 attempts; port-scan 30s, 4 distinct ports
BF_ATTEMPTS = 5
BF_WINDOW = timedelta(seconds=60)
PS_PORTS = 4
PS_WINDOW = timedelta(seconds=30)

recent_failed = defaultdict(deque)   # ip -> deque of datetime
recent_porthits = defaultdict(deque) # ip -> deque of (ts, port)
recent_requests = deque()            # for spike detection (if needed)

# --- parsing ---
def parse_line(line):
    line = line.strip()
    if not line:
        return None
    # parse timestamp from prefix (like "Sep 17 13:30:28")
    ts_prefix = line[:15]
    try:
        ts = datetime.strptime(ts_prefix + f" {datetime.now().year}", "%b %d %H:%M:%S %Y")
        ts_iso = ts.isoformat()
    except Exception:
        ts_iso = datetime.now().isoformat()

    ip_m = ip_pattern.search(line)
    ip = ip_m.group(1) if ip_m else ""
    action = "Other"
    port = None

    if "Failed password" in line:
        action = "FailedLogin"
    elif "Accepted password" in line:
        action = "SuccessfulLogin"
    elif "DPT=" in line or "IN=eth0" in line:
        action = "PortHit"

    m = re.search(r'port\s+(\d+)', line)
    if m:
        try:
            port = int(m.group(1))
        except:
            port = None

    return {
        "timestamp": ts_iso,
        "source": "auth",
        "ip": ip,
        "action": action,
        "port": port,
        "raw": line
    }

# --- storage helpers (CSV + DB) ---
def append_parsed(row):
    # CSV write
    header = ["timestamp","ip","action","port","raw"]
    write_header = not os.path.exists(PARSED_CSV)
    try:
        with open(PARSED_CSV, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow({
                "timestamp": row.get("timestamp",""),
                "ip": row.get("ip",""),
                "action": row.get("action",""),
                "port": row.get("port","") if row.get("port") is not None else "",
                "raw": row.get("raw","")
            })
    except Exception as e:
        print("CSV write error (parsed):", e)

    # DB insert if not duplicate
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM logs WHERE raw = ? LIMIT 1", (row.get("raw",""),))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO logs (timestamp, source, ip, action, port, raw) VALUES (?, ?, ?, ?, ?, ?)",
                (row.get("timestamp"), row.get("source","auth"), row.get("ip"), row.get("action"),
                 row.get("port"), row.get("raw"))
            )
            conn.commit()
    except Exception as e:
        print("DB insert log error:", e)

def append_alert(alert):
    # alert: dict with keys type/ip/details/time (time optional)
    # CSV write
    header = ["time","type","ip","details"]
    write_header = not os.path.exists(ALERTS_CSV)
    try:
        with open(ALERTS_CSV, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow({
                "time": alert.get("time",""),
                "type": alert.get("type",""),
                "ip": alert.get("ip",""),
                "details": alert.get("details","")
            })
    except Exception as e:
        print("CSV write error (alert):", e)

    # DB insert (avoid duplicates)
    try:
        cur = conn.cursor()
        # simple uniqueness check on details text
        cur.execute("SELECT 1 FROM alerts WHERE details = ? LIMIT 1", (alert.get("details",""),))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO alerts (time, alert_type, ip, details) VALUES (?, ?, ?, ?)",
                (alert.get("time", datetime.now().isoformat()), alert.get("type",""), alert.get("ip",""), alert.get("details",""))
            )
            conn.commit()
    except Exception as e:
        print("DB insert alert error:", e)

# --- detection logic ---
def detect_on_row(row):
    alerts = []
    try:
        ts = datetime.fromisoformat(row["timestamp"])
    except Exception:
        ts = datetime.now()
    ip = row.get("ip","")
    action = row.get("action","")
    port = row.get("port", None)

    # update global requests for spike detection (optional)
    recent_requests.append(ts)
    # prune old requests older than BF_WINDOW (small overhead)
    while recent_requests and (ts - recent_requests[0]) > BF_WINDOW:
        recent_requests.popleft()

    # brute-force detection
    if action == "FailedLogin" and ip:
        dq = recent_failed[ip]
        dq.append(ts)
        # remove old
        while dq and (ts - dq[0]) > BF_WINDOW:
            dq.popleft()
        if len(dq) >= BF_ATTEMPTS:
            alerts.append({
                "type": "BruteForce",
                "ip": ip,
                "details": f"{len(dq)} failed logins within {BF_WINDOW.seconds}s"
            })

    # port-scan detection
    if action == "PortHit" and ip:
        dq = recent_porthits[ip]
        dq.append((ts, port))
        # prune old
        while dq and (ts - dq[0][0]) > PS_WINDOW:
            dq.popleft()
        distinct_ports = {p for (_, p) in dq if p}
        if len(distinct_ports) >= PS_PORTS:
            alerts.append({
                "type": "PortScan",
                "ip": ip,
                "details": f"ports scanned: {', '.join(map(str, sorted(distinct_ports)))}"
            })

    return alerts

# --- main processing per line ---
def process_row(row):
    if not row:
        return
    append_parsed(row)
    print("PARSED:", row.get("timestamp",""), row.get("ip",""), row.get("action",""))
    # detection
    alerts = detect_on_row(row)
    for a in alerts:
        a["time"] = datetime.now().isoformat()
        a["type"] = a.get("type")
        append_alert(a)
        print("ALERT:", a.get("type"), "-", a.get("ip"), "-", a.get("details"))

# --- watch file: first read existing lines, then tail for new lines ---
def watch_file():
    # ensure log file exists (create if not)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "a", encoding='utf-8').close()

    print("Watching log:", LOG_PATH)
    with open(LOG_PATH, "r", encoding='utf-8') as f:
        # 1) read existing lines first (so pre-existing logs are parsed)
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = parse_line(line)
            process_row(row)

        # 2) now continue tailing for new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            row = parse_line(line)
            process_row(row)

if __name__ == "__main__":
    watch_file()
