# siem_lite_v2.py (A better, faster SIEM engine)
import os
import time
import re
import requests
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Apne DB helper ko import karo
from siem_db import get_conn, init_db
ABUSEIPDB_API_KEY = "be7b9f3f93003b0d1c7e8dd4cb1bbd6e15ddcf9da50fc98e2f125d2b4b8dd33d73d6a5fe9750ddfc"

# --- Constants aur Paths ---
BASE_DIR = os.path.dirname(__file__)
LOG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "auth_dummy.log"))
DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "siem_lite.db"))

# --- Database Connection ---
# Har cheez ke liye ek hi connection use karenge
conn = get_conn(DB_PATH)
init_db(conn) # Check karta hai ki tables bani hui hain ya nahi

# --- DETECTION CONSTANTS AND TRACKERS ---
BF_ATTEMPTS = 5
BF_WINDOW = timedelta(seconds=60)
recent_failed = defaultdict(deque)
brute_force_alerted_ips = set()
ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

# **[NEW] Port Scan Logic**
PS_THRESHOLD = 5 # 5 alag ports
PS_WINDOW = timedelta(seconds=60) # 60 seconds ke andar
# Format: { 'source_ip': { 'destination_port': timestamp } }
port_hit_tracker = defaultdict(dict)
port_scan_alerted_ips = set()

# --- Parsing Logic (FINAL FIX: packet_sniffer: keyword use kiya) ---
def parse_line(line):
    line = line.strip()
    if not line:
        return None
        
    ts_prefix = line[:15]
    try:
        ts = datetime.strptime(ts_prefix + f" {datetime.now().year}", "%b %d %H:%M:%S %Y")
        ts_iso = ts.isoformat()
    except Exception:
        ts_iso = datetime.now().isoformat()

    # **[FIXED] Ab hum 'packet_sniffer:' ya 'NETWORK:LIVE_PACKET' dono se pehchaan sakte hain**
    if "packet_sniffer:" in line or "NETWORK:LIVE_PACKET" in line: 
        # Log format: ... packet_sniffer: IN=eth0 SRC=1.1.1.1 ... DST_PORT=80 (from packet_sniffer.py)
        # Humne 'DST_PORT' ko pakadne ke liye regex use kiya hai
        match = re.search(r'SRC=(\d{1,3}(?:\.\d{1,3}){3}).*DST_PORT=(\d+)', line)
        if match:
            src_ip = match.group(1)
            # Port number 0 aane par ignore karne ke liye yahan sirf DST_PORT ko parse kar rahe hain
            dst_port = match.group(2)
            
            # Agar DST_PORT 0 hai (jaise ki ICMP traffic) toh isko PortHit mat maano
            if dst_port == '0':
                return None
                
            return {
                "timestamp": ts_iso, "source": "network", "ip": src_ip,
                "action": "PortHit", "port": dst_port, "raw": line
            }
        else:
            return None # Agar format match nahi hua
    
    # **[ORIGINAL LOGIC] SSHD/Auth logs ke liye**
    ip_m = ip_pattern.search(line)
    ip = ip_m.group(1) if ip_m else ""
    action = "Other"

    if "Failed password" in line:
        action = "FailedLogin"
    elif "Accepted password" in line:
        action = "SuccessfulLogin"
    
    return {
        "timestamp": ts_iso, "source": "auth", "ip": ip,
        "action": action, "port": None, "raw": line
    }

def check_ip_abuseipdb(ip_address):
    # AbuseIPDB API se IP ka risk score check karo
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    try:
        # Timeout ko badhaya taaki API call ruk na jaaye
        res = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5) 
        if res.status_code == 200:
            data = res.json()
            score = data.get('data', {}).get('abuseConfidenceScore', 0)
            return score
    except requests.RequestException as e:
        # print(f"API call to AbuseIPDB failed: {e}") # Debugging ke liye hata diya
        pass
    return None

# --- IMPROVEMENT 1: Simplified Database Functions (Same as before) ---
def insert_log_to_db(row):
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (timestamp, source, ip, action, port, raw, abuse_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (row.get("timestamp"), row.get("source"), row.get("ip"), row.get("action"),
             row.get("port"), row.get("raw"), row.get("abuse_score", 0))
        )
        conn.commit()
    except Exception as e:
        if "UNIQUE constraint failed" not in str(e):
            print(f"DB insert log error: {e}")

def insert_alert_to_db(alert):
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (time, alert_type, ip, details) VALUES (?, ?, ?, ?)",
            (alert.get("time", datetime.now().isoformat()), alert.get("type",""), alert.get("ip",""), alert.get("details",""))
        )
        conn.commit()
    except Exception as e:
        if "UNIQUE constraint failed" not in str(e):
            print(f"DB insert alert error: {e}")

# --- DETECTION LOGIC (BruteForce - Same as before) ---
def detect_brute_force(row):
    try:
        ts = datetime.fromisoformat(row["timestamp"])
    except Exception:
        ts = datetime.now()
    ip = row.get("ip","")
    action = row.get("action","")

    if action == "FailedLogin" and ip:
        dq = recent_failed[ip]
        dq.append(ts)
        
        while dq and (ts - dq[0]) > BF_WINDOW:
            dq.popleft()

        is_under_attack = len(dq) >= BF_ATTEMPTS
        already_alerted = ip in brute_force_alerted_ips

        if is_under_attack and not already_alerted:
            brute_force_alerted_ips.add(ip)
            return {
                "type": "BruteForce", "ip": ip,
                "details": f"{len(dq)}+ failed logins within {BF_WINDOW.seconds}s"
            }
            
    elif ip in brute_force_alerted_ips and len(recent_failed.get(ip, [])) < BF_ATTEMPTS:
          brute_force_alerted_ips.remove(ip)

    return None

# --- [NEW] DETECTION LOGIC (PortScan - Same as before) ---
def detect_port_scan(row):
    ip = row.get("ip","")
    action = row.get("action","")
    port = row.get("port")
    
    if action == "PortHit" and ip and port:
        try:
            ts = datetime.fromisoformat(row["timestamp"])
        except Exception:
            ts = datetime.now()
        
        # 1. Port Hit aur Time-stamp ko store karo
        port_hit_tracker[ip][port] = ts
        
        # 2. Purane hits ko clean 
        current_time = datetime.now()
        recent_ports = {}
        for p, timestamp in port_hit_tracker[ip].items():
            if current_time - timestamp < PS_WINDOW:
                recent_ports[p] = timestamp

        port_hit_tracker[ip] = recent_ports
        
        # 3. Check karo ki kitne alag ports hit hue hain
        distinct_ports_hit = len(port_hit_tracker[ip])
        
        # 4. Agar threshold cross ho gaya, aur alert nahi diya hai toh alert raise karo
        is_scanning = distinct_ports_hit >= PS_THRESHOLD
        already_alerted = ip in port_scan_alerted_ips
        
        if is_scanning and not already_alerted:
            port_scan_alerted_ips.add(ip)
            return {
                "type": "PortScan", "ip": ip,
                "details": f"Port Scan detected! {ip} hit {distinct_ports_hit} ports in {PS_WINDOW.seconds}s."
            }
        
        # 5. Agar scanning band ho gayi hai, toh IP ko alerted list se hatao
        elif not is_scanning and already_alerted:
            port_scan_alerted_ips.remove(ip)
            
    return None

# --- Main Processing Logic (Updated to include PortScan) ---
def process_line(line):
    row = parse_line(line)
    if not row:
        return
    
    # New Task: Check the IP's risk score (Only for external IPs, not for local network)
    ip = row.get("ip")
    # Yahan humne thodi checking dali hai taaki har internal IP ke liye API call na ho
    if ip and not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.') and row.get("abuse_score") is None:
        abuse_score = check_ip_abuseipdb(ip)
        if abuse_score is not None:
            # print(f"RISK SCORE for {ip}: {abuse_score}") # Optional: Print the score
            row['abuse_score'] = abuse_score

    insert_log_to_db(row)
    print("PARSED:", row.get("timestamp",""), row.get("ip",""), row.get("action",""))
    
    # --- Detection Calls ---
    alerts = []
    
    # 1. Brute Force Detection
    alert_bf = detect_brute_force(row)
    if alert_bf:
        alerts.append(alert_bf)
        
    # 2. [NEW] Port Scan Detection
    alert_ps = detect_port_scan(row)
    if alert_ps:
        alerts.append(alert_ps)

    # Alerts ko DB mein daalo
    for alert in alerts:
        alert["time"] = datetime.now().isoformat()
        insert_alert_to_db(alert)
        print("!! ALERT !!:", alert.get("type"), "-", alert.get("ip"), "-", alert.get("details"))

# --- IMPROVEMENT 2: Smart File Tailing (Same as before) ---
def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "a", encoding='utf-8').close()

    print("Watching log:", LOG_PATH)
    logfile = open(LOG_PATH, "r", encoding='utf-8')
    
    for line in follow(logfile):
        process_line(line)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping the SIEM engine.")
        conn.close()