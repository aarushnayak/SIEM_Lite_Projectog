# flask_app.py (Updated & Improved)
from flask import Flask, render_template, jsonify, request
import sqlite3, os
import requests
from pathlib import Path

# --- Constants aur Paths ---
BASE = Path(__file__).parent.resolve()
DB_PATH = BASE.joinpath("..", "logs", "siem_lite.db").resolve()

app = Flask(__name__, template_folder=str(BASE.joinpath("templates")))

# --- Helper Functions ---
def get_conn():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"DB not found: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes / Endpoints ---
@app.route("/")
def index():
    # Main dashboard
    return render_template("dashboard.html")

@app.route("/api/alerts")
def api_alerts():
    """Return latest alerts and enrich them with geo-location data (Optimized)."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, time, alert_type, ip, details FROM alerts ORDER BY id DESC LIMIT 50")
        alerts = [dict(r) for r in cur.fetchall()]
        conn.close()

        # --- BADLAAV 1: Speed ke liye Optimization ---
        # Sirf unique IPs ki list banao taaki duplicate API calls na hon
        unique_ips = {alert.get("ip") for alert in alerts if alert.get("ip")}
        locations_cache = {} # Yahan hum locations save karenge

        for ip in unique_ips:
            # Localhost aur private IPs ko skip karo
            if ip and not ip.startswith('192.168.') and not ip.startswith('10.') and ip != '127.0.0.1': # <-- BADLAAV 2: Typo Theek Kiya
                try:
                    geo_res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon,country", timeout=2)
                    if geo_res.status_code == 200:
                        geo_data = geo_res.json()
                        if geo_data.get('status') == 'success':
                            locations_cache[ip] = {
                                'lat': geo_data['lat'],
                                'lon': geo_data['lon'],
                                'country': geo_data.get('country', 'Unknown')
                            }
                except requests.RequestException:
                    pass # Error aaye toh aage badho

        # Ab saare alerts mein location data daalo
        for alert in alerts:
            if alert.get("ip") in locations_cache:
                alert['location'] = locations_cache[alert.get("ip")]
        # --- End of Optimization ---

        return jsonify({"ok": True, "alerts": alerts})
    except Exception as e:
        print("alerts error", e)
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/logs")
def api_logs():
    """Return latest parsed logs with abuse score"""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, timestamp, ip, action, raw, abuse_score FROM logs ORDER BY id DESC LIMIT 200")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"ok": True, "logs": rows})
    except Exception as e:
        print("logs api error", e)
        return jsonify({"ok": False, "error": str(e)}), 500
    # Yeh naya function IP ki saari details dega
@app.route('/api/ip/<ip_address>')
def get_ip_details(ip_address):
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # Us IP ke saare logs nikaalo
        cur.execute("SELECT timestamp, action, abuse_score FROM logs WHERE ip = ? ORDER BY id DESC LIMIT 100", (ip_address,))
        logs = [dict(r) for r in cur.fetchall()]

        # Us IP ke saare alerts nikaalo
        cur.execute("SELECT time, alert_type, details FROM alerts WHERE ip = ? ORDER BY id DESC LIMIT 50", (ip_address,))
        alerts = [dict(r) for r in cur.fetchall()]

        conn.close()
        
        # Saara data JSON mein bhejo
        return jsonify({
            "ok": True,
            "logs": logs,
            "alerts": alerts
        })
    except Exception as e:
        print(f"Error fetching details for IP {ip_address}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/counts")
def api_counts():
    """Return simple counts by alert_type and total logs count"""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type")
        by_type = [{ "type": r["alert_type"], "count": r["cnt"] } for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) as c FROM logs")
        total_logs = cur.fetchone()["c"]
        conn.close()
        return jsonify({"ok": True, "by_type": by_type, "total_logs": total_logs})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    
@app.route('/api/timeline')
def api_timeline():
    """Return counts of alerts grouped by hour for a timeline chart."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        # This SQL query groups alerts by the hour for the last 24 hours
        cur.execute("""
            SELECT strftime('%Y-%m-%d %H:00:00', time) as hour, COUNT(*) as count
            FROM alerts
            WHERE time >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"ok": True, "timeline": rows})
    except Exception as e:
        print(f"Timeline API error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500
    
    # Yeh naya function search ke liye hai
@app.route('/api/search')
def api_search():
    # Browser se search query lo (jaise ?q=8.8.8.8)
    query = request.args.get('q', '').strip()
    
    if not query:
        # Agar search box khali hai, toh kuch mat return karo
        return jsonify({"ok": True, "logs": []})

    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # Yahan hum dynamic query bana rahe hain
        # Yeh LIKE operator ka use karke IP, action, ya raw log mein search karega
        # Parameterized query (?) ka use karna SQL Injection se bachata hai
        sql_query = """
            SELECT id, timestamp, ip, action, raw, abuse_score 
            FROM logs 
            WHERE ip LIKE ? OR action LIKE ? OR raw LIKE ?
            ORDER BY id DESC
        """
        search_term = f"%{query}%"
        cur.execute(sql_query, (search_term, search_term, search_term))
        
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"ok": True, "logs": rows})
    except Exception as e:
        print(f"Search API error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    # --- BADLAAV 3: Debug Mode On Kiya ---
    # Isse code save karte hi server apne aap restart ho jayega
    app.run(host="0.0.0.0", port=5000, debug=True)