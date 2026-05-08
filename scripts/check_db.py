# check_db.py
import sqlite3, os

db = os.path.abspath(os.path.join("..", "logs", "siem_lite.db"))

if not os.path.exists(db):
    print("DB not found:", db)
else:
    conn = sqlite3.connect(db)
    try:
        logs_count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        alerts_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        print("logs:", logs_count)
        print("alerts:", alerts_count)
    except Exception as e:
        print("Error reading DB:", e)
    finally:
        conn.close()
