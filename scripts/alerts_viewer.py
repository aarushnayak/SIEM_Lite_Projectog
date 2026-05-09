# alerts_viewer.py 
import sqlite3
import os
import csv
from datetime import datetime

DB_PATH = os.path.abspath(os.path.join("..", "logs", "siem_lite.db"))
OUT_CSV = os.path.abspath(os.path.join("..", "logs", "alerts_viewed.csv"))

# 1) Check DB file
if not os.path.exists(DB_PATH):
    print("Error: Database file nahi mili ->", DB_PATH)
    raise SystemExit(1)

# 2) Open DB
try:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    cur = conn.cursor()
except Exception as e:
    print("DB open error:", e)
    raise SystemExit(1)

# 3) Read table info
cur.execute("PRAGMA table_info(alerts)")
info = cur.fetchall()
if not info:
    print("Alerts table nahi mili ya empty.")
    conn.close()
    raise SystemExit(1)

# 4) Columns and rows
columns = [row[1] for row in info]
print("Alerts table columns detected:", columns)

cur.execute("SELECT * FROM alerts ORDER BY id DESC")
rows = cur.fetchall()
conn.close()

if not rows:
    print("No alerts found in database.")
    raise SystemExit(0)

# 5) Append to CSV with export timestamp
file_exists = os.path.exists(OUT_CSV)
with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(columns + ["export_timestamp"])
    export_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for row in rows:
        writer.writerow(list(row) + [export_time])

print(f"Wrote {len(rows)} alerts to {OUT_CSV}")

# 6) Print a quick preview (most recent 5)
print("\nRecent alerts (most recent first):")
for row in rows[:5]:
    print(row)
# hello hii 
