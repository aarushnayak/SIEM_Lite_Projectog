# siem_db.py
import sqlite3
from pathlib import Path

def get_conn(db_path):
    # ensure parent folder exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        ip TEXT,
        action TEXT,
        port INTEGER,
        abuse_score INTEGER, -- <-- YAHAN BADLAAV KIYA HAI
        raw TEXT UNIQUE
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        alert_type TEXT,
        ip TEXT,
        details TEXT UNIQUE
    )""")
    conn.commit()

