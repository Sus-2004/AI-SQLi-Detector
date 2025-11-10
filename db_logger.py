# backend_api/db_logger.py
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(_file_))
DB_PATH = os.path.join(BASE_DIR, "queries_log.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_query(query, status, reason=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO logs (query, status, reason) VALUES (?, ?, ?)", (query, status, reason))
    conn.commit()
    conn.close()

def get_stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM logs")
    total = cur.fetchone()["cnt"] or 0
    cur.execute("SELECT COUNT(*) as cnt FROM logs WHERE status='safe'")
    safe = cur.fetchone()["cnt"] or 0
    cur.execute("SELECT COUNT(*) as cnt FROM logs WHERE status='sqli'")
    attacks = cur.fetchone()["cnt"] or 0
    conn.close()
    return {"total": total, "safe": safe, "attacks": attacks}

# Ensure DB ready on import
init_db()
