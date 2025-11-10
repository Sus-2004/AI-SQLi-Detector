# db_logger.py
import os, sqlite3, csv, tempfile
BASE = os.path.dirname(os.path.abspath(_file_))
DB = os.path.join(BASE, "queries_log.db")

def get_conn():
    conn = sqlite3.connect(DB, check_same_thread=False)
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    """)
    conn.commit()
    conn.close()

def log_query(query, status, reason=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO logs (query, status, reason) VALUES (?, ?, ?)",
                (query, status, reason))
    conn.commit()
    conn.close()

def get_stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM logs")
    total = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(*) FROM logs WHERE status='safe'")
    safe = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(*) FROM logs WHERE status='sqli'")
    attacks = cur.fetchone()[0] or 0
    conn.close()
    return {"total": total, "safe": safe, "attacks": attacks}

def export_logs_csv():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, query, status, reason, ts FROM logs ORDER BY ts DESC")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        return None
    fd, tmpfile = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id","query","status","reason","timestamp"])
        writer.writerows(rows)
    return tmpfile
