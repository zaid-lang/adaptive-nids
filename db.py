import sqlite3

DB_PATH = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            packet_count INTEGER,
            threshold INTEGER,
            severity TEXT,
            reason TEXT,
            attack_type TEXT DEFAULT 'Unknown',
            explanation TEXT DEFAULT ''
        )
    """)

    # Add new columns if upgrading from old schema
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN attack_type TEXT DEFAULT 'Unknown'")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN explanation TEXT DEFAULT ''")
    except:
        pass

    conn.commit()
    conn.close()

def log_alert(timestamp, ip, count, threshold, severity, reason, attack_type="Unknown", explanation=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (timestamp, source_ip, packet_count, threshold, severity, reason, attack_type, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, ip, count, threshold, severity, reason, attack_type, explanation))

    conn.commit()
    conn.close()

def get_alerts(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, source_ip, packet_count, threshold, severity, reason, attack_type, explanation
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    stats = {}

    cursor.execute("SELECT COUNT(*) FROM alerts")
    stats["total"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
    stats["high"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'")
    stats["medium"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'")
    stats["low"] = cursor.fetchone()[0]

    cursor.execute("SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 1")
    row = cursor.fetchone()
    stats["top_ip"] = row[0] if row else "N/A"
    stats["top_ip_count"] = row[1] if row else 0

    cursor.execute("""
        SELECT attack_type, COUNT(*) as cnt FROM alerts
        GROUP BY attack_type ORDER BY cnt DESC
    """)
    stats["attack_types"] = cursor.fetchall()

    conn.close()
    return stats
