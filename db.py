import sqlite3, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "alerts.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now')),
            api_key       TEXT UNIQUE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER REFERENCES users(id),
            timestamp     TEXT,
            source_ip     TEXT,
            packet_count  INTEGER,
            threshold     INTEGER,
            severity      TEXT,
            reason        TEXT,
            attack_type   TEXT DEFAULT 'Unknown',
            explanation   TEXT DEFAULT '',
            agent_host    TEXT DEFAULT 'unknown'
        )
    """)
    for col, defn in [
        ("attack_type", "TEXT DEFAULT 'Unknown'"),
        ("explanation", "TEXT DEFAULT ''"),
        ("user_id",     "INTEGER"),
        ("agent_host",  "TEXT DEFAULT 'unknown'"),
    ]:
        try:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
        except:
            pass
    conn.commit()
    conn.close()

def create_user(username, email, password_hash, api_key):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, email, password_hash, api_key) VALUES (?,?,?,?)",
        (username, email, password_hash, api_key)
    )
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(uid):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_apikey(api_key):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE api_key=?", (api_key,)).fetchone()
    conn.close()
    return dict(row) if row else None

def log_alert(user_id, timestamp, ip, count, threshold,
              severity, reason, attack_type, explanation, agent_host="unknown"):
    conn = get_db()
    conn.execute("""
        INSERT INTO alerts
            (user_id, timestamp, source_ip, packet_count, threshold,
             severity, reason, attack_type, explanation, agent_host)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (user_id, timestamp, ip, count, threshold,
          severity, reason, attack_type, explanation, agent_host))
    conn.commit()
    conn.close()

def get_alerts(user_id, limit=50):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, timestamp, source_ip, packet_count, threshold,
               severity, reason, attack_type, explanation, agent_host
        FROM alerts WHERE user_id=?
        ORDER BY id DESC LIMIT ?
    """, (user_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats(user_id):
    conn = get_db()
    def one(q, *a): return conn.execute(q, *a).fetchone()[0]
    stats = {
        "total":  one("SELECT COUNT(*) FROM alerts WHERE user_id=?", (user_id,)),
        "high":   one("SELECT COUNT(*) FROM alerts WHERE user_id=? AND severity='HIGH'",   (user_id,)),
        "medium": one("SELECT COUNT(*) FROM alerts WHERE user_id=? AND severity='MEDIUM'", (user_id,)),
        "low":    one("SELECT COUNT(*) FROM alerts WHERE user_id=? AND severity='LOW'",    (user_id,)),
    }
    top = conn.execute(
        "SELECT source_ip, COUNT(*) c FROM alerts WHERE user_id=? GROUP BY source_ip ORDER BY c DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    stats["top_ip"]       = top["source_ip"] if top else "N/A"
    stats["top_ip_count"] = top["c"]         if top else 0
    atypes = conn.execute(
        "SELECT COALESCE(attack_type,'Unknown'), COUNT(*) FROM alerts WHERE user_id=? GROUP BY attack_type",
        (user_id,)
    ).fetchall()
    stats["attack_types"] = [{"type": r[0], "count": r[1]} for r in atypes]
    agents = conn.execute(
        "SELECT DISTINCT agent_host FROM alerts WHERE user_id=?", (user_id,)
    ).fetchall()
    stats["agents"] = [r[0] for r in agents]
    conn.close()
    return stats
