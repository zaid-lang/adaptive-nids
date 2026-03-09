import os, sqlite3
from flask import Flask, render_template, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "alerts.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            source_ip     TEXT,
            packet_count  INTEGER,
            threshold     INTEGER,
            severity      TEXT,
            reason        TEXT,
            attack_type   TEXT DEFAULT 'Unknown',
            explanation   TEXT DEFAULT ''
        )
    """)
    for col in ("attack_type", "explanation"):
        try:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT DEFAULT ''")
        except:
            pass
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/alerts")
def api_alerts():
    conn = get_db()
    rows = conn.execute("""
        SELECT id, timestamp, source_ip, packet_count, threshold,
               severity, reason, attack_type, explanation
        FROM alerts ORDER BY id DESC LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    total  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    high   = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    medium = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0]
    low    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0]
    top    = conn.execute(
        "SELECT source_ip, COUNT(*) c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 1"
    ).fetchone()
    atypes = conn.execute(
        "SELECT COALESCE(attack_type,'Unknown'), COUNT(*) FROM alerts GROUP BY attack_type"
    ).fetchall()
    conn.close()
    return jsonify({
        "total": total, "high": high, "medium": medium, "low": low,
        "top_ip":       top[0] if top else "N/A",
        "top_ip_count": top[1] if top else 0,
        "attack_types": [{"type": r[0], "count": r[1]} for r in atypes],
    })

@app.route("/api/log", methods=["POST"])
def api_log():
    from flask import request
    data = request.get_json(force=True)
    conn = get_db()
    conn.execute("""
        INSERT INTO alerts
            (timestamp,source_ip,packet_count,threshold,severity,reason,attack_type,explanation)
        VALUES (:timestamp,:source_ip,:packet_count,:threshold,:severity,:reason,:attack_type,:explanation)
    """, data)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
