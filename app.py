import os, secrets, hashlib
from flask import (Flask, render_template, jsonify, request,
                   session, redirect, url_for)
from db import init_db, create_user, get_user_by_email, get_user_by_id, \
               get_user_by_apikey, log_alert, get_alerts, get_stats

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def logged_in():
    return "user_id" in session

def current_user():
    return get_user_by_id(session["user_id"]) if logged_in() else None

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw    = request.form.get("password", "")
        user  = get_user_by_email(email)
        if user and user["password_hash"] == hash_pw(pw):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        error = "Invalid email or password."
    return render_template("login.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        pw       = request.form.get("password", "")
        pw2      = request.form.get("password2", "")
        if not username or not email or not pw:
            error = "All fields are required."
        elif pw != pw2:
            error = "Passwords do not match."
        elif get_user_by_email(email):
            error = "Email already registered."
        else:
            try:
                api_key = secrets.token_hex(24)
                create_user(username, email, hash_pw(pw), api_key)
                user = get_user_by_email(email)
                session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))
            except Exception as e:
                error = f"Registration failed: {e}"
    return render_template("signup.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("login"))
    user = current_user()
    return render_template("dashboard.html", user=user)

# ── API: alerts + stats (login protected) ─────────────────────────────────────
@app.route("/api/alerts")
def api_alerts():
    if not logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_alerts(session["user_id"]))

@app.route("/api/stats")
def api_stats():
    if not logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_stats(session["user_id"]))

# ── API: agent key info ───────────────────────────────────────────────────────
@app.route("/api/mykey")
def api_mykey():
    if not logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    user = current_user()
    return jsonify({
        "api_key":    user["api_key"],
        "username":   user["username"],
        "server_url": request.host_url.rstrip("/")
    })

# ── API: receive alerts FROM sniffer agents ───────────────────────────────────
@app.route("/api/log", methods=["POST"])
def api_log():
    # Authenticate via API key in header
    api_key = request.headers.get("X-API-Key", "")
    user    = get_user_by_apikey(api_key)
    if not user:
        return jsonify({"error": "Invalid API key"}), 403

    data = request.get_json(force=True)
    required = ["timestamp","source_ip","packet_count","threshold",
                "severity","reason","attack_type","explanation"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400

    log_alert(
        user_id     = user["id"],
        timestamp   = data["timestamp"],
        ip          = data["source_ip"],
        count       = data["packet_count"],
        threshold   = data["threshold"],
        severity    = data["severity"],
        reason      = data["reason"],
        attack_type = data["attack_type"],
        explanation = data["explanation"],
        agent_host  = data.get("agent_host", "unknown"),
    )
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

# ── Download pre-configured sniffer.py ───────────────────────────────────────
@app.route("/download/sniffer")
def download_sniffer():
    if not logged_in():
        return redirect(url_for("login"))
    user = current_user()
    server_url = request.host_url.rstrip("/")

    sniffer_code = f'''"""
sniffer.py — Adaptive NIDS Agent
Pre-configured for: {user["username"]}

HOW TO RUN:
  Windows: Run Command Prompt as Administrator, then:
    python sniffer.py

  Linux/Mac:
    sudo python3 sniffer.py

Requirements: pip install scapy requests
"""

SERVER_URL = "{server_url}"
API_KEY    = "{user["api_key"]}"
TEST_MODE  = False   # Set True to simulate attacks without real packets

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import time, statistics, socket, requests

WINDOW     = 10
AGENT_HOST = socket.gethostname()

packet_count = defaultdict(int)
syn_count    = defaultdict(int)
port_set     = defaultdict(set)
icmp_count   = defaultdict(int)
history      = []
start_time   = time.time()

def send_alert(timestamp, ip, count, threshold, severity, reason, attack_type, explanation):
    payload = {{
        "timestamp":    timestamp,
        "source_ip":    ip,
        "packet_count": count,
        "threshold":    threshold,
        "severity":     severity,
        "reason":       reason,
        "attack_type":  attack_type,
        "explanation":  explanation,
        "agent_host":   AGENT_HOST,
    }}
    try:
        r = requests.post(
            f"{{SERVER_URL}}/api/log",
            json=payload,
            headers={{"X-API-Key": API_KEY}},
            timeout=5
        )
        if r.status_code == 200:
            print(f"  ✅ Alert sent — {{attack_type}} [{{severity}}]")
        elif r.status_code == 403:
            print("  ❌ Invalid API key")
        else:
            print(f"  ⚠️  Server returned {{r.status_code}}")
    except Exception as e:
        print(f"  ❌ Connection error: {{e}}")

def classify_attack(ip, count, threshold):
    syn   = syn_count[ip]
    ports = len(port_set[ip])
    icmp  = icmp_count[ip]
    ratio = count / threshold if threshold > 0 else 0

    if syn > count * 0.7:
        return ("SYN Flood",
            f"High SYN ratio ({{syn}}/{{count}} packets are SYN)",
            f"A SYN Flood exploits TCP handshake. {{ip}} sent {{syn}} SYN packets out of {{count}} total "
            f"({{int(syn/count*100)}}% SYN ratio). Normal traffic is below 5%. Server connection tables "
            f"fill up and crash, making it unavailable to legitimate users.")
    elif ports > 15:
        return ("Port Scan",
            f"Accessed {{ports}} unique destination ports in {{WINDOW}}s",
            f"A port scan probes multiple ports to discover open services. {{ip}} contacted {{ports}} unique "
            f"ports in {{WINDOW}} seconds. Legitimate software rarely touches more than 2-3 ports at once. "
            f"This is reconnaissance — mapping the network before a targeted attack.")
    elif icmp > count * 0.6:
        return ("ICMP Flood",
            f"Excessive ICMP packets ({{icmp}}/{{count}})",
            f"An ICMP Flood sends thousands of ping packets per second. Normal ping sends 1/sec for "
            f"reachability testing. {{ip}} sent {{icmp}} ICMP packets ({{int(icmp/count*100)}}% of traffic), "
            f"consuming CPU and saturating bandwidth using tools like hping3 --icmp --flood.")
    elif ratio > 3.0:
        return ("Volumetric DoS",
            f"Traffic is {{ratio:.1f}}x above adaptive threshold",
            f"A Volumetric DoS floods the network with sheer volume. {{ip}} sent {{count}} packets — "
            f"{{ratio:.1f}}x the adaptive threshold of {{int(threshold)}}. This saturates network links "
            f"and prevents legitimate traffic. Often executed via botnets.")
    else:
        return ("Anomalous Burst",
            f"Packet rate {{ratio:.1f}}x above adaptive baseline",
            f"Anomalous burst from {{ip}}. Adaptive threshold ({{int(threshold)}} packets) is 1.5x the "
            f"rolling average of recent windows. {{ip}} sent {{count}} packets ({{ratio:.1f}}x the limit). "
            f"Anomalous bursts often precede larger attacks.")

def classify_severity(count, threshold):
    r = count / threshold if threshold > 0 else 0
    if r <= 1.2:   return "LOW"
    elif r <= 1.5: return "MEDIUM"
    else:          return "HIGH"

def packet_handler(packet):
    global start_time
    if packet.haslayer(IP):
        src = packet[IP].src
        packet_count[src] += 1
        if packet.haslayer(TCP):
            if packet[TCP].flags == 0x02:
                syn_count[src] += 1
            port_set[src].add(packet[TCP].dport)
        if packet.haslayer(UDP):
            port_set[src].add(packet[UDP].dport)
        if packet.haslayer(ICMP):
            icmp_count[src] += 1

    if TEST_MODE:
        packet_count["10.0.0.1"] += 150; syn_count["10.0.0.1"] += 130
        packet_count["10.0.0.2"] += 80
        for p in range(20, 45): port_set["10.0.0.2"].add(p)
        packet_count["10.0.0.3"] += 300

    if time.time() - start_time >= WINDOW:
        total = sum(packet_count.values())
        history.append(total)
        threshold = (statistics.mean(history) * 1.5) if len(history) > 1 else 200
        print(f"\\n[{{datetime.now().strftime('%H:%M:%S')}}] Window: {{total}} pkts | Threshold: {{int(threshold)}}")
        for ip, count in packet_count.items():
            if count > threshold:
                severity = classify_severity(count, threshold)
                attack_type, reason, explanation = classify_attack(ip, count, threshold)
                print(f"  ⚠️  {{ip}} → {{count}} pkts | {{attack_type}} | {{severity}}")
                send_alert(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                           ip, count, int(threshold), severity, reason, attack_type, explanation)
        packet_count.clear(); syn_count.clear()
        port_set.clear();     icmp_count.clear()
        start_time = time.time()

print("=" * 55)
print(f"  Adaptive NIDS Agent — {user["username"]}")
print(f"  Machine   : {{AGENT_HOST}}")
print(f"  Server    : {{SERVER_URL}}")
print(f"  Mode      : {{'TEST (simulated)' if TEST_MODE else 'LIVE capture'}}")
print(f"  Window    : {{WINDOW}}s")
print("=" * 55)
sniff(filter="ip", prn=packet_handler, store=False)
'''

    from flask import Response
    return Response(
        sniffer_code,
        mimetype="text/x-python",
        headers={{"Content-Disposition": "attachment; filename=sniffer.py"}}
    )

# ── Admin Panel ───────────────────────────────────────────────────────────────
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nids.com")

@app.route("/admin")
def admin():
    if not logged_in():
        return redirect(url_for("login"))
    user = current_user()
    if user["email"] != ADMIN_EMAIL:
        return "Access denied.", 403
    conn = get_db()
    users = conn.execute("""
        SELECT u.id, u.username, u.email, u.created_at, u.api_key,
               COUNT(a.id) as alert_count,
               MAX(a.timestamp) as last_alert
        FROM users u
        LEFT JOIN alerts a ON a.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """).fetchall()
    conn.close()
    return render_template("admin.html", users=[dict(u) for u in users], current=user)