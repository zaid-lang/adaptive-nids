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
