# Adaptive NIDS — Explainable Intrusion Detection System

A real-time Network Intrusion Detection System that detects 5 attack types
and generates plain-English explanations for every alert.

---

## Project Files

| File | Purpose |
|------|---------|
| `app.py` | Flask web server + REST API |
| `db.py` | SQLite database layer |
| `sniffer.py` | Live packet capture + adaptive detection engine |
| `seed_demo.py` | Populates DB with realistic demo alerts (run once) |
| `templates/dashboard.html` | Live auto-refreshing dashboard UI |
| `requirements.txt` | Python dependencies |
| `Procfile` | Tells Railway how to start the app |

---

## Run Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Seed demo data (run once)
python seed_demo.py

# 3. Start dashboard
python app.py
# Open http://localhost:5000

# 4. (Optional) Start live sniffer (requires admin/root)
sudo python sniffer.py
```

---

## Deploy to Railway (Free — Public URL)

### Step 1 — Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit — Adaptive NIDS"
# Create a new repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/adaptive-nids.git
git push -u origin main
```

### Step 2 — Deploy on Railway
1. Go to **https://railway.app** → Sign up with GitHub (free)
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Select your `adaptive-nids` repository
4. Railway auto-detects Python and deploys using `Procfile`
5. Click **"Generate Domain"** under Settings → Networking
6. Your public URL will be: `https://adaptive-nids-xxxx.up.railway.app`

### Step 3 — Seed demo data on Railway
In Railway dashboard → your service → **Shell tab**:
```bash
python seed_demo.py
```

That's it. Share the URL with anyone — no login needed.

---

## Attack Types Detected

| Attack | Detection Method | Real-World Tool |
|--------|-----------------|-----------------|
| SYN Flood | >70% SYN flag ratio | hping3 --syn --flood |
| Port Scan | >15 unique ports/window | nmap, masscan |
| ICMP Flood | >60% ICMP packets | ping -f, hping3 --icmp |
| Volumetric DoS | >3x adaptive threshold | LOIC, botnets |
| Anomalous Burst | 1.5x–3x adaptive threshold | misconfigured apps, malware |

---

## Key Concepts (for viva/review)

**What is a packet?**
A packet is a small unit of data transmitted over a network. Every file transfer,
webpage load, or ping is broken into packets. Each has a header (source IP,
destination IP, protocol) and payload (actual data).

**What is adaptive thresholding?**
Instead of a fixed limit (e.g., always alert at >100 packets), the system
calculates threshold = 1.5 × average of recent windows. If your network
normally handles 200 packets/window, the threshold auto-adjusts to 300.
This reduces false positives on busy networks.

**What is a subnet / subnet mask?**
A subnet divides a large network into smaller segments. The subnet mask
(e.g., 255.255.255.0 or /24) defines which part of an IP address identifies
the network vs the specific device. 192.168.1.x devices are on the same
/24 subnet — the sniffer sees them because they share the same LAN.

**Why does ICMP flood increase traffic?**
Normal ping = 1 packet/second. A ping flood (ping -f or hping3 --icmp --flood)
sends hundreds or thousands per second, saturating CPU and bandwidth.
Volume is the attack — not the protocol.
