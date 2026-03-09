"""
seed_demo.py
Run this ONCE to populate alerts.db with realistic demo data covering all attack types.
Usage: python seed_demo.py
"""
import sqlite3, random, os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")

# ── Ensure schema exists ──────────────────────────────────────────────────────
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

# ── Attack scenario templates ─────────────────────────────────────────────────
SCENARIOS = [
    # ── SYN Flood ──────────────────────────────────────────────────────────────
    {
        "attack_type": "SYN Flood",
        "ips":         ["45.33.32.156", "198.51.100.23", "203.0.113.77"],
        "count_range": (800, 2400),
        "threshold":   220,
        "severities":  ["HIGH", "HIGH", "MEDIUM"],
        "reason":      "High SYN ratio — over 80% of packets are TCP SYN flags",
        "explanation": (
            "A SYN Flood attack works by exploiting the TCP three-way handshake. "
            "The attacker sends thousands of SYN (synchronise) packets to the target server "
            "but never completes the handshake. The server reserves memory for each half-open "
            "connection, waiting for the final ACK that never arrives. Eventually the connection "
            "table fills up and the server cannot accept legitimate connections — effectively "
            "making it unavailable. This IP sent {count} packets with {syn_pct}% being SYN-only, "
            "which is {ratio:.1f}x the adaptive threshold of {threshold}. "
            "Normal application traffic has a SYN ratio below 5%."
        ),
    },
    # ── Port Scan ──────────────────────────────────────────────────────────────
    {
        "attack_type": "Port Scan",
        "ips":         ["192.168.1.45", "10.0.0.88", "172.16.0.12"],
        "count_range": (90, 250),
        "threshold":   55,
        "severities":  ["MEDIUM", "HIGH", "LOW"],
        "reason":      "Accessed 20+ unique destination ports within a 10-second window",
        "explanation": (
            "A port scan is a reconnaissance technique used by attackers to discover which "
            "services are running on a target machine. By probing many ports rapidly, they "
            "build a map of the network — identifying web servers, databases, SSH daemons, "
            "and other services to target later. This IP ({ip}) contacted {ports} unique "
            "destination ports in just 10 seconds. Legitimate software almost never touches "
            "more than 2-3 ports in the same window. Tools like Nmap, Masscan, or Zmap "
            "are commonly used for this purpose. The {count} packets sent were {ratio:.1f}x "
            "the adaptive threshold of {threshold}."
        ),
    },
    # ── ICMP Flood ─────────────────────────────────────────────────────────────
    {
        "attack_type": "ICMP Flood",
        "ips":         ["10.10.10.5", "192.168.0.201"],
        "count_range": (400, 1100),
        "threshold":   180,
        "severities":  ["HIGH", "MEDIUM"],
        "reason":      "Excessive ICMP echo-request packets — over 70% of total traffic",
        "explanation": (
            "An ICMP Flood (also called a Ping Flood) overwhelms the target by sending a "
            "continuous stream of ICMP Echo Request (ping) packets. While a normal ping "
            "sends one packet per second to test reachability, a flood attack uses tools "
            "like 'ping -f' (Linux flood ping) or 'hping3 --icmp --flood' to send hundreds "
            "or thousands per second. Each packet forces the victim to process a request and "
            "send a reply, consuming CPU and saturating bandwidth. {ip} sent {count} ICMP "
            "packets in 10 seconds — that is {ratio:.1f}x the adaptive limit of {threshold}. "
            "Normal hosts send 0-2 ICMP packets per 10-second window."
        ),
    },
    # ── Volumetric DoS ─────────────────────────────────────────────────────────
    {
        "attack_type": "Volumetric DoS",
        "ips":         ["77.88.55.80", "185.220.101.34", "91.108.4.1"],
        "count_range": (1500, 5000),
        "threshold":   300,
        "severities":  ["HIGH", "HIGH", "HIGH"],
        "reason":      "Traffic volume is 4x+ above adaptive threshold — bandwidth saturation detected",
        "explanation": (
            "A Volumetric Denial-of-Service attack simply tries to consume all available "
            "bandwidth or exhaust server resources through sheer volume. Unlike SYN floods "
            "or port scans which exploit specific protocols, volumetric attacks work by "
            "sending as much data as possible — UDP packets, HTTP requests, or raw IP traffic. "
            "Botnets (networks of thousands of infected machines) are often used so the "
            "traffic appears to come from many different IPs simultaneously. This IP ({ip}) "
            "sent {count} packets in a single 10-second window — that is {ratio:.1f}x the "
            "adaptive threshold of {threshold} packets. At this rate, a 100 Mbps link "
            "would be significantly degraded."
        ),
    },
    # ── Anomalous Burst ────────────────────────────────────────────────────────
    {
        "attack_type": "Anomalous Burst",
        "ips":         ["192.168.1.100", "192.168.1.23", "10.0.0.55"],
        "count_range": (70, 200),
        "threshold":   45,
        "severities":  ["LOW", "MEDIUM", "LOW"],
        "reason":      "Packet rate exceeded adaptive baseline — unusual burst pattern detected",
        "explanation": (
            "An anomalous traffic burst occurs when an IP address suddenly sends significantly "
            "more packets than the established baseline without matching a known attack signature. "
            "This could indicate early-stage reconnaissance, a misconfigured application, "
            "malware beginning its infection routine, or a user running an unusually heavy "
            "network operation. The adaptive threshold is calculated as 1.5x the rolling "
            "average of recent 10-second traffic windows — so it adjusts to your network's "
            "own normal behaviour. {ip} sent {count} packets which is {ratio:.1f}x the "
            "current adaptive limit of {threshold}. While not immediately dangerous, "
            "sustained anomalies frequently precede larger intrusion attempts and warrant monitoring."
        ),
    },
]

# ── Generate alerts spread over the past 48 hours ────────────────────────────
now = datetime.now()
records = []

random.seed(42)  # reproducible demo data

for scenario in SCENARIOS:
    for i, ip in enumerate(scenario["ips"]):
        # 3-6 events per IP
        num_events = random.randint(3, 6)
        for j in range(num_events):
            hours_ago  = random.uniform(0.5, 47)
            ts         = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")
            count      = random.randint(*scenario["count_range"])
            threshold  = scenario["threshold"] + random.randint(-10, 10)
            ratio      = count / threshold
            severity   = scenario["severities"][i % len(scenario["severities"])]
            syn_pct    = random.randint(75, 92)
            ports      = random.randint(18, 35)

            # Fill template placeholders
            explanation = scenario["explanation"].format(
                ip        = ip,
                count     = count,
                threshold = threshold,
                ratio     = ratio,
                syn_pct   = syn_pct,
                ports     = ports,
            )

            records.append((
                ts, ip, count, threshold, severity,
                scenario["reason"], scenario["attack_type"], explanation
            ))

# Sort by timestamp ascending so IDs make sense
records.sort(key=lambda r: r[0])

conn = sqlite3.connect(DB_PATH)
conn.executemany("""
    INSERT INTO alerts
        (timestamp, source_ip, packet_count, threshold, severity, reason, attack_type, explanation)
    VALUES (?,?,?,?,?,?,?,?)
""", records)
conn.commit()
total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
conn.close()

print(f"✅  Seeded {len(records)} demo alerts → alerts.db  (total rows: {total})")
print("\nAttack type breakdown:")
conn = sqlite3.connect(DB_PATH)
for row in conn.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type ORDER BY 2 DESC"):
    print(f"   {row[0]:<20} {row[1]} alerts")
conn.close()
