"""
sniffer.py — Adaptive NIDS Agent
Runs on YOUR machine, captures packets, sends alerts to the cloud dashboard.

SETUP (do this before running):
  1. Sign up at your Railway app URL
  2. Copy your API key from the dashboard
  3. Paste them into SERVER_URL and API_KEY below
  4. Run: python sniffer.py  (as Administrator on Windows / sudo on Linux)
"""

# ═══════════════════════════════════════════════════════
#  CONFIGURE THESE TWO LINES BEFORE RUNNING
SERVER_URL = "https://adaptive-nids.up.railway.app"   # your Railway URL
API_KEY    = "b0bf273dbcf15e9de9551d74f11f955228a3080ff3244339"            # from dashboard
# ═══════════════════════════════════════════════════════

TEST_MODE = False   # True = simulate attacks without real packets (for demo)

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import time, statistics, socket, requests

WINDOW     = 10   # seconds per analysis window
AGENT_HOST = socket.gethostname()

packet_count = defaultdict(int)
syn_count    = defaultdict(int)
port_set     = defaultdict(set)
icmp_count   = defaultdict(int)
history      = []
start_time   = time.time()

# ── Send alert to cloud dashboard ─────────────────────────────────────────────
def send_alert(timestamp, ip, count, threshold, severity, reason, attack_type, explanation):
    payload = {
        "timestamp":    timestamp,
        "source_ip":    ip,
        "packet_count": count,
        "threshold":    threshold,
        "severity":     severity,
        "reason":       reason,
        "attack_type":  attack_type,
        "explanation":  explanation,
        "agent_host":   AGENT_HOST,
    }
    try:
        r = requests.post(
            f"{SERVER_URL}/api/log",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        if r.status_code == 200:
            print(f"  ✅ Alert sent to dashboard — {attack_type} [{severity}]")
        elif r.status_code == 403:
            print("  ❌ Invalid API key — check your API_KEY setting")
        else:
            print(f"  ⚠️  Server returned {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  ❌ Cannot reach {SERVER_URL} — check SERVER_URL or internet connection")
    except Exception as e:
        print(f"  ❌ Error sending alert: {e}")

# ── Attack classifier ─────────────────────────────────────────────────────────
def classify_attack(ip, count, threshold):
    syn   = syn_count[ip]
    ports = len(port_set[ip])
    icmp  = icmp_count[ip]
    ratio = count / threshold if threshold > 0 else 0

    if syn > count * 0.7:
        return (
            "SYN Flood",
            f"High SYN ratio ({syn}/{count} packets are SYN)",
            f"A SYN Flood attack sends massive TCP SYN packets without completing "
            f"the handshake. The server reserves memory for each half-open connection "
            f"until its table fills up and crashes. {ip} sent {syn} SYN packets out of "
            f"{count} total — a {int(syn/count*100)}% SYN ratio. Normal traffic is below 5%."
        )
    elif ports > 15:
        return (
            "Port Scan",
            f"Accessed {ports} unique destination ports in {WINDOW}s",
            f"A port scan probes multiple ports to discover open services — a reconnaissance "
            f"technique used before launching a targeted attack. {ip} contacted {ports} unique "
            f"ports in {WINDOW} seconds. Legitimate software rarely touches more than 2-3 ports "
            f"at once. Tools like Nmap or Masscan produce this pattern."
        )
    elif icmp > count * 0.6:
        return (
            "ICMP Flood",
            f"Excessive ICMP echo-requests ({icmp}/{count} packets)",
            f"An ICMP Flood overwhelms a host with ping packets. Normal ping sends 1 packet/sec "
            f"to test reachability. Flood tools like 'ping -f' or 'hping3 --icmp --flood' send "
            f"hundreds per second. {ip} sent {icmp} ICMP packets — {int(icmp/count*100)}% of "
            f"all traffic — consuming CPU and saturating bandwidth."
        )
    elif ratio > 3.0:
        return (
            "Volumetric DoS",
            f"Traffic is {ratio:.1f}x above adaptive threshold",
            f"A Volumetric DoS floods the network with sheer traffic volume to consume all "
            f"available bandwidth. {ip} sent {count} packets — {ratio:.1f}x the adaptive "
            f"threshold of {int(threshold)}. This level saturates network links and prevents "
            f"legitimate traffic from getting through. Often executed via botnets."
        )
    else:
        return (
            "Anomalous Burst",
            f"Packet rate {ratio:.1f}x above adaptive baseline",
            f"An anomalous traffic burst was detected from {ip}. The adaptive threshold "
            f"({int(threshold)} packets) is 1.5x the rolling average of recent windows — "
            f"calibrated to this network's own behaviour. {ip} sent {count} packets "
            f"({ratio:.1f}x the limit). Anomalous bursts often precede larger attacks."
        )

def classify_severity(count, threshold):
    r = count / threshold if threshold > 0 else 0
    if r <= 1.2:  return "LOW"
    elif r <= 1.5: return "MEDIUM"
    else:          return "HIGH"

# ── Packet handler ────────────────────────────────────────────────────────────
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
        threshold = (statistics.mean(history) * 1.5) if len(history) > 1 else 50

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Window: {total} pkts | Threshold: {int(threshold)}")

        for ip, count in packet_count.items():
            if count > threshold:
                severity = classify_severity(count, threshold)
                attack_type, reason, explanation = classify_attack(ip, count, threshold)
                print(f"  ⚠️  {ip} → {count} pkts | {attack_type} | {severity}")
                send_alert(
                    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ip          = ip,
                    count       = count,
                    threshold   = int(threshold),
                    severity    = severity,
                    reason      = reason,
                    attack_type = attack_type,
                    explanation = explanation,
                )

        packet_count.clear(); syn_count.clear()
        port_set.clear(); icmp_count.clear()
        start_time = time.time()

# ── Start ─────────────────────────────────────────────────────────────────────
print("=" * 55)
print("  Adaptive NIDS Agent")
print(f"  Machine   : {AGENT_HOST}")
print(f"  Server    : {SERVER_URL}")
print(f"  Mode      : {'TEST (simulated)' if TEST_MODE else 'LIVE capture'}")
print(f"  Window    : {WINDOW}s")
print("=" * 55)

if SERVER_URL == "https://your-app.up.railway.app":
    print("\n⚠️  WARNING: You haven't set SERVER_URL yet!")
    print("   Open sniffer.py and paste your Railway URL.\n")

sniff(filter="ip", prn=packet_handler, store=False)
