TEST_MODE = True   # Set to False for real network sniffing

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import statistics

from db import init_db, log_alert
from datetime import datetime

init_db()

# ── Per-IP tracking ──────────────────────────────────────────────────────────
packet_count   = defaultdict(int)        # total packets per IP
syn_count      = defaultdict(int)        # TCP SYN packets (DoS/SYN flood)
port_set       = defaultdict(set)        # unique destination ports (port scan)
icmp_count     = defaultdict(int)        # ICMP packets (ping flood)
burst_times    = defaultdict(list)       # timestamps for burst detection

history        = []                      # window totals for adaptive threshold
WINDOW         = 10                      # seconds per analysis window
start_time     = time.time()

# ── Attack Classifier ────────────────────────────────────────────────────────
def classify_attack(ip, count, threshold):
    """
    Returns (attack_type, reason, explanation) based on traffic patterns.
    This is the EXPLAINABILITY core of the system.
    """
    syn   = syn_count[ip]
    ports = len(port_set[ip])
    icmp  = icmp_count[ip]
    ratio = count / threshold if threshold > 0 else 0

    # Rule 1 — SYN Flood (many SYN packets = trying to exhaust connections)
    if syn > count * 0.7:
        attack_type = "SYN Flood"
        reason = f"High SYN ratio ({syn}/{count} packets are SYN)"
        explanation = (
            f"A SYN Flood attack sends a massive number of TCP SYN packets "
            f"to exhaust the server's connection table. {ip} sent {syn} SYN "
            f"packets out of {count} total — a {int(syn/count*100)}% SYN ratio, "
            f"far above the normal ~5%. This pattern strongly indicates a "
            f"deliberate attempt to make your server unavailable."
        )

    # Rule 2 — Port Scan (many unique ports = reconnaissance)
    elif ports > 15:
        attack_type = "Port Scan"
        reason = f"Accessing {ports} unique ports in {WINDOW}s window"
        explanation = (
            f"A port scan probes multiple ports to discover open services. "
            f"{ip} accessed {ports} unique destination ports in just {WINDOW} "
            f"seconds. Legitimate traffic rarely touches more than 2–3 ports. "
            f"This behaviour is characteristic of reconnaissance tools like "
            f"Nmap or Masscan attempting to map your network."
        )

    # Rule 3 — ICMP / Ping Flood
    elif icmp > count * 0.6:
        attack_type = "ICMP Flood"
        reason = f"Excessive ICMP packets ({icmp}/{count})"
        explanation = (
            f"An ICMP Flood overwhelms a target with ping requests. "
            f"{ip} sent {icmp} ICMP packets out of {count} total "
            f"({int(icmp/count*100)}% ICMP ratio). Normal hosts send ICMP "
            f"only for diagnostics. This volume suggests an automated flood "
            f"designed to saturate your network bandwidth."
        )

    # Rule 4 — Volumetric DoS (sheer volume, no specific pattern)
    elif ratio > 3.0:
        attack_type = "Volumetric DoS"
        reason = f"Traffic is {ratio:.1f}× above adaptive threshold"
        explanation = (
            f"A Volumetric DoS attack simply floods the network with traffic. "
            f"{ip} sent {count} packets — {ratio:.1f}× the adaptive threshold "
            f"of {int(threshold)}. The adaptive threshold is calculated from "
            f"your network's own recent history, so this is {ratio:.1f}× your "
            f"normal baseline. This level of traffic can cause packet loss "
            f"and service degradation."
        )

    # Rule 5 — Anomalous Burst (moderately over threshold)
    else:
        attack_type = "Anomalous Burst"
        reason = f"Packet rate {ratio:.1f}× above normal adaptive baseline"
        explanation = (
            f"An anomalous traffic burst was detected from {ip}. "
            f"The adaptive threshold ({int(threshold)} packets) is dynamically "
            f"calculated as 1.5× the rolling average of recent windows. "
            f"{ip} sent {count} packets, which is {ratio:.1f}× this baseline. "
            f"While not yet classified as a named attack, sustained anomalies "
            f"often precede larger intrusion attempts."
        )

    return attack_type, reason, explanation


# ── Severity Classifier ──────────────────────────────────────────────────────
def classify_severity(count, threshold):
    ratio = count / threshold if threshold > 0 else 0
    if ratio <= 1.2:
        return "LOW"
    elif ratio <= 1.5:
        return "MEDIUM"
    else:
        return "HIGH"


# ── Packet Handler ───────────────────────────────────────────────────────────
def packet_handler(packet):
    global start_time

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count[src_ip] += 1

        # Track SYN flags
        if packet.haslayer(TCP):
            if packet[TCP].flags == 0x02:  # SYN flag
                syn_count[src_ip] += 1
            port_set[src_ip].add(packet[TCP].dport)

        # Track UDP ports
        if packet.haslayer(UDP):
            port_set[src_ip].add(packet[UDP].dport)

        # Track ICMP
        if packet.haslayer(ICMP):
            icmp_count[src_ip] += 1

    # ── TEST MODE: inject simulated attack traffic ───────────────────────────
    if TEST_MODE:
        # Simulate SYN flood from attacker 1
        packet_count["10.0.0.1"] += 150
        syn_count["10.0.0.1"] += 130

        # Simulate port scan from attacker 2
        packet_count["10.0.0.2"] += 80
        for p in range(20, 45):
            port_set["10.0.0.2"].add(p)

        # Simulate volumetric DoS from attacker 3
        packet_count["10.0.0.3"] += 300

    current_time = time.time()

    # ── Analysis Window ──────────────────────────────────────────────────────
    if current_time - start_time >= WINDOW:
        print("\n══════════════════════════════════════════")
        print("   Adaptive Traffic Analysis  ")
        print("══════════════════════════════════════════")

        total_packets = sum(packet_count.values())
        history.append(total_packets)

        # Adaptive threshold from rolling history
        if len(history) > 1:
            avg = statistics.mean(history)
            threshold = avg * 1.5
        else:
            threshold = 50

        print(f"  Window Total  : {total_packets} packets")
        print(f"  Adaptive Limit: {int(threshold)} packets")
        print(f"  History Depth : {len(history)} windows\n")

        for ip, count in packet_count.items():
            if count > threshold:
                severity    = classify_severity(count, threshold)
                attack_type, reason, explanation = classify_attack(ip, count, threshold)

                print(f"  ⚠️  ALERT [{severity}] from {ip}")
                print(f"     Attack Type : {attack_type}")
                print(f"     Packets     : {count}  |  Limit: {int(threshold)}")
                print(f"     Reason      : {reason}")
                print(f"     Explanation : {explanation[:80]}...")
                print()

                log_alert(
                    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ip          = ip,
                    count       = count,
                    threshold   = int(threshold),
                    severity    = severity,
                    reason      = reason,
                    attack_type = attack_type,
                    explanation = explanation
                )

        print("══════════════════════════════════════════\n")

        # Reset for next window
        packet_count.clear()
        syn_count.clear()
        port_set.clear()
        icmp_count.clear()
        start_time = current_time


# ── Start Sniffing ───────────────────────────────────────────────────────────
print("Starting Adaptive NIDS with Explainable Alerts...")
print(f"  Mode    : {'TEST (simulated traffic)' if TEST_MODE else 'LIVE network capture'}")
print(f"  Window  : {WINDOW} seconds\n")
sniff(filter="ip", prn=packet_handler, store=False)
