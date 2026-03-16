"""
attacker.py — Live Attack Demonstrator
Simulates all 4 real attack types against YOUR OWN machine (127.0.0.1).
100% legal — attacking yourself for demonstration purposes.

Run this in a SECOND terminal while sniffer.py is running in the first.
Attacks will appear live on your dashboard within 10 seconds.

Requirements: pip install scapy
Run as Administrator (Windows) / sudo (Linux)
"""

from scapy.all import IP, TCP, UDP, ICMP, send, RandShort
import time, threading

TARGET = "127.0.0.1"   # your own machine — safe!

MENU = """
╔══════════════════════════════════════════════╗
║     ADAPTIVE NIDS — Live Attack Demo         ║
║     Target: 127.0.0.1 (your own machine)     ║
╠══════════════════════════════════════════════╣
║  1 — SYN Flood      (TCP SYN storm)          ║
║  2 — Port Scan      (probe 1-1024 ports)     ║
║  3 — ICMP Flood     (ping flood)             ║
║  4 — Volumetric DoS (UDP flood)              ║
║  5 — ALL ATTACKS    (full demo sequence)     ║
║  0 — Exit                                   ║
╚══════════════════════════════════════════════╝
"""

# ── Attack 1: SYN Flood ───────────────────────────────────────────────────────
def syn_flood(count=500):
    print(f"\n[SYN FLOOD] Sending {count} SYN packets to {TARGET}...")
    pkts = [
        IP(dst=TARGET) /
        TCP(sport=RandShort(), dport=80, flags="S", seq=1000)
        for _ in range(count)
    ]
    send(pkts, verbose=False)
    print(f"[SYN FLOOD] Done — {count} SYN packets sent.")
    print("[SYN FLOOD] Check your dashboard — should show HIGH severity SYN Flood alert.")

# ── Attack 2: Port Scan ───────────────────────────────────────────────────────
def port_scan(start=1, end=200):
    print(f"\n[PORT SCAN] Scanning ports {start}-{end} on {TARGET}...")
    pkts = [
        IP(dst=TARGET) /
        TCP(sport=RandShort(), dport=port, flags="S")
        for port in range(start, end + 1)
    ]
    send(pkts, verbose=False)
    print(f"[PORT SCAN] Done — {end - start + 1} ports scanned.")
    print("[PORT SCAN] Check your dashboard — should show Port Scan alert.")

# ── Attack 3: ICMP Flood ──────────────────────────────────────────────────────
def icmp_flood(count=400):
    print(f"\n[ICMP FLOOD] Sending {count} ICMP ping packets to {TARGET}...")
    pkts = [
        IP(dst=TARGET) / ICMP()
        for _ in range(count)
    ]
    send(pkts, verbose=False)
    print(f"[ICMP FLOOD] Done — {count} ICMP packets sent.")
    print("[ICMP FLOOD] Check your dashboard — should show ICMP Flood alert.")

# ── Attack 4: Volumetric DoS ──────────────────────────────────────────────────
def volumetric_dos(count=600):
    print(f"\n[VOLUMETRIC DoS] Sending {count} UDP packets to {TARGET}...")
    pkts = [
        IP(dst=TARGET) /
        UDP(sport=RandShort(), dport=RandShort()) /
        b"X" * 64
        for _ in range(count)
    ]
    send(pkts, verbose=False)
    print(f"[VOLUMETRIC DoS] Done — {count} UDP packets sent.")
    print("[VOLUMETRIC DoS] Check your dashboard — should show Volumetric DoS alert.")

# ── Attack 5: Full demo sequence ──────────────────────────────────────────────
def full_demo():
    print("\n[FULL DEMO] Running all attacks in sequence...")
    print("[FULL DEMO] Watch your dashboard — alerts will appear within 10 seconds each.\n")

    attacks = [
        ("SYN Flood",      syn_flood),
        ("Port Scan",      port_scan),
        ("ICMP Flood",     icmp_flood),
        ("Volumetric DoS", volumetric_dos),
    ]

    for name, fn in attacks:
        print(f"━━━ Starting {name} ━━━")
        fn()
        print(f"━━━ Waiting 12 seconds for sniffer window to close... ━━━")
        for i in range(12, 0, -1):
            print(f"    Next attack in {i}s...", end="\r")
            time.sleep(1)
        print()

    print("\n[FULL DEMO] All attacks complete!")
    print("[FULL DEMO] Open your dashboard to see all 4 attack types detected.")

# ── Main menu ─────────────────────────────────────────────────────────────────
def main():
    print("\n" + "="*50)
    print("  ADAPTIVE NIDS — Live Attack Demonstrator")
    print("  Make sure sniffer.py is running first!")
    print("="*50)

    while True:
        print(MENU)
        choice = input("Enter choice (0-5): ").strip()

        if choice == "1":
            syn_flood()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            icmp_flood()
        elif choice == "4":
            volumetric_dos()
        elif choice == "5":
            full_demo()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Enter 0-5.")

        print("\n✅ Attack sent! Check your Railway dashboard now.")
        print("   Alerts appear within 10 seconds (one sniffer window).")

if __name__ == "__main__":
    main()
