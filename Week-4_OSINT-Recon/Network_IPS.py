#Intrusion Prevention System (IPS) using Scapy
# Blocks ICMP floods, SYN floods, port scans, and SQLi in HTTP requests

from scapy.all import rdpcap, IP, TCP, ICMP, Raw
from collections import defaultdict
import re

# ---- Simple detection thresholds ----
ICMP_THRESHOLD = 20       # more than 20 pings
SYN_THRESHOLD = 50        # more than 50 SYNs
SCAN_PORTS = 15           # touching >15 ports quickly
BLOCKLIST = set()         # blocked IPs

# Simple SQL injection pattern
SQLI_PATTERN = re.compile(rb"(UNION|SELECT|OR 1=1|DROP TABLE)", re.I)


def process_pcap(filename):
    packets = rdpcap(filename)
    icmp_count = defaultdict(int)
    syn_count = defaultdict(int)
    ports_seen = defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src

        # Drop if already blocked
        if src in BLOCKLIST:
            continue

        # ICMP ping flood
        if ICMP in pkt:
            icmp_count[src] += 1
            if icmp_count[src] > ICMP_THRESHOLD:
                print(f"[BLOCK] {src} - ICMP flood detected")
                BLOCKLIST.add(src)

        # TCP rules
        if TCP in pkt:
            tcp = pkt[TCP]

            # SYN flood
            if tcp.flags == "S":
                syn_count[src] += 1
                if syn_count[src] > SYN_THRESHOLD:
                    print(f"[BLOCK] {src} - SYN flood detected")
                    BLOCKLIST.add(src)

            # Port scan detection (many ports)
            ports_seen[src].add(tcp.dport)
            if len(ports_seen[src]) > SCAN_PORTS:
                print(f"[BLOCK] {src} - Port scan detected")
                BLOCKLIST.add(src)

            # HTTP SQLi detection
            if Raw in pkt and (tcp.dport == 80 or tcp.sport == 80):
                data = pkt[Raw].load
                if SQLI_PATTERN.search(data):
                    print(f"[BLOCK] {src} - Suspicious HTTP SQLi")
                    BLOCKLIST.add(src)

    print("\nFinal Blocklist:", BLOCKLIST)


if __name__ == "__main__":
    # Example usage: run on a pcap
    process_pcap("malicious.pcap")
