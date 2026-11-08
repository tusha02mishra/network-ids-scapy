#!/usr/bin/env python3
"""
Packet Sniffer + ARP Spoof Detection + Port Scan Detection
-------------------------------------------------------------
1) ARP spoof detection: live IP -> MAC table. If an IP that we've
   already seen suddenly shows up with a DIFFERENT MAC in a later
   ARP reply, that's flagged as possible ARP spoofing / MITM.

2) Port scan detection: tracks, per source IP, how many DISTINCT
   destination ports received a SYN packet within a rolling time
   window. Crossing a threshold (default 15 ports / 5 seconds) is
   flagged as a probable port scan.

Usage:
    sudo python3 packet_sniffer_arp.py -i eth0
    sudo python3 packet_sniffer_arp.py -i eth0 -f "arp"     # ARP-only
    sudo python3 packet_sniffer_arp.py -i eth0 -c 100
    sudo python3 packet_sniffer_arp.py -i eth0 --scan-threshold 10 --scan-window 3

Test this safely ONLY on an isolated lab network you own (e.g. VMware
VMnet1 host-only network with two VMs) — never on a shared/production
network without explicit authorization.
"""

import argparse
import time
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, ICMP, Ether, DNS, DNSQR


# --- Global state: tracks the most recent MAC we've seen for each IP ---
# Format: { "192.168.175.10": "aa:bb:cc:dd:ee:ff" }
ip_mac_table = {}

# --- Global state: tracks SYN activity per source IP for scan detection ---
# Format: { "192.168.175.128": {"ports": {80, 443, ...}, "first_seen": <epoch time>} }
scan_tracker = {}

# --- Tracks which source IPs we've already alerted on, so we don't spam ---
already_alerted = set()

# --- Global state: tracks DNS query activity per source IP ---
# Format: { "192.168.175.128": {"queries": [(domain, epoch_time), ...], "first_seen": <epoch time>} }
dns_tracker = {}

# --- Tracks which source IPs we've already alerted on for DNS volume ---
dns_already_alerted = set()

# --- Configurable detection parameters (set from CLI args in main()) ---
SCAN_PORT_THRESHOLD = 15   # distinct ports within the window that trigger an alert
SCAN_TIME_WINDOW = 5       # seconds
DNS_QUERY_THRESHOLD = 20   # queries within the window that trigger a volume alert
DNS_TIME_WINDOW = 5        # seconds
DNS_LENGTH_THRESHOLD = 50  # characters — domain names longer than this are flagged immediately


def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")


def check_arp_spoofing(arp_layer):
    """
    Inspect an ARP packet and update/compare against our IP->MAC table.
    Only ARP REPLIES (op=2) are meaningful here — requests ("who has X?")
    don't assert an IP->MAC binding, replies do ("X is at this MAC").
    """
    if arp_layer.op != 2:  # 2 = is-at (reply)
        return

    src_ip = arp_layer.psrc
    src_mac = arp_layer.hwsrc

    if src_ip not in ip_mac_table:
        # First time seeing this IP — record it, nothing suspicious yet
        ip_mac_table[src_ip] = src_mac
        log(f"ARP     Learned mapping: {src_ip:<15} -> {src_mac}")
        return

    known_mac = ip_mac_table[src_ip]

    if known_mac != src_mac:
        # The same IP is now claiming a DIFFERENT MAC address.
        # This is the classic ARP spoofing signature.
        log("!" * 60)
        log(f"POSSIBLE ARP SPOOFING DETECTED")
        log(f"  IP address:      {src_ip}")
        log(f"  Previously seen: {known_mac}")
        log(f"  Now claiming:    {src_mac}")
        log("!" * 60)

        # Update the table to the new value so we don't spam repeat
        # alerts for every single subsequent packet from the same
        # attacker — you may prefer to keep alerting instead; see notes.
        ip_mac_table[src_ip] = src_mac
    else:
        # Same IP, same MAC as before — normal, expected traffic
        log(f"ARP     Confirmed mapping: {src_ip:<15} -> {src_mac}")


def check_port_scan(ip_layer, tcp_layer):
    """
    Track SYN packets per source IP. If a single source hits more than
    SCAN_PORT_THRESHOLD distinct destination ports within SCAN_TIME_WINDOW
    seconds, flag it as a probable port scan.
    """
    # A SYN scan sends packets with ONLY the SYN flag set (no ACK).
    # tcp_layer.flags is a FlagValue object; 'S' in it means SYN is set.
    # We specifically want SYN-only (a fresh connection attempt), so we
    # exclude SYN-ACK replies (flags == 'SA') which are legitimate responses.
    if tcp_layer.flags != "S":
        return

    src_ip = ip_layer.src
    dst_port = tcp_layer.dport
    now = time.time()

    if src_ip not in scan_tracker:
        # First SYN we've seen from this source — start a fresh window
        scan_tracker[src_ip] = {"ports": {dst_port}, "first_seen": now}
        return

    entry = scan_tracker[src_ip]

    # If the tracking window has expired, reset it — this source gets a
    # clean slate (avoids permanently flagging a source based on old activity)
    if now - entry["first_seen"] > SCAN_TIME_WINDOW:
        scan_tracker[src_ip] = {"ports": {dst_port}, "first_seen": now}
        already_alerted.discard(src_ip)  # allow re-alerting in a new window
        return

    # Still within the window — record this port
    entry["ports"].add(dst_port)

    # Check threshold, but only alert once per source per window
    if len(entry["ports"]) >= SCAN_PORT_THRESHOLD and src_ip not in already_alerted:
        log("#" * 60)
        log(f"POSSIBLE PORT SCAN DETECTED")
        log(f"  Source IP:        {src_ip}")
        log(f"  Distinct ports:   {len(entry['ports'])} within {SCAN_TIME_WINDOW}s")
        log(f"  Ports seen:       {sorted(entry['ports'])}")
        log("#" * 60)
        already_alerted.add(src_ip)


def check_dns_anomaly(ip_layer, dns_layer):
    """
    Two independent checks on DNS queries:
      1) Volume: too many distinct queries from one source in a short window
         (classic DGA-malware / recon behavior).
      2) Length: an unusually long domain name in a single query
         (classic DNS-tunneling signature — real domains are short).
    """
    # DNS packets can be queries (qr=0) or responses (qr=1) — we only
    # want to inspect queries, since that's where a source is asking
    # for something, which is what both anomaly types are about.
    if dns_layer.qr != 0:
        return

    # A query can technically have zero question records; guard against that.
    if dns_layer.qdcount == 0 or dns_layer.qd is None:
        return

    # qname is the domain being looked up, e.g. b'www.google.com.'
    domain = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
    src_ip = ip_layer.src
    now = time.time()

    # --- Rule 2: Length check (no time window needed, immediate signal) ---
    if len(domain) > DNS_LENGTH_THRESHOLD:
        log("*" * 60)
        log(f"POSSIBLE DNS TUNNELING DETECTED (long domain name)")
        log(f"  Source IP:     {src_ip}")
        log(f"  Domain length: {len(domain)} chars")
        log(f"  Domain:        {domain}")
        log("*" * 60)

    # --- Rule 1: Volume check (same time-window pattern as port scans) ---
    if src_ip not in dns_tracker:
        dns_tracker[src_ip] = {"queries": [(domain, now)], "first_seen": now}
        return

    entry = dns_tracker[src_ip]

    if now - entry["first_seen"] > DNS_TIME_WINDOW:
        # Window expired — reset for a clean slate
        dns_tracker[src_ip] = {"queries": [(domain, now)], "first_seen": now}
        dns_already_alerted.discard(src_ip)
        return

    entry["queries"].append((domain, now))

    if len(entry["queries"]) >= DNS_QUERY_THRESHOLD and src_ip not in dns_already_alerted:
        log("*" * 60)
        log(f"POSSIBLE DNS ANOMALY DETECTED (high query volume)")
        log(f"  Source IP:      {src_ip}")
        log(f"  Query count:    {len(entry['queries'])} within {DNS_TIME_WINDOW}s")
        recent_domains = [q[0] for q in entry["queries"][-5:]]
        log(f"  Recent domains: {recent_domains}")
        log("*" * 60)
        dns_already_alerted.add(src_ip)


def describe_packet(pkt):
    """Extract and print basic info from a captured packet."""
    timestamp = datetime.now().strftime("%H:%M:%S")

    # --- ARP packets (no IP layer) ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
        print(f"[{timestamp}] ARP     {arp.psrc:<15} -> {arp.pdst:<15} ({op}) hwsrc={arp.hwsrc}")

        # Run spoof-detection logic on every ARP packet observed
        check_arp_spoofing(arp)
        return

    # --- IP-based packets ---
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            print(f"[{timestamp}] TCP     {src_ip}:{sport:<5} -> {dst_ip}:{dport:<5} flags={flags}")

            # Run scan-detection logic on every TCP packet observed
            check_port_scan(ip_layer, tcp)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            print(f"[{timestamp}] UDP     {src_ip}:{sport:<5} -> {dst_ip}:{dport:<5}")

            # DNS runs over UDP (typically port 53) — check for the DNS layer
            if pkt.haslayer(DNS):
                check_dns_anomaly(ip_layer, pkt[DNS])

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            print(f"[{timestamp}] ICMP    {src_ip:<15} -> {dst_ip:<15} type={icmp.type} code={icmp.code}")

        else:
            print(f"[{timestamp}] IP({ip_layer.proto}) {src_ip:<15} -> {dst_ip:<15}")
        return

    # --- IPv6 packets (separate class from IP in Scapy) ---
    if pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        src_ip, dst_ip = ipv6.src, ipv6.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            print(f"[{timestamp}] TCP6    {src_ip}:{tcp.sport:<5} -> {dst_ip}:{tcp.dport:<5} flags={tcp.flags}")
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            print(f"[{timestamp}] UDP6    {src_ip}:{udp.sport:<5} -> {dst_ip}:{udp.dport:<5}")
        else:
            print(f"[{timestamp}] IPv6({ipv6.nh}) {src_ip} -> {dst_ip}")
        return

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"[{timestamp}] ETH     {eth.src} -> {eth.dst} (type={hex(eth.type)})")


def main():
    parser = argparse.ArgumentParser(description="Packet sniffer with ARP spoof detection")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'arp' to watch ARP only")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--scan-threshold", type=int, default=15,
                         help="Distinct ports within the window that trigger a port-scan alert (default: 15)")
    parser.add_argument("--scan-window", type=int, default=5,
                         help="Time window in seconds for port-scan tracking (default: 5)")
    parser.add_argument("--dns-threshold", type=int, default=20,
                         help="Query count within the window that triggers a DNS volume alert (default: 20)")
    parser.add_argument("--dns-window", type=int, default=5,
                         help="Time window in seconds for DNS volume tracking (default: 5)")
    parser.add_argument("--dns-length", type=int, default=50,
                         help="Domain name length (chars) that triggers a tunneling alert (default: 50)")
    args = parser.parse_args()

    global SCAN_PORT_THRESHOLD, SCAN_TIME_WINDOW, DNS_QUERY_THRESHOLD, DNS_TIME_WINDOW, DNS_LENGTH_THRESHOLD
    SCAN_PORT_THRESHOLD = args.scan_threshold
    SCAN_TIME_WINDOW = args.scan_window
    DNS_QUERY_THRESHOLD = args.dns_threshold
    DNS_TIME_WINDOW = args.dns_window
    DNS_LENGTH_THRESHOLD = args.dns_length

    print("Starting packet capture with ARP spoof + port scan + DNS anomaly detection... (Ctrl+C to stop)")
    if args.iface:
        print(f"Interface: {args.iface}")
    if args.filter:
        print(f"Filter: {args.filter}")
    print("-" * 70)

    try:
        sniff(
            iface=args.iface if args.iface else None,
            filter=args.filter if args.filter else None,
            prn=describe_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        print(f"\nFinal known IP -> MAC table ({len(ip_mac_table)} entries):")
        for ip, mac in ip_mac_table.items():
            print(f"  {ip:<15} -> {mac}")

        print(f"\nSources flagged for port scanning ({len(already_alerted)} entries):")
        for ip in already_alerted:
            ports = scan_tracker.get(ip, {}).get("ports", set())
            print(f"  {ip:<15} -> {len(ports)} distinct ports")

        print(f"\nSources flagged for DNS anomalies ({len(dns_already_alerted)} entries):")
        for ip in dns_already_alerted:
            queries = dns_tracker.get(ip, {}).get("queries", [])
            print(f"  {ip:<15} -> {len(queries)} queries in window")


if __name__ == "__main__":
    main()