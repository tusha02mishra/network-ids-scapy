#!/usr/bin/env python3
"""
Basic Packet Sniffer
---------------------
Captures live packets with Scapy and prints basic info:
source/destination IP, protocol, and port (if applicable).

This is step 1 of a network traffic analyzer / IDS prototype —
purely observational, no detection logic yet.

Usage:
    sudo python3 packet_sniffer.py                # sniff on default interface
    sudo python3 packet_sniffer.py -i eth0         # sniff on a specific interface
    sudo python3 packet_sniffer.py -f "tcp"        # apply a BPF filter
    sudo python3 packet_sniffer.py -c 50           # stop after 50 packets

Note: Requires root/administrator privileges to open raw sockets.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Ether


def describe_packet(pkt):
    """Extract and print basic info from a captured packet."""
    timestamp = datetime.now().strftime("%H:%M:%S")

    # --- ARP packets (no IP layer) ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
        print(f"[{timestamp}] ARP     {arp.psrc:<15} -> {arp.pdst:<15} ({op})")
        return

    # --- IP-based packets ---
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            print(f"[{timestamp}] {proto:<7} {src_ip}:{sport:<5} -> {dst_ip}:{dport:<5} flags={flags}")

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            sport, dport = udp.sport, udp.dport
            print(f"[{timestamp}] {proto:<7} {src_ip}:{sport:<5} -> {dst_ip}:{dport:<5}")

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            print(f"[{timestamp}] ICMP    {src_ip:<15} -> {dst_ip:<15} type={icmp.type} code={icmp.code}")

        else:
            # Some other IP protocol (e.g. GRE, ESP) — show the protocol number
            print(f"[{timestamp}] IP({ip_layer.proto}) {src_ip:<15} -> {dst_ip:<15}")
        return

    # --- Fallback: non-IP, non-ARP (e.g. raw Ethernet) ---
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"[{timestamp}] ETH     {eth.src} -> {eth.dst} (type={hex(eth.type)})")


def main():
    parser = argparse.ArgumentParser(description="Basic Scapy packet sniffer")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on (default: Scapy's default)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string, e.g. 'tcp', 'udp port 53'")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    print("Starting packet capture... (Ctrl+C to stop)")
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
            store=False,  # don't keep packets in memory, just process and discard
        )
    except PermissionError:
        print("\nPermission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
