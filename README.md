# Network IDS and Packet Sniffer Using Scapy

A Python-based network packet sniffer and lightweight Intrusion Detection System (IDS) developed using Scapy.

This project captures and analyzes network traffic in real time to monitor communication and identify potentially suspicious network activity.

## Features

- Real-time packet capture and monitoring
- TCP, UDP, ICMP, IPv4, IPv6, and ARP packet inspection
- Source and destination IP address monitoring
- TCP and UDP port identification
- ARP spoofing detection using IP-to-MAC mapping
- TCP SYN-based port scan detection
- DNS anomaly detection based on query volume
- Potential DNS tunneling detection using unusually long domain names
- Configurable packet filters and detection thresholds

## Technologies Used

- Python
- Scapy
- Kali Linux
- VMware Workstation
- Windows

## Lab Setup

The project is designed for testing in an isolated VMware host-only network.

| Component | Description |
|---|---|
| Monitoring Machine | Kali Linux |
| Target Machine | Windows |
| Virtualization | VMware Workstation |
| Network | Host-only |
| Packet Capture Library | Scapy |

The lab environment allows packet monitoring and security testing between virtual machines without exposing experiments to an external network.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/network-ids-scapy.git
cd network-ids-scapy
```

Install the required dependency:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Packet Sniffer

```bash
sudo python3 packet_sniffer.py -i eth0
```

### Network IDS

```bash
sudo python3 network_ids.py -i eth0
```

### Capture ARP Traffic

```bash
sudo python3 network_ids.py -i eth0 -f "arp"
```

### Capture a Limited Number of Packets

```bash
sudo python3 network_ids.py -i eth0 -c 100
```

### Configure Port Scan Detection

```bash
sudo python3 network_ids.py -i eth0 --scan-threshold 10 --scan-window 3
```

Press `Ctrl+C` to stop packet capture.

Replace `eth0` with the appropriate network interface.

## Detection Mechanisms

### ARP Spoofing Detection

Maintains an IP-to-MAC mapping and generates an alert when an IP address is observed with a different MAC address.

### Port Scan Detection

Tracks TCP SYN packets and identifies a source IP accessing multiple distinct destination ports within a configurable time window.

### DNS Anomaly Detection

Monitors DNS query volume and identifies unusually long domain names that may indicate suspicious activity.

## Screenshots

Screenshots of packet capture and detection alerts will be added here.

## Limitations

- Detection is based on heuristic rules and may generate false positives.
- Legitimate IP-to-MAC changes may trigger ARP alerts.
- Detection accuracy depends on network visibility and threshold configuration.

## Future Improvements

- Logging alerts to files
- Exporting alerts to JSON or CSV
- Improving detection accuracy
- Developing a graphical dashboard
- Integration with SIEM platforms such as Wazuh or Splunk

## Disclaimer

For use only in an isolated lab on machines you own.

This project is intended for educational and defensive cybersecurity research.
