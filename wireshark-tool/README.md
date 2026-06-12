# net-intel

Passive network intelligence tool built on top of Wireshark/tshark.

Two modes: analyze an existing pcap file, or capture live on an interface.

Extracts credentials, maps devices, tracks DNS queries, and flags suspicious traffic — all automatically, no manual filters needed.

## What it finds

- Cleartext credentials from HTTP Basic Auth, FTP, Telnet, SMTP
- POST body credential pairs (login forms over HTTP)
- All hosts on the network with IP, MAC, vendor, hostname, and open ports
- Every DNS query and response
- Top conversations by traffic volume
- Suspicious patterns: DNS tunneling, DGA domains, session cookies in cleartext

## Usage

```bash
# Analyze a pcap file
python3 net_intel.py pcap -f capture.pcap
python3 net_intel.py pcap -f capture.pcapng -o report.txt

# Live capture (requires root/sudo)
sudo python3 net_intel.py live -i eth0
sudo python3 net_intel.py live -i wlan0 -t 60 -o report.txt
```

## Requirements

Wireshark/tshark must be installed on the system.

```bash
# macOS
brew install wireshark

# Linux
sudo apt install tshark

# Python
pip install -r requirements.txt
```

## Notes

- Live capture requires root privileges
- For best results on pcap analysis, use files captured in promiscuous mode
- Credentials are only extracted from unencrypted protocols — HTTPS traffic will not yield passwords
