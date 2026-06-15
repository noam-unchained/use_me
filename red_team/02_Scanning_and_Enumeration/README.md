# Scanning and Enumeration

Active phase — you are now touching the target directly.

The goal is to map what's running: open ports, services, software versions, hidden web paths, misconfigurations. This is where you figure out the attack surface before deciding how to exploit it.

Unlike recon, this generates traffic and can trigger alerts. Keep it targeted.

## Tools

| Tool | Purpose |
|------|---------|
| [cve-scanner](cve-scanner/) | Scan a host for known CVEs based on detected services |
| [dir-enum](dir-enum/) | Brute-force directories and files on web servers |
| [net-intel](net-intel/) | Passive network intelligence via tshark: hosts, credentials, DNS, suspicious traffic |