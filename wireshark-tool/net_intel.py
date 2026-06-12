#!/usr/bin/env python3

import argparse
import sys
import os
import re
import json
import base64
from collections import defaultdict
from datetime import datetime

try:
    import pyshark
except ImportError:
    print("[!] pyshark not installed: pip install pyshark")
    sys.exit(1)

# ─── Data stores ─────────────────────────────────────────────────────────────

hosts = {}          # ip -> {mac, hostname, ports, vendor, packets}
credentials = []    # {protocol, src, dst, user, password, info}
dns_queries = []    # {src, query, response, type}
conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
suspicious = []

# ─── Helpers ─────────────────────────────────────────────────────────────────

OUI_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1b:21": "Intel",
    "3c:5a:b4": "Google Chromecast",
    "ac:de:48": "Apple",
    "f8:ff:c2": "Apple",
    "00:17:88": "Philips Hue",
}

def get_vendor(mac):
    if not mac:
        return "Unknown"
    prefix = mac[:8].lower().replace("-", ":")
    for oui, vendor in OUI_VENDORS.items():
        if prefix.startswith(oui):
            return vendor
    return "Unknown"

def register_host(ip, mac=None, hostname=None, port=None):
    if not ip or ip.startswith("224.") or ip == "255.255.255.255":
        return
    if ip not in hosts:
        hosts[ip] = {"mac": None, "hostname": None, "ports": set(), "vendor": "Unknown", "packets": 0}
    if mac and not hosts[ip]["mac"]:
        hosts[ip]["mac"] = mac
        hosts[ip]["vendor"] = get_vendor(mac)
    if hostname and not hosts[ip]["hostname"]:
        hosts[ip]["hostname"] = hostname
    if port:
        hosts[ip]["ports"].add(port)
    hosts[ip]["packets"] += 1

def flag_suspicious(reason, src, dst, detail=""):
    suspicious.append({"reason": reason, "src": src, "dst": dst, "detail": detail})

# ─── Protocol parsers ─────────────────────────────────────────────────────────

def parse_http(pkt, src, dst):
    try:
        http = pkt.http
        # Basic Auth
        if hasattr(http, "authorization"):
            auth = http.authorization
            if auth.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="ignore")
                    if ":" in decoded:
                        user, password = decoded.split(":", 1)
                        credentials.append({
                            "protocol": "HTTP Basic Auth",
                            "src": src, "dst": dst,
                            "user": user, "password": password,
                            "info": getattr(http, "request_uri", "")
                        })
                except Exception:
                    pass

        # POST body with credentials
        if hasattr(http, "file_data"):
            body = http.file_data
            for pattern in [
                r"(?:user(?:name)?|login|email)[=:]([^&\s]+).*?(?:pass(?:word)?|pwd)[=:]([^&\s]+)",
                r"(?:pass(?:word)?|pwd)[=:]([^&\s]+).*?(?:user(?:name)?|login|email)[=:]([^&\s]+)",
            ]:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    credentials.append({
                        "protocol": "HTTP POST",
                        "src": src, "dst": dst,
                        "user": m.group(1), "password": m.group(2),
                        "info": getattr(http, "request_uri", "")
                    })

        # Interesting headers
        if hasattr(http, "cookie") and "session" in http.cookie.lower():
            flag_suspicious("Session cookie in cleartext HTTP", src, dst, http.cookie[:80])

    except Exception:
        pass

def parse_ftp(pkt, src, dst):
    try:
        ftp = pkt.ftp
        request = getattr(ftp, "request_command", "").upper()
        arg = getattr(ftp, "request_arg", "")

        if request == "USER":
            parse_ftp._pending_user = (src, dst, arg)
        elif request == "PASS" and hasattr(parse_ftp, "_pending_user"):
            prev_src, prev_dst, user = parse_ftp._pending_user
            credentials.append({
                "protocol": "FTP",
                "src": prev_src, "dst": prev_dst,
                "user": user, "password": arg,
                "info": ""
            })
            del parse_ftp._pending_user
    except Exception:
        pass

parse_ftp._pending_user = None

def parse_telnet(pkt, src, dst):
    try:
        data = pkt.telnet.data if hasattr(pkt.telnet, "data") else ""
        if data:
            parse_telnet._buffer[src] = parse_telnet._buffer.get(src, "") + data
            buf = parse_telnet._buffer[src]
            m = re.search(r"login:\s*(\S+).*?Password:\s*(\S+)", buf, re.IGNORECASE | re.DOTALL)
            if m:
                credentials.append({
                    "protocol": "Telnet",
                    "src": src, "dst": dst,
                    "user": m.group(1), "password": m.group(2),
                    "info": ""
                })
                parse_telnet._buffer[src] = ""
    except Exception:
        pass

parse_telnet._buffer = {}

def parse_smtp(pkt, src, dst):
    try:
        data = getattr(pkt.smtp, "req_parameter", "") or getattr(pkt.smtp, "message", "")
        if not data:
            return
        if getattr(pkt.smtp, "req_command", "").upper() == "AUTH":
            parse_smtp._auth_src = src
        if hasattr(parse_smtp, "_auth_src") and parse_smtp._auth_src == src:
            try:
                decoded = base64.b64decode(data).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 3:
                    credentials.append({
                        "protocol": "SMTP AUTH",
                        "src": src, "dst": dst,
                        "user": decoded, "password": "",
                        "info": "base64 decoded"
                    })
            except Exception:
                pass
    except Exception:
        pass

parse_smtp._auth_src = None

def parse_dns(pkt, src, dst):
    try:
        dns = pkt.dns
        qname = getattr(dns, "qry_name", None)
        rdata = getattr(dns, "a", None) or getattr(dns, "cname", None)
        qtype = getattr(dns, "qry_type", "A")

        if qname:
            dns_queries.append({
                "src": src,
                "query": qname,
                "response": rdata or "",
                "type": qtype
            })
            if rdata:
                register_host(rdata, hostname=qname)

            # DNS tunneling heuristic
            label = qname.split(".")[0] if "." in qname else qname
            if len(label) > 40:
                flag_suspicious("Possible DNS tunneling", src, dst, qname)

            # DGA heuristic - high entropy short domain
            domain_part = ".".join(qname.split(".")[-2:]) if qname.count(".") >= 1 else qname
            consonants = sum(1 for c in domain_part if c.lower() in "bcdfghjklmnpqrstvwxyz")
            if len(domain_part) > 6 and consonants / max(len(domain_part), 1) > 0.75:
                flag_suspicious("Possible DGA domain", src, dst, qname)

    except Exception:
        pass

def parse_dhcp(pkt, src, dst):
    try:
        dhcp = pkt.dhcp
        hostname = getattr(dhcp, "option_hostname", None)
        mac = getattr(pkt, "eth", None)
        mac_addr = getattr(mac, "src", None) if mac else None
        ip = getattr(dhcp, "option_requested_ip", None) or getattr(dhcp, "ip_your", None)
        if ip:
            register_host(ip, mac=mac_addr, hostname=hostname)
    except Exception:
        pass

def parse_mdns(pkt, src):
    try:
        dns = pkt.dns
        hostname = getattr(dns, "qry_name", None)
        if hostname and hostname.endswith(".local"):
            register_host(src, hostname=hostname.replace(".local", ""))
    except Exception:
        pass

# ─── Packet dispatcher ────────────────────────────────────────────────────────

def process_packet(pkt):
    try:
        src = dst = ""

        if hasattr(pkt, "ip"):
            src = pkt.ip.src
            dst = pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src = pkt.ipv6.src
            dst = pkt.ipv6.dst
        else:
            return

        mac_src = getattr(getattr(pkt, "eth", None), "src", None)
        length = int(pkt.length) if hasattr(pkt, "length") else 0

        register_host(src, mac=mac_src)
        register_host(dst)

        key = tuple(sorted([src, dst]))
        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += length

        layers = [l.layer_name for l in pkt.layers]

        if "http" in layers:
            parse_http(pkt, src, dst)
        if "ftp" in layers:
            parse_ftp(pkt, src, dst)
        if "telnet" in layers:
            parse_telnet(pkt, src, dst)
        if "smtp" in layers:
            parse_smtp(pkt, src, dst)
        if "dns" in layers:
            if dst == "224.0.0.251":
                parse_mdns(pkt, src)
            else:
                parse_dns(pkt, src, dst)
        if "dhcp" in layers or "bootp" in layers:
            parse_dhcp(pkt, src, dst)

    except Exception:
        pass

# ─── Output / Report ─────────────────────────────────────────────────────────

def print_report(output_file=None):
    lines = []

    def p(line=""):
        lines.append(line)
        print(line)

    p("=" * 60)
    p("  NET-INTEL ANALYSIS REPORT")
    p(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p("=" * 60)

    p(f"\n[HOSTS] ({len(hosts)} discovered)")
    p(f"  {'IP':<18} {'MAC':<20} {'Vendor':<18} {'Hostname':<25} {'Ports':<20} Packets")
    p("  " + "-" * 110)
    for ip, info in sorted(hosts.items()):
        ports = ", ".join(str(p_) for p_ in sorted(info["ports"])[:6]) or "-"
        p(f"  {ip:<18} {(info['mac'] or '-'):<20} {info['vendor']:<18} {(info['hostname'] or '-'):<25} {ports:<20} {info['packets']}")

    p(f"\n[CREDENTIALS] ({len(credentials)} found)")
    if credentials:
        for c in credentials:
            p(f"  [{c['protocol']}] {c['src']} -> {c['dst']}")
            p(f"    User:     {c['user']}")
            p(f"    Password: {c['password']}")
            if c["info"]:
                p(f"    Info:     {c['info']}")
            p()
    else:
        p("  None found")

    p(f"\n[DNS QUERIES] ({len(dns_queries)} total)")
    seen = set()
    for q in dns_queries:
        key = q["query"]
        if key not in seen:
            seen.add(key)
            resp = f" -> {q['response']}" if q["response"] else ""
            p(f"  {q['src']:<18} {q['type']:<6} {q['query']}{resp}")

    top_convs = sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
    p(f"\n[TOP CONVERSATIONS] (by bytes)")
    for (a, b), stats in top_convs:
        p(f"  {a:<18} <-> {b:<18}  {stats['packets']} pkts  {stats['bytes']:,} bytes")

    p(f"\n[SUSPICIOUS] ({len(suspicious)} alerts)")
    if suspicious:
        for s in suspicious:
            p(f"  [{s['reason']}] {s['src']} -> {s['dst']}")
            if s["detail"]:
                p(f"    {s['detail']}")
    else:
        p("  Nothing flagged")

    p("\n" + "=" * 60)

    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(lines))
        print(f"\n[+] Report saved to {output_file}")

# ─── Modes ────────────────────────────────────────────────────────────────────

def analyze_pcap(path, output=None):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)
    print(f"[*] Analyzing: {path}")
    cap = pyshark.FileCapture(path, keep_packets=False)
    count = 0
    for pkt in cap:
        process_packet(pkt)
        count += 1
        if count % 1000 == 0:
            print(f"    {count} packets processed...", end="\r")
    cap.close()
    print(f"\n[+] Done. {count} packets analyzed.\n")
    print_report(output)

def live_capture(interface, timeout=None, output=None):
    print(f"[*] Live capture on {interface}")
    if timeout:
        print(f"[*] Will stop after {timeout} seconds")
    print("[*] Press Ctrl+C to stop\n")
    try:
        cap = pyshark.LiveCapture(interface=interface)
        if timeout:
            cap.sniff(timeout=timeout)
            for pkt in cap._packets:
                process_packet(pkt)
        else:
            for pkt in cap.sniff_continuously():
                process_packet(pkt)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped")
    print_report(output)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Passive network intelligence - credential extraction, host mapping, DNS analysis"
    )
    sub = parser.add_subparsers(dest="mode")

    p_pcap = sub.add_parser("pcap", help="Analyze a pcap file")
    p_pcap.add_argument("-f", "--file", required=True, help="Path to .pcap / .pcapng file")
    p_pcap.add_argument("-o", "--output", help="Save report to text file")

    p_live = sub.add_parser("live", help="Live capture on an interface")
    p_live.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0, wlan0)")
    p_live.add_argument("-t", "--timeout", type=int, help="Stop after N seconds")
    p_live.add_argument("-o", "--output", help="Save report to text file")

    args = parser.parse_args()

    if args.mode == "pcap":
        analyze_pcap(args.file, args.output)
    elif args.mode == "live":
        live_capture(args.interface, args.timeout, args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
