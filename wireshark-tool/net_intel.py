#!/usr/bin/env python3

import argparse
import sys
import os
import re
import json
import base64
import subprocess
import shutil
import urllib.request
from collections import defaultdict
from datetime import datetime

TSHARK = shutil.which("tshark")
OUI_CACHE = os.path.join(os.path.dirname(__file__), ".oui_cache.txt")

# ─── Colors ───────────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def col(text, color):
    return f"{color}{text}{C.RESET}"

def strip_color(text):
    return re.sub(r"\033\[[0-9;]+m", "", text)
OUI_URLS = [
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf",
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf",
    "https://www.wireshark.org/download/automated/data/manuf",
]

# ─── OUI database ─────────────────────────────────────────────────────────────

_oui_db = {}

def load_oui():
    global _oui_db
    if _oui_db:
        return

    if not os.path.exists(OUI_CACHE):
        print("[*] Downloading OUI database...")
        downloaded = False
        for url in OUI_URLS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read().decode("utf-8", errors="ignore")
                with open(OUI_CACHE, "w") as f:
                    f.write(data)
                print("[+] OUI database cached\n")
                downloaded = True
                break
            except Exception:
                continue
        if not downloaded:
            print("[!] Could not download OUI database, vendor info will be limited\n")
            return

    with open(OUI_CACHE, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                prefix = parts[0].strip().lower().replace("-", ":")[:8]
                vendor = parts[2].strip() if len(parts) > 2 else parts[1].strip()
                _oui_db[prefix] = vendor

def get_vendor(mac):
    if not mac:
        return "-"
    clean = mac.lower().replace("-", ":").replace(".", ":")
    if len(clean) < 8:
        return "-"
    prefix = clean[:8]
    return _oui_db.get(prefix, "Unknown")

# ─── TTL fingerprinting ────────────────────────────────────────────────────────

def guess_os(ttl):
    if not ttl:
        return "-"
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux/Android/iOS/macOS"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network device"
    return "-"

# ─── Data stores ─────────────────────────────────────────────────────────────

hosts = {}
credentials = []
dns_queries = []
conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
suspicious = []

def register_host(ip, mac=None, hostname=None, port=None, ttl=None, user_agent=None, dhcp_vendor=None):
    if not ip or ip.startswith("224.") or ip in ("255.255.255.255", "0.0.0.0"):
        return
    if ip not in hosts:
        hosts[ip] = {
            "mac": None, "hostname": None, "ports": set(),
            "vendor": "-", "os_guess": "-", "user_agent": None,
            "dhcp_vendor": None, "packets": 0
        }
    h = hosts[ip]
    if mac and not h["mac"]:
        h["mac"] = mac
        h["vendor"] = get_vendor(mac)
    if hostname and not h["hostname"]:
        h["hostname"] = hostname
    if port:
        h["ports"].add(int(port))
    if ttl and h["os_guess"] == "-":
        h["os_guess"] = guess_os(ttl)
    if user_agent and not h["user_agent"]:
        h["user_agent"] = user_agent[:80]
    if dhcp_vendor and not h["dhcp_vendor"]:
        h["dhcp_vendor"] = dhcp_vendor
    h["packets"] += 1

def flag_suspicious(reason, src, dst, detail=""):
    suspicious.append({"reason": reason, "src": src, "dst": dst, "detail": detail})

# ─── tshark field extraction ──────────────────────────────────────────────────

FIELDS = [
    "frame.number",
    "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst",
    "eth.src", "eth.dst",
    "ip.ttl",
    "frame.len",
    "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.qry.type", "dns.a", "dns.cname",
    "http.authorization",
    "http.file_data",
    "http.request.uri",
    "http.user_agent",
    "ftp.request.command", "ftp.request.arg",
    "smtp.req.command", "smtp.req.parameter",
    "dhcp.option.hostname", "dhcp.option.vendor_class_id",
    "bootp.option.hostname",
    "nbns.name",
]

def run_tshark(source, is_live=False, interface=None, timeout=None):
    if not TSHARK:
        print("[!] tshark not found. Install Wireshark/tshark first.")
        sys.exit(1)

    cmd = ["tshark", "-n", "-T", "fields", "-E", "separator=|", "-E", "occurrence=f", "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]

    if is_live:
        cmd += ["-i", interface]
        if timeout:
            cmd += ["-a", f"duration:{timeout}"]
    else:
        cmd += ["-r", source]

    return cmd

def parse_line(line):
    parts = line.strip().split("|")
    if len(parts) < len(FIELDS):
        parts += [""] * (len(FIELDS) - len(parts))

    def g(name):
        try:
            return parts[FIELDS.index(name)].strip()
        except (ValueError, IndexError):
            return ""

    src = g("ip.src") or g("ipv6.src")
    dst = g("ip.dst") or g("ipv6.dst")
    mac_src = g("eth.src")
    mac_dst = g("eth.dst")
    ttl = g("ip.ttl")
    length = g("frame.len")
    tcp_sp = g("tcp.srcport")
    tcp_dp = g("tcp.dstport")
    udp_sp = g("udp.srcport")
    udp_dp = g("udp.dstport")

    dns_name = g("dns.qry.name")
    dns_type = g("dns.qry.type")
    dns_a = g("dns.a") or g("dns.cname")

    http_auth = g("http.authorization")
    http_body = g("http.file_data")
    http_uri = g("http.request.uri")
    http_ua = g("http.user_agent")

    ftp_cmd = g("ftp.request.command").upper()
    ftp_arg = g("ftp.request.arg")

    smtp_cmd = g("smtp.req.command").upper()
    smtp_arg = g("smtp.req.parameter")

    dhcp_host = g("dhcp.option.hostname") or g("bootp.option.hostname")
    dhcp_vendor = g("dhcp.option.vendor_class_id")

    nbns = g("nbns.name")


    # Register hosts
    if src:
        port = tcp_sp or udp_sp or None
        register_host(src, mac=mac_src, ttl=ttl, port=port, user_agent=http_ua or None)
    if dst:
        port = tcp_dp or udp_dp or None
        register_host(dst, mac=mac_dst, port=port)

    # DHCP
    if dhcp_host and src:
        register_host(src, hostname=dhcp_host, dhcp_vendor=dhcp_vendor or None)

    # NBNS (Windows NetBIOS name)
    if nbns and src:
        register_host(src, hostname=nbns.strip().rstrip("\x00"))

    # Conversations
    if src and dst:
        key = tuple(sorted([src, dst]))
        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += int(length) if length.isdigit() else 0

    # DNS
    if dns_name:
        dns_queries.append({"src": src, "query": dns_name, "response": dns_a, "type": dns_type})
        if dns_a:
            register_host(dns_a, hostname=dns_name)
        # DNS tunneling heuristic
        label = dns_name.split(".")[0] if "." in dns_name else dns_name
        if len(label) > 40:
            flag_suspicious("Possible DNS tunneling", src, dst, dns_name)
        # DGA heuristic
        if dns_name.count(".") >= 1:
            domain_part = ".".join(dns_name.split(".")[-2:])
            consonants = sum(1 for c in domain_part if c.lower() in "bcdfghjklmnpqrstvwxyz")
            if len(domain_part) > 8 and consonants / max(len(domain_part), 1) > 0.78:
                flag_suspicious("Possible DGA domain", src, dst, dns_name)

    # HTTP Basic Auth
    if http_auth and http_auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(http_auth[6:]).decode("utf-8", errors="ignore")
            if ":" in decoded:
                user, password = decoded.split(":", 1)
                credentials.append({
                    "protocol": "HTTP Basic Auth", "src": src, "dst": dst,
                    "user": user, "password": password, "info": http_uri
                })
        except Exception:
            pass

    # HTTP POST body
    if http_body:
        for pattern in [
            r"(?:user(?:name)?|login|email)[=:]([^&\s]{1,60}).*?(?:pass(?:word)?|pwd)[=:]([^&\s]{1,60})",
            r"(?:pass(?:word)?|pwd)[=:]([^&\s]{1,60}).*?(?:user(?:name)?|login|email)[=:]([^&\s]{1,60})",
        ]:
            m = re.search(pattern, http_body, re.IGNORECASE)
            if m:
                credentials.append({
                    "protocol": "HTTP POST", "src": src, "dst": dst,
                    "user": m.group(1), "password": m.group(2), "info": http_uri
                })

    # FTP
    if ftp_cmd == "USER":
        parse_line._ftp_user[src] = ftp_arg
    elif ftp_cmd == "PASS" and src in parse_line._ftp_user:
        credentials.append({
            "protocol": "FTP", "src": src, "dst": dst,
            "user": parse_line._ftp_user.pop(src), "password": ftp_arg, "info": ""
        })

    # SMTP AUTH
    if smtp_cmd == "AUTH":
        parse_line._smtp_auth[src] = True
    if smtp_arg and parse_line._smtp_auth.get(src):
        try:
            decoded = base64.b64decode(smtp_arg).decode("utf-8", errors="ignore")
            if decoded and len(decoded) > 2:
                credentials.append({
                    "protocol": "SMTP AUTH", "src": src, "dst": dst,
                    "user": decoded, "password": "", "info": "base64"
                })
                parse_line._smtp_auth.pop(src, None)
        except Exception:
            pass

parse_line._ftp_user = {}
parse_line._smtp_auth = {}

# ─── Report ───────────────────────────────────────────────────────────────────

def host_color(h):
    if h["hostname"] and h["mac"] and h["os_guess"] != "-":
        return C.GREEN
    if h["hostname"] or h["vendor"] != "-":
        return C.CYAN
    return C.GRAY

def print_report(output_file=None):
    screen_lines = []
    file_lines = []

    def p(line=""):
        screen_lines.append(line)
        file_lines.append(strip_color(line))
        print(line)

    # Legend
    p(col("=" * 70, C.BOLD))
    p(col("  NET-INTEL REPORT", C.BOLD))
    p(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p(col("=" * 70, C.BOLD))
    p()
    p(col("  COLOR LEGEND:", C.BOLD))
    p(f"  {col('GREEN',   C.GREEN)}   - Host fully identified (IP + MAC + hostname + OS)")
    p(f"  {col('CYAN',    C.CYAN)}    - Host partially identified (some info available)")
    p(f"  {col('GRAY',    C.GRAY)}    - Host with minimal info (IP only)")
    p(f"  {col('RED',     C.RED)}     - Credentials found / critical finding")
    p(f"  {col('YELLOW',  C.YELLOW)}  - Suspicious activity / alert")
    p(f"  {col('MAGENTA', C.MAGENTA)} - Device / OS fingerprint detail")
    p(f"  {col('BLUE',    C.BLUE)}    - Top conversations")
    p()

    # Hosts
    p(col(f"[HOSTS] ({len(hosts)} discovered)", C.BOLD))
    p()
    p(f"  {'IP':<20} {'MAC':<20} {'Vendor':<22} {'OS Guess':<26} {'Hostname':<28} {'DHCP Vendor':<25} Ports")
    p("  " + "-" * 160)
    for ip, h in sorted(hosts.items()):
        ports = ", ".join(str(x) for x in sorted(h["ports"])[:8]) or "-"
        color = host_color(h)
        row = (
            f"  {ip:<20} {(h['mac'] or '-'):<20} {h['vendor']:<22} "
            f"{h['os_guess']:<26} {(h['hostname'] or '-'):<28} "
            f"{(h['dhcp_vendor'] or '-'):<25} {ports}"
        )
        p(col(row, color))
        if h["user_agent"]:
            p(col(f"  {'':20} User-Agent: {h['user_agent']}", C.MAGENTA))

    # Credentials
    p()
    p(col(f"[CREDENTIALS] ({len(credentials)} found)", C.BOLD))
    p()
    if credentials:
        for c in credentials:
            p(col(f"  [{c['protocol']}]  {c['src']}  ->  {c['dst']}", C.RED))
            p(col(f"    User:     {c['user']}", C.RED))
            if c['password']:
                p(col(f"    Password: {c['password']}", C.RED))
            if c['info']:
                p(col(f"    URI:      {c['info']}", C.RED))
            p()
    else:
        p(col("  None found", C.GRAY))

    # DNS
    seen_dns = set()
    p()
    p(col(f"[DNS QUERIES] ({len(dns_queries)} total)", C.BOLD))
    p()
    for q in dns_queries:
        key = q["query"]
        if key not in seen_dns:
            seen_dns.add(key)
            resp = f"  ->  {q['response']}" if q["response"] else ""
            p(col(f"  {(q['src'] or '-'):<20} {q['type']:<6} {q['query']}{resp}", C.CYAN))

    # Top conversations
    top = sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]
    p()
    p(col(f"[TOP CONVERSATIONS] (by bytes)", C.BOLD))
    p()
    for (a, b), s in top:
        p(col(f"  {a:<22} <->  {b:<22}  {s['packets']} pkts  {s['bytes']:,} bytes", C.BLUE))

    # Suspicious
    p()
    p(col(f"[SUSPICIOUS] ({len(suspicious)} alerts)", C.BOLD))
    p()
    if suspicious:
        for s in suspicious:
            p(col(f"  [{s['reason']}]  {s['src']}  ->  {s['dst']}", C.YELLOW))
            if s["detail"]:
                p(col(f"    {s['detail']}", C.YELLOW))
    else:
        p(col("  Nothing flagged", C.GRAY))

    p()
    p(col("=" * 70, C.BOLD))

    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(file_lines))
        print(f"\n[+] Report saved to {output_file} (no colors in file)")

# ─── Modes ────────────────────────────────────────────────────────────────────

def stream_tshark(cmd, label="packets"):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )
    count = 0
    try:
        for line in proc.stdout:
            if line.strip():
                parse_line(line)
                count += 1
                if count % 5000 == 0:
                    print(f"  {count:,} {label} processed...", end="\r", flush=True)
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[*] Stopped by user")
    proc.wait()
    if count == 0:
        print(f"\n[!] No packets parsed. Check that tshark can read the file and has permissions.\n")
    print(f"  {count:,} {label} processed.   ")
    return count

def analyze_pcap(path, output=None):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)
    load_oui()
    print(f"[*] Analyzing: {path}  ({os.path.getsize(path) / 1e6:.1f} MB)\n")
    cmd = run_tshark(path)
    count = stream_tshark(cmd, "packets")
    print(f"\n[+] Done. {count:,} packets analyzed.\n")
    print_report(output)

def live_capture(interface, timeout=None, output=None):
    load_oui()
    print(f"[*] Live capture on interface: {interface}")
    if timeout:
        print(f"[*] Stopping after {timeout} seconds")
    print("[*] Press Ctrl+C to stop\n")
    cmd = run_tshark(None, is_live=True, interface=interface, timeout=timeout)
    stream_tshark(cmd, "packets")
    print_report(output)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Passive network intelligence — credentials, host mapping, device fingerprinting, DNS"
    )
    sub = parser.add_subparsers(dest="mode")

    p_pcap = sub.add_parser("pcap", help="Analyze a pcap/pcapng file")
    p_pcap.add_argument("-f", "--file", required=True, help="Path to pcap file")
    p_pcap.add_argument("-o", "--output", help="Save report to file")

    p_live = sub.add_parser("live", help="Live capture on a network interface")
    p_live.add_argument("-i", "--interface", required=True, help="Interface (e.g. eth0, wlan0)")
    p_live.add_argument("-t", "--timeout", type=int, help="Stop after N seconds")
    p_live.add_argument("-o", "--output", help="Save report to file")

    args = parser.parse_args()

    if args.mode == "pcap":
        analyze_pcap(args.file, args.output)
    elif args.mode == "live":
        live_capture(args.interface, args.timeout, args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
