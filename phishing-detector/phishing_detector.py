#!/usr/bin/env python3
"""
Phishing Page Detector
========================
Analyzes a URL and returns a risk score (0-100) with a detailed
explanation of why it's suspicious or safe.

Checks performed:
1. Domain Analysis — age, typosquatting, suspicious TLDs, entropy
2. SSL Certificate — validity, issuer, age, self-signed
3. HTML Content — login forms, password fields, hidden inputs
4. Meta & Redirects — suspicious meta refreshes, iframe injections
5. URL Structure — excessive subdomains, encoded chars, IP-based
6. Threat Intel — checks against VirusTotal (optional API key)
7. Brand Impersonation — detects known brand lookalikes

Usage:
python phishing_detector.py
python phishing_detector.py -u https://suspicious-site.com
python phishing_detector.py -u https://site.com --vt-key YOUR_KEY
python phishing_detector.py -f urls.txt # batch mode

Requirements:
pip install -r requirements.txt
"""

import re
import sys
import ssl
import math
import socket
import argparse
import datetime
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
import urllib3
urllib3.disable_warnings()


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# Known brands commonly impersonated in phishing attacks
KNOWN_BRANDS = [
"paypal", "apple", "google", "microsoft", "amazon", "facebook",
"netflix", "instagram", "twitter", "linkedin", "dropbox", "gmail",
"yahoo", "bankofamerica", "chase", "wellsfargo", "citibank",
"dhl", "fedex", "ups", "whatsapp", "telegram", "binance",
"coinbase", "ethereum", "bitcoin", "blockchain"
]

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
".tk", ".ml", ".ga", ".cf", ".gq", # Free Namecheap TLDs
".xyz", ".top", ".club", ".online", ".site", ".space",
".buzz", ".icu", ".work", ".live", ".shop"
]

# Legitimate TLDs that phishers fake via subdomains
# e.g. paypal.com.evil-domain.tk
TRUSTED_DOMAINS = [
"paypal.com", "google.com", "microsoft.com", "apple.com",
"amazon.com", "facebook.com", "instagram.com", "twitter.com",
"linkedin.com", "netflix.com", "dropbox.com"
]

REQUEST_TIMEOUT = 8
USER_AGENT = (
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
"AppleWebKit/537.36 (KHTML, like Gecko) "
"Chrome/120.0.0.0 Safari/537.36"
)


# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────

class C:
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def red(t): return f"{C.RED}{t}{C.RESET}"
def green(t): return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def bold(t): return f"{C.BOLD}{t}{C.RESET}"
def cyan(t): return f"{C.CYAN}{t}{C.RESET}"


# ─────────────────────────────────────────────
# Risk Score Tracker
# ─────────────────────────────────────────────

class RiskScore:
def __init__(self):
self.score = 0
self.reasons = []
self.safe = []

def add(self, points, reason):
self.score += points
self.reasons.append((points, reason))

def good(self, reason):
self.safe.append(reason)

def total(self):
return min(self.score, 100)

def verdict(self):
s = self.total()
if s >= 70:
return red(" HIGH RISK — Likely Phishing")
elif s >= 40:
return yellow("️ MEDIUM RISK — Suspicious")
elif s >= 20:
return yellow(" LOW RISK — Some Concerns")
else:
return green(" LIKELY SAFE")


# ─────────────────────────────────────────────
# Check 1 — URL Structure Analysis
# ─────────────────────────────────────────────

def check_url_structure(url, parsed, risk):
"""
Analyzes the URL itself for common phishing patterns:
- IP address instead of domain name
- Excessive subdomains (e.g. secure.login.paypal.verify.evil.com)
- URL-encoded characters hiding the real destination
- Excessively long URLs
- Trusted brand names in subdomains (subdomain spoofing)
- Suspicious TLDs
- Hyphens in domain (common in phishing: paypal-secure-login.com)
"""
domain = parsed.netloc.lower()
path = parsed.path.lower()
full_url = url.lower()

# IP address instead of domain
ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
hostname = domain.split(":")[0]
if ip_pattern.match(hostname):
risk.add(30, "URL uses raw IP address instead of domain name")
else:
risk.good("Uses a domain name (not raw IP)")

# Excessive subdomains
subdomain_count = len(hostname.split(".")) - 2
if subdomain_count >= 3:
risk.add(20, f"Excessive subdomains ({subdomain_count}) — common in phishing")
elif subdomain_count >= 2:
risk.add(10, f"Multiple subdomains ({subdomain_count})")

# URL-encoded characters
decoded = unquote(url)
if decoded != url:
risk.add(15, "URL contains encoded characters — may be hiding true destination")

# URL length
if len(url) > 100:
risk.add(10, f"Unusually long URL ({len(url)} chars)")

# Brand name in subdomain (spoofing)
for brand in KNOWN_BRANDS:
if brand in hostname and not hostname.endswith(f"{brand}.com"):
risk.add(35, f"Known brand '{brand}' appears in subdomain/path — possible spoofing")
break

# Trusted domain as subdomain
for trusted in TRUSTED_DOMAINS:
trusted_base = trusted.replace(".", "\\.")
if re.search(rf"{trusted_base}\.", hostname) and not hostname.endswith(trusted):
risk.add(40, f"'{trusted}' appears as subdomain of another domain — classic phishing trick")
break

# Suspicious TLD
for tld in SUSPICIOUS_TLDS:
if hostname.endswith(tld):
risk.add(20, f"Suspicious TLD '{tld}' — commonly used in free phishing domains")
break

# Hyphens in domain
domain_part = hostname.rsplit(".", 2)[-2] if "." in hostname else hostname
if domain_part.count("-") >= 2:
risk.add(15, f"Multiple hyphens in domain '{domain_part}' — common phishing pattern")
elif "-" in domain_part:
risk.add(5, f"Hyphen in domain name")

# @ symbol in URL (redirects to different host)
if "@" in url:
risk.add(30, "URL contains '@' — browser ignores everything before it (redirect trick)")

# Double slash in path
if "//" in path:
risk.add(10, "Double slash in URL path — possible redirect abuse")


# ─────────────────────────────────────────────
# Check 2 — Domain Age & WHOIS
# ─────────────────────────────────────────────

def check_domain_age(hostname, risk):
"""
Phishing domains are almost always newly registered (days/weeks old).
Checks domain creation date via WHOIS.
"""
try:
w = whois.whois(hostname)
creation = w.creation_date

if isinstance(creation, list):
creation = creation[0]

if creation:
age_days = (datetime.datetime.now() - creation).days
if age_days < 30:
risk.add(40, f"Domain is only {age_days} days old — very suspicious")
elif age_days < 180:
risk.add(20, f"Domain is only {age_days} days old — recently registered")
elif age_days < 365:
risk.add(10, f"Domain is {age_days} days old — less than 1 year")
else:
risk.good(f"Domain is {age_days} days old — established domain")
else:
risk.add(10, "Could not determine domain age (WHOIS hidden)")

except Exception:
risk.add(10, "WHOIS lookup failed — domain may be hiding registration info")


# ─────────────────────────────────────────────
# Check 3 — SSL Certificate
# ─────────────────────────────────────────────

def check_ssl(hostname, risk):
"""
Analyzes the SSL certificate:
- Presence (no HTTPS = bad)
- Self-signed certificates
- Certificate age (newly issued = suspicious)
- Subject/issuer mismatch
Note: HTTPS alone is NOT a safety indicator — phishers use it too.
"""
try:
ctx = ssl.create_default_context()
conn = ctx.wrap_socket(
socket.create_connection((hostname, 443), timeout=5),
server_hostname=hostname
)
cert = conn.getpeercert()
conn.close()

# Check expiry
not_after = datetime.datetime.strptime(
cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
)
not_before = datetime.datetime.strptime(
cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
)

cert_age_days = (datetime.datetime.now() - not_before).days
if cert_age_days < 30:
risk.add(20, f"SSL certificate issued only {cert_age_days} days ago — newly created")
else:
risk.good(f"SSL certificate is {cert_age_days} days old")

# Check issuer
issuer = dict(x[0] for x in cert.get("issuer", []))
org = issuer.get("organizationName", "")

free_cas = ["Let's Encrypt", "ZeroSSL", "Buypass"]
if any(ca in org for ca in free_cas):
risk.add(10, f"Free SSL certificate from '{org}' — easy to obtain, used by phishers")
else:
risk.good(f"SSL issued by: {org}")

# Certificate covers the right domain?
sans = []
for ext in cert.get("subjectAltName", []):
if ext[0] == "DNS":
sans.append(ext[1])

if not any(hostname.endswith(san.lstrip("*")) for san in sans):
risk.add(25, "SSL certificate domain mismatch")
else:
risk.good("SSL certificate matches domain")

except ssl.SSLError as e:
risk.add(30, f"SSL error: {e} — invalid or self-signed certificate")
except socket.timeout:
risk.add(10, "SSL check timed out")
except ConnectionRefusedError:
risk.add(20, "No HTTPS (port 443 refused) — site does not use SSL")
except Exception as e:
risk.add(5, f"SSL check failed: {e}")


# ─────────────────────────────────────────────
# Check 4 — HTML Content Analysis
# ─────────────────────────────────────────────

def check_html_content(url, html, risk):
"""
Parses the page HTML for phishing indicators:
- Login/password forms (especially if action points elsewhere)
- Hidden input fields (used to pass stolen data)
- Disabled right-click (prevent inspection)
- External form submission to a different domain
- Iframe loading external content
- Favicon from a known brand (impersonation)
- Suspicious keywords in page text
"""
if not html:
risk.add(5, "Could not retrieve page content")
return

soup = BeautifulSoup(html, "html.parser")
parsed = urlparse(url)
domain = parsed.netloc.lower()
text = soup.get_text().lower()

# Password input fields
password_fields = soup.find_all("input", {"type": "password"})
if password_fields:
risk.add(20, f"Page contains {len(password_fields)} password input field(s)")

# Check where the form submits to
for form in soup.find_all("form"):
action = form.get("action", "")
if action and action.startswith("http"):
form_domain = urlparse(action).netloc.lower()
if form_domain and form_domain != domain:
risk.add(35, f"Form submits credentials to different domain: {form_domain}")

# Hidden input fields
hidden = soup.find_all("input", {"type": "hidden"})
if len(hidden) > 5:
risk.add(15, f"{len(hidden)} hidden input fields — may be collecting extra data")

# External iframes
iframes = soup.find_all("iframe")
for iframe in iframes:
src = iframe.get("src", "")
if src and src.startswith("http"):
iframe_domain = urlparse(src).netloc
if iframe_domain and iframe_domain != domain:
risk.add(20, f"External iframe loading from: {iframe_domain}")

# Disabled right-click / inspect
if "contextmenu" in html.lower() and "return false" in html.lower():
risk.add(15, "Page disables right-click — trying to prevent inspection")

# Suspicious page keywords
phishing_keywords = [
"verify your account", "confirm your identity", "suspended",
"unusual activity", "login to continue", "update your payment",
"your account has been", "click here to verify", "we detected",
"immediately", "unauthorized access", "security alert"
]
keyword_hits = [kw for kw in phishing_keywords if kw in text]
if len(keyword_hits) >= 3:
risk.add(20, f"Multiple phishing keywords found: {keyword_hits[:3]}")
elif keyword_hits:
risk.add(10, f"Phishing keyword found: '{keyword_hits[0]}'")

# Brand impersonation via favicon or title
title = soup.title.string.lower() if soup.title else ""
for brand in KNOWN_BRANDS:
if brand in title and brand not in domain:
risk.add(25, f"Page title mentions '{brand}' but domain doesn't match")
break

# Meta refresh redirect
for meta in soup.find_all("meta"):
if meta.get("http-equiv", "").lower() == "refresh":
content = meta.get("content", "")
if "url=" in content.lower():
risk.add(20, f"Meta refresh redirect found: {content[:60]}")

# No visible text (blank page with hidden form)
if len(text.strip()) < 50 and password_fields:
risk.add(25, "Page has almost no visible text but contains login form — hidden phishing page")


# ─────────────────────────────────────────────
# Check 5 — VirusTotal (optional)
# ─────────────────────────────────────────────

def check_virustotal(url, api_key, risk):
"""
Submits the URL to VirusTotal's API and checks how many
security vendors flagged it as malicious/phishing.
Requires a free VirusTotal API key.
"""
if not api_key:
return

try:
import base64
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
headers = {"x-apikey": api_key}
response = requests.get(
f"https://www.virustotal.com/api/v3/urls/{url_id}",
headers=headers,
timeout=10
)

if response.status_code == 200:
data = response.json()
stats = data["data"]["attributes"]["last_analysis_stats"]
malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)

if malicious >= 5:
risk.add(50, f"VirusTotal: {malicious} vendors flagged as MALICIOUS")
elif malicious >= 1:
risk.add(30, f"VirusTotal: {malicious} vendor(s) flagged as malicious")
elif suspicious >= 3:
risk.add(20, f"VirusTotal: {suspicious} vendors flagged as suspicious")
else:
risk.good(f"VirusTotal: Clean ({malicious} malicious, {suspicious} suspicious)")

elif response.status_code == 404:
risk.add(5, "VirusTotal: URL not previously analyzed — new/unknown")

except Exception as e:
print(f" [!] VirusTotal check failed: {e}")


# ─────────────────────────────────────────────
# Check 6 — Domain Entropy (typosquatting)
# ─────────────────────────────────────────────

def check_domain_entropy(hostname, risk):
"""
High character entropy in a domain name often indicates
randomly generated or typosquatted domains.
e.g. 'paypa1-secure.com' vs 'paypal.com'

Shannon entropy: measures randomness in the character distribution.
"""
domain_part = hostname.split(".")[0] if "." in hostname else hostname

# Calculate Shannon entropy
freq = {}
for ch in domain_part:
freq[ch] = freq.get(ch, 0) + 1

entropy = 0
length = len(domain_part)
for count in freq.values():
p = count / length
if p > 0:
entropy -= p * math.log2(p)

if entropy > 4.0:
risk.add(15, f"High domain entropy ({entropy:.2f}) — may be randomly generated")
elif entropy > 3.5:
risk.add(5, f"Moderate domain entropy ({entropy:.2f})")
else:
risk.good(f"Normal domain entropy ({entropy:.2f})")

# Check for number substitutions (l33t speak)
leet_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s"}
normalized = domain_part.lower()
for num, letter in leet_map.items():
normalized = normalized.replace(num, letter)

for brand in KNOWN_BRANDS:
if normalized == brand and domain_part.lower() != brand:
risk.add(40, f"Domain '{domain_part}' looks like '{brand}' with character substitution")
break


# ─────────────────────────────────────────────
# Main Analysis Pipeline
# ─────────────────────────────────────────────

def analyze_url(url, vt_key=None):
"""
Runs all checks against a URL and prints a detailed risk report.
"""
# Normalize URL
if not url.startswith(("http://", "https://")):
url = "https://" + url

parsed = urlparse(url)
hostname = parsed.netloc.split(":")[0].lower()
risk = RiskScore()

print(f"\n{'═' * 60}")
print(bold(f" Analyzing: {url}"))
print(f"{'═' * 60}\n")

# Fetch page content
html = None
try:
resp = requests.get(
url,
timeout=REQUEST_TIMEOUT,
headers={"User-Agent": USER_AGENT},
verify=False,
allow_redirects=True
)
html = resp.text

# Check for redirects
if resp.url != url:
final_domain = urlparse(resp.url).netloc
original_domain = parsed.netloc
if final_domain != original_domain:
risk.add(15, f"URL redirects to different domain: {final_domain}")

print(f" {green('[+]')} Page loaded — status {resp.status_code} ({len(html):,} bytes)")

except requests.exceptions.SSLError:
risk.add(25, "SSL certificate error on page load")
print(f" {yellow('[!]')} SSL error on page load")
except requests.exceptions.ConnectionError:
risk.add(10, "Could not connect to the server")
print(f" {red('[!]')} Connection failed")
except Exception as e:
print(f" {yellow('[!]')} Page fetch warning: {e}")

# Run all checks
print(f"\n {cyan('[*]')} Running checks...\n")

print(f" {'─' * 50}")
print(f" {bold('1. URL Structure')}")
check_url_structure(url, parsed, risk)

print(f" {bold('2. Domain Age (WHOIS)')}")
check_domain_age(hostname, risk)

print(f" {bold('3. SSL Certificate')}")
check_ssl(hostname, risk)

print(f" {bold('4. HTML Content')}")
check_html_content(url, html, risk)

print(f" {bold('5. Domain Entropy')}")
check_domain_entropy(hostname, risk)

if vt_key:
print(f" {bold('6. VirusTotal')}")
check_virustotal(url, vt_key, risk)

print(f" {'─' * 50}")

# Print report
print(f"\n{'═' * 60}")
print(bold(" RISK REPORT"))
print(f"{'═' * 60}")

if risk.reasons:
print(f"\n {bold(red(' Risk Indicators:'))}")
for points, reason in sorted(risk.reasons, key=lambda x: -x[0]):
bar = "█" * min(points // 5, 10)
print(f" +{points:>3} {bar} {reason}")

if risk.safe:
print(f"\n {bold(green(' Safe Indicators:'))}")
for s in risk.safe:
print(f" {s}")

total = risk.total()
verdict = risk.verdict()

print(f"\n{'─' * 60}")
print(f" Risk Score : {bold(str(total))}/100")
print(f" Verdict : {verdict}")
print(f"{'═' * 60}\n")

return total, risk


# ─────────────────────────────────────────────
# Batch Mode
# ─────────────────────────────────────────────

def batch_analyze(filepath, vt_key=None):
"""Reads a file with one URL per line and analyzes each."""
try:
with open(filepath) as f:
urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
except FileNotFoundError:
print(red(f"[!] File not found: {filepath}"))
sys.exit(1)

print(f"\n[*] Batch mode — {len(urls)} URLs to analyze\n")
results = []

for url in urls:
score, _ = analyze_url(url, vt_key)
results.append((url, score))

# Summary table
print(f"\n{'═' * 60}")
print(bold(" BATCH SUMMARY"))
print(f"{'═' * 60}")
for url, score in sorted(results, key=lambda x: -x[1]):
if score >= 70:
label = red(f"{score:>3}/100 HIGH RISK")
elif score >= 40:
label = yellow(f"{score:>3}/100 ️ SUSPICIOUS")
else:
label = green(f"{score:>3}/100 SAFE")
print(f" {label} {url}")
print(f"{'═' * 60}\n")


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────

def main():
parser = argparse.ArgumentParser(
description="Phishing Page Detector — URL Risk Analyzer"
)
parser.add_argument("-u", "--url", help="URL to analyze")
parser.add_argument("-f", "--file", help="File with URLs (one per line)")
parser.add_argument("--vt-key", help="VirusTotal API key (optional)")
args = parser.parse_args()

print(f"\n{'=' * 60}")
print(bold(cyan(" PHISHING PAGE DETECTOR — URL Risk Analyzer")))
print(f"{'=' * 60}")

if args.file:
batch_analyze(args.file, args.vt_key)
elif args.url:
analyze_url(args.url, args.vt_key)
else:
url = input("\nEnter URL to analyze:\n> ").strip()
analyze_url(url, args.vt_key)


if __name__ == "__main__":
main()
