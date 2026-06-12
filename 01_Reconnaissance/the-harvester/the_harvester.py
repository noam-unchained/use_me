#!/usr/bin/env python3

import argparse
import requests
import re
import sys
import time
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def google_search(domain, pages=3):
    results = set()
    for page in range(pages):
        url = f"https://www.google.com/search?q=site:{domain}+OR+%40{domain}&start={page*10}&num=10"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), r.text)
            results.update(emails)
            time.sleep(1.5)
        except Exception:
            pass
    return results

def bing_search(domain, pages=3):
    results = set()
    for page in range(pages):
        url = f"https://www.bing.com/search?q=%40{domain}&first={page*10+1}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), r.text)
            results.update(emails)
            time.sleep(1)
        except Exception:
            pass
    return results

def search_crt(domain):
    subdomains = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains

def search_hackertarget(domain):
    subdomains = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in r.text.splitlines():
            if "," in line:
                subdomains.add(line.split(",")[0].strip())
    except Exception:
        pass
    return subdomains

def run(domain, sources, output=None):
    emails = set()
    subdomains = set()

    print(f"[*] Target: {domain}")
    print(f"[*] Sources: {', '.join(sources)}\n")

    if "google" in sources:
        print("[*] Searching Google...")
        found = google_search(domain)
        emails.update(found)
        print(f"    Found {len(found)} email(s)")

    if "bing" in sources:
        print("[*] Searching Bing...")
        found = bing_search(domain)
        emails.update(found)
        print(f"    Found {len(found)} email(s)")

    if "crt" in sources:
        print("[*] Querying crt.sh...")
        found = search_crt(domain)
        subdomains.update(found)
        print(f"    Found {len(found)} subdomain(s)")

    if "hackertarget" in sources:
        print("[*] Querying HackerTarget...")
        found = search_hackertarget(domain)
        subdomains.update(found)
        print(f"    Found {len(found)} subdomain(s)")

    print("\n--- Results ---")
    if emails:
        print(f"\n[Emails] ({len(emails)} found)")
        for e in sorted(emails):
            print(f"  {e}")

    if subdomains:
        print(f"\n[Subdomains] ({len(subdomains)} found)")
        for s in sorted(subdomains):
            print(f"  {s}")

    if output:
        with open(output, "w") as f:
            f.write(f"Target: {domain}\n\n")
            if emails:
                f.write("Emails:\n")
                for e in sorted(emails):
                    f.write(f"  {e}\n")
            if subdomains:
                f.write("\nSubdomains:\n")
                for s in sorted(subdomains):
                    f.write(f"  {s}\n")
        print(f"\n[+] Results saved to {output}")

def main():
    parser = argparse.ArgumentParser(description="Passive OSINT harvester - emails and subdomains")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument(
        "-s", "--sources",
        default="google,bing,crt,hackertarget",
        help="Comma-separated sources (google,bing,crt,hackertarget)"
    )
    parser.add_argument("-o", "--output", help="Save results to file")
    args = parser.parse_args()

    sources = [s.strip() for s in args.sources.split(",")]
    run(args.domain, sources, args.output)

if __name__ == "__main__":
    main()
