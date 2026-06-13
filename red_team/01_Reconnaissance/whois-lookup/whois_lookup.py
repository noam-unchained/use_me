#!/usr/bin/env python3

import argparse
import whois
import json
import sys
from datetime import datetime

def format_date(val):
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    return str(val) if val else "N/A"

def lookup(domain):
    try:
        w = whois.whois(domain)
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        sys.exit(1)

    fields = {
        "Domain": w.domain_name,
        "Registrar": w.registrar,
        "Creation Date": format_date(w.creation_date),
        "Expiration Date": format_date(w.expiration_date),
        "Updated Date": format_date(w.updated_date),
        "Name Servers": w.name_servers,
        "Status": w.status,
        "Emails": w.emails,
        "Registrant": w.get("registrant_name") or w.get("org"),
        "Country": w.country,
        "DNSSEC": w.dnssec,
    }
    return fields

def print_results(fields):
    print("\n--- WHOIS Results ---\n")
    for key, val in fields.items():
        if isinstance(val, (list, set)):
            val_str = ", ".join(str(v) for v in val) if val else "N/A"
        else:
            val_str = str(val) if val else "N/A"
        print(f"  {key:<20} {val_str}")
    print()

def main():
    parser = argparse.ArgumentParser(description="WHOIS lookup tool")
    parser.add_argument("domain", nargs="+", help="Domain(s) to query")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    all_results = {}

    for domain in args.domain:
        domain = domain.strip().lower()
        print(f"[*] Querying: {domain}")
        results = lookup(domain)
        print_results(results)
        all_results[domain] = results

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
