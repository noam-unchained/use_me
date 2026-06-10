#!/usr/bin/env python3
"""
Email Enumeration Tool — OSINT & Recon
========================================
Given a target domain and a person's full name, this tool:
  1. Generates all common corporate email format permutations
  2. Verifies each address via SMTP (without sending an actual email)
  3. Reports which addresses are valid

This is a classic OSINT / recon technique used in penetration testing
to identify valid email addresses before phishing simulations or
credential attacks.

Usage:
    python email_enum.py                        # interactive mode
    python email_enum.py -d company.com -n "John Doe"
    python email_enum.py -d company.com -f names.txt  # batch mode

Requirements:
    pip install -r requirements.txt
"""

import smtplib
import socket
import dns.resolver
import argparse
import time
import sys
from itertools import product


# ─────────────────────────────────────────────
# Email Pattern Generator
# ─────────────────────────────────────────────

def generate_patterns(first, last, domain):
    """
    Generates all common corporate email format permutations
    for a given first name, last name, and domain.

    Returns a list of email address strings.
    """
    f = first.lower()
    l = last.lower()
    fi = f[0]   # first initial
    li = l[0]   # last initial

    patterns = [
        f"{f}.{l}@{domain}",        # john.doe@company.com
        f"{f}{l}@{domain}",         # johndoe@company.com
        f"{fi}{l}@{domain}",        # jdoe@company.com
        f"{f}{li}@{domain}",        # johnd@company.com
        f"{fi}.{l}@{domain}",       # j.doe@company.com
        f"{f}@{domain}",            # john@company.com
        f"{l}@{domain}",            # doe@company.com
        f"{l}.{f}@{domain}",        # doe.john@company.com
        f"{l}{fi}@{domain}",        # doej@company.com
        f"{f}_{l}@{domain}",        # john_doe@company.com
        f"{fi}_{l}@{domain}",       # j_doe@company.com
        f"{f}-{l}@{domain}",        # john-doe@company.com
        f"{fi}{li}@{domain}",       # jd@company.com
        f"{f}.{li}@{domain}",       # john.d@company.com
    ]

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


# ─────────────────────────────────────────────
# MX Record Lookup
# ─────────────────────────────────────────────

def get_mx_record(domain):
    """
    Looks up the MX (Mail Exchange) record for the domain.
    The MX record tells us which server handles incoming mail —
    this is the server we connect to for SMTP verification.

    Returns the MX hostname string, or None if lookup fails.
    """
    try:
        records = dns.resolver.resolve(domain, 'MX')
        # Sort by priority (lowest number = highest priority)
        mx = sorted(records, key=lambda r: r.preference)[0]
        return str(mx.exchange).rstrip('.')
    except Exception as e:
        print(f"[!] MX lookup failed for {domain}: {e}")
        return None


# ─────────────────────────────────────────────
# SMTP Verification
# ─────────────────────────────────────────────

def verify_email(email, mx_host, sender="verify@checker.com", timeout=5):
    """
    Verifies whether an email address exists by probing the mail server
    using the SMTP RCPT TO command — without actually sending any email.

    How it works:
      1. Connect to the MX server on port 25
      2. Say EHLO (introduce ourselves)
      3. Pretend to send a mail FROM a fake address
      4. Ask if the target address (RCPT TO) exists
      5. Check the server's response code:
           250 = address exists (VALID)
           550 = address doesn't exist (INVALID)
           other = inconclusive (server may be greylisting or rate-limiting)

    Note: Many large providers (Gmail, Microsoft) block this technique
    and always return 250 to prevent enumeration. Results may vary.

    Returns: "VALID", "INVALID", or "UNKNOWN"
    """
    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(sender)
            code, message = smtp.rcpt(email)

            if code == 250:
                return "VALID"
            elif code == 550:
                return "INVALID"
            else:
                return "UNKNOWN"

    except smtplib.SMTPConnectError:
        return "CONNECT_FAILED"
    except smtplib.SMTPServerDisconnected:
        return "DISCONNECTED"
    except socket.timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"


# ─────────────────────────────────────────────
# Core Enumeration Logic
# ─────────────────────────────────────────────

def enumerate_emails(domain, first, last, delay=1.0):
    """
    Full pipeline:
      - Generate email patterns
      - Look up the MX record
      - Verify each address via SMTP
      - Print and return results

    Args:
        domain (str): Target domain (e.g. company.com)
        first  (str): Target person's first name
        last   (str): Target person's last name
        delay  (float): Seconds to wait between SMTP checks (avoid rate limiting)

    Returns:
        list of dicts: [{email, status}, ...]
    """
    print(f"\n{'═' * 55}")
    print(f"  Target  : {first} {last}")
    print(f"  Domain  : {domain}")
    print(f"{'═' * 55}\n")

    # Step 1 — Generate patterns
    patterns = generate_patterns(first, last, domain)
    print(f"[*] Generated {len(patterns)} email patterns\n")

    # Step 2 — Get MX record
    print(f"[*] Looking up MX record for {domain}...")
    mx_host = get_mx_record(domain)
    if not mx_host:
        print("[!] Could not resolve MX record — skipping SMTP verification.")
        print("    Printing generated patterns only:\n")
        for p in patterns:
            print(f"  {p}")
        return []

    print(f"[*] Mail server: {mx_host}\n")
    print(f"[*] Starting SMTP verification...\n")
    print(f"  {'Email':<40} {'Status'}")
    print(f"  {'─' * 38} {'─' * 10}")

    results = []

    # Step 3 — Verify each pattern
    for email in patterns:
        status = verify_email(email, mx_host)

        # Format output with color indicators
        if status == "VALID":
            indicator = "✓  VALID"
        elif status == "INVALID":
            indicator = "✗  INVALID"
        else:
            indicator = f"?  {status}"

        print(f"  {email:<40} {indicator}")
        results.append({"email": email, "status": status})

        # Delay between requests to avoid triggering rate limits
        time.sleep(delay)

    # Step 4 — Summary
    valid = [r for r in results if r["status"] == "VALID"]
    print(f"\n{'═' * 55}")
    print(f"  Done! {len(valid)} valid address(es) found out of {len(patterns)}")

    if valid:
        print(f"\n  Valid addresses:")
        for r in valid:
            print(f"    → {r['email']}")

    print(f"{'═' * 55}\n")
    return results


# ─────────────────────────────────────────────
# Batch Mode — multiple names from a file
# ─────────────────────────────────────────────

def batch_from_file(domain, names_file, delay=1.0):
    """
    Reads a file with one full name per line and runs enumeration for each.

    File format (names.txt):
        John Doe
        Jane Smith
        # this is a comment
    """
    try:
        with open(names_file, "r") as f:
            names = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        print(f"[!] Names file not found: {names_file}")
        sys.exit(1)

    print(f"[*] Loaded {len(names)} name(s) from {names_file}")

    all_results = {}

    for name in names:
        parts = name.split()
        if len(parts) < 2:
            print(f"[!] Skipping '{name}' — need first and last name")
            continue
        first, last = parts[0], parts[-1]
        results = enumerate_emails(domain, first, last, delay)
        all_results[name] = results

    # Final summary across all names
    print("\n" + "═" * 55)
    print("  BATCH SUMMARY")
    print("═" * 55)
    for name, results in all_results.items():
        valid = [r["email"] for r in results if r["status"] == "VALID"]
        if valid:
            for email in valid:
                print(f"  ✓  {email}")
        else:
            print(f"  ✗  {name} — no valid addresses found")
    print("═" * 55)


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Email Enumeration Tool — OSINT & Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python email_enum.py -d company.com -n "John Doe"
  python email_enum.py -d company.com -f names.txt
  python email_enum.py -d company.com -n "John Doe" --delay 2
        """
    )
    parser.add_argument("-d", "--domain", help="Target domain (e.g. company.com)")
    parser.add_argument("-n", "--name",   help='Full name in quotes (e.g. "John Doe")')
    parser.add_argument("-f", "--file",   help="Path to names file (one name per line)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Delay in seconds between SMTP checks (default: 1.0)")

    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("    EMAIL ENUMERATION TOOL — OSINT & Recon")
    print("=" * 55)

    # Interactive mode if no args provided
    if not args.domain:
        args.domain = input("\nEnter target domain (e.g. company.com):\n> ").strip()

    if not args.name and not args.file:
        print("\nSelect mode:")
        print("  [1] Single name")
        print("  [2] Batch from file")
        mode = input("\n> ").strip()

        if mode == "1":
            args.name = input("\nEnter full name (e.g. John Doe):\n> ").strip()
        elif mode == "2":
            args.file = input("\nEnter path to names file:\n> ").strip()
        else:
            print("[!] Invalid option.")
            sys.exit(1)

    # Run
    if args.file:
        batch_from_file(args.domain, args.file, args.delay)
    elif args.name:
        parts = args.name.strip().split()
        if len(parts) < 2:
            print("[!] Please provide both first and last name.")
            sys.exit(1)
        first, last = parts[0], parts[-1]
        enumerate_emails(args.domain, first, last, args.delay)
    else:
        print("[!] Provide a name (-n) or a names file (-f).")
        sys.exit(1)


if __name__ == "__main__":
    main()
