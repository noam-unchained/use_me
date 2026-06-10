#!/usr/bin/env python3
"""
Hash Cracker — Wordlist Attack Tool
=====================================
A dictionary-based hash cracking tool that supports:
  - MD5, SHA1, SHA256, SHA512 (via Python's hashlib)
  - NTLM (Windows password hashes — common in AD pentesting)
  - bcrypt (via the bcrypt library)

Attack method: wordlist attack using rockyou.txt (or any custom wordlist)

Modes:
  - Single hash: provide one hash via CLI input
  - Batch mode:  provide a .txt file containing multiple hashes (one per line)

Usage:
    python hash_cracker.py
"""

import hashlib
import bcrypt
import sys
import os
import time


# ─────────────────────────────────────────────
# Hash Detection
# ─────────────────────────────────────────────

# Hash type is identified by its length (and prefix for bcrypt)
# Note: NTLM and MD5 are both 32 chars — NTLM must be specified manually
# or detected from context (e.g. from a known Windows dump)
HASH_LENGTH_MAP = {
    32:  "MD5",       # also NTLM — ambiguous, defaults to MD5
    40:  "SHA1",
    64:  "SHA256",
    128: "SHA512",
}


def detect_hash_type(hash_str):
    """
    Auto-detects hash type based on length and known prefixes.
    bcrypt hashes always start with $2b$ or $2a$ and are 60 chars long.
    NTLM and MD5 are both 32 hex chars — cannot be auto-distinguished.
    If you know the hash is NTLM (e.g. from a Windows dump), select it manually.
    """
    if hash_str.startswith(("$2b$", "$2a$")) and len(hash_str) == 60:
        return "bcrypt"

    length = len(hash_str)
    return HASH_LENGTH_MAP.get(length, None)


# ─────────────────────────────────────────────
# Hash Comparison
# ─────────────────────────────────────────────

def hash_password(password, hash_type):
    """
    Hashes a plaintext password using the specified algorithm.
    Returns the hex digest string (or None on error).
    """
    try:
        algorithms = {
            "MD5":    hashlib.md5,
            "SHA1":   hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }
        if hash_type in algorithms:
            return algorithms[hash_type](password.encode()).hexdigest()

        if hash_type == "NTLM":
            return hash_ntlm(password)

    except Exception as e:
        print(f"[!] Hashing error: {e}")
    return None


def hash_ntlm(password):
    """
    Computes the NTLM hash of a password.

    NTLM = MD4(UTF-16-LE encoded password)

    This is the format used by Windows to store local account passwords
    and is commonly extracted via tools like Mimikatz or secretsdump.
    MD4 is not directly in hashlib — we access it via hashlib.new('md4').
    """
    try:
        return hashlib.new('md4', password.encode('utf-16-le')).hexdigest()
    except ValueError:
        # MD4 may not be available on hardened OpenSSL builds
        print("[!] MD4 not available on this system.")
        print("    Try: pip install pycryptodome and use Crypto.Hash.MD4")
        return None


def check_bcrypt(password, hash_str):
    """
    bcrypt uses a built-in salt, so we can't just rehash and compare.
    bcrypt.checkpw() handles the comparison correctly.
    """
    try:
        return bcrypt.checkpw(password.encode(), hash_str.encode())
    except Exception:
        return False


# ─────────────────────────────────────────────
# Core Cracking Logic
# ─────────────────────────────────────────────

def crack_hash(target_hash, wordlist_path, hash_type=None):
    """
    Attempts to crack a single hash using a wordlist attack.

    Args:
        target_hash  (str): The hash string to crack
        wordlist_path(str): Path to the wordlist file (e.g. rockyou.txt)
        hash_type    (str): Optional — auto-detected if not provided

    Returns:
        str | None: The cracked plaintext password, or None if not found
    """
    # Auto-detect hash type if not specified
    if not hash_type:
        hash_type = detect_hash_type(target_hash)
        if not hash_type:
            print(f"[!] Could not detect hash type for: {target_hash}")
            print(f"    Supported lengths: 32 (MD5/NTLM), 40 (SHA1), 64 (SHA256), 128 (SHA512), 60 (bcrypt)")
            print(f"    Note: if this is an NTLM hash, re-run and select hash type manually.")
            return None
        print(f"[*] Detected hash type: {hash_type}")

    # Verify wordlist exists
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        return None

    print(f"[*] Cracking: {target_hash}")
    print(f"[*] Wordlist: {wordlist_path}\n")

    start_time = time.time()
    attempts = 0

    try:
        # rockyou.txt uses latin-1 encoding — utf-8 will crash on some lines
        with open(wordlist_path, "r", encoding="latin-1") as f:
            for line in f:
                password = line.strip()
                attempts += 1

                # Progress update every 100,000 attempts
                if attempts % 100_000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"    [{attempts:,} attempts | {rate:,.0f}/sec]", end="\r")

                # Compare hashes
                if hash_type == "bcrypt":
                    if check_bcrypt(password, target_hash):
                        elapsed = time.time() - start_time
                        print(f"\n[+] CRACKED in {elapsed:.2f}s after {attempts:,} attempts!")
                        return password
                else:
                    if hash_password(password, hash_type) == target_hash.lower():
                        elapsed = time.time() - start_time
                        print(f"\n[+] CRACKED in {elapsed:.2f}s after {attempts:,} attempts!")
                        return password

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return None

    elapsed = time.time() - start_time
    print(f"\n[-] Not found after {attempts:,} attempts ({elapsed:.2f}s).")
    return None


# ─────────────────────────────────────────────
# Batch Mode — crack multiple hashes from a file
# ─────────────────────────────────────────────

def crack_from_file(hashes_file, wordlist_path):
    """
    Reads a file containing one hash per line and attempts to crack each.
    Prints a summary table at the end.
    """
    if not os.path.exists(hashes_file):
        print(f"[!] Hashes file not found: {hashes_file}")
        return

    with open(hashes_file, "r") as f:
        # Skip empty lines and comments (#)
        hashes = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not hashes:
        print("[!] No hashes found in file.")
        return

    print(f"[*] Loaded {len(hashes)} hash(es) from {hashes_file}\n")
    print("=" * 60)

    results = {}

    for i, h in enumerate(hashes, 1):
        print(f"\n[{i}/{len(hashes)}] Attempting: {h}")
        result = crack_hash(h, wordlist_path)
        results[h] = result if result else "NOT FOUND"

    # Summary table
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    for h, password in results.items():
        status = f"✓  {password}" if password != "NOT FOUND" else "✗  NOT FOUND"
        print(f"  {h[:40]}{'...' if len(h) > 40 else '':<3} → {status}")
    print("=" * 60)


# ─────────────────────────────────────────────
# Main — User Interface
# ─────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("       HASH CRACKER — Wordlist Attack Tool")
    print("=" * 60)

    # Get wordlist path
    default_wordlist = "/usr/share/wordlists/rockyou.txt"
    wordlist_input = input(f"\nWordlist path (press Enter for default: {default_wordlist}):\n> ").strip()
    wordlist_path = wordlist_input if wordlist_input else default_wordlist

    # Choose mode
    print("\nSelect mode:")
    print("  [1] Single hash (enter manually)")
    print("  [2] Batch mode  (load from file)")
    mode = input("\n> ").strip()

    if mode == "1":
        target_hash = input("\nEnter hash to crack:\n> ").strip()
        if not target_hash:
            print("[!] No hash provided.")
            sys.exit(1)

        # Allow manual override for NTLM (same length as MD5 — ambiguous)
        print("\nForce hash type? (leave blank for auto-detect)")
        print("  Options: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt")
        forced_type = input("> ").strip().upper() or None

        result = crack_hash(target_hash, wordlist_path, hash_type=forced_type)

        if result:
            print(f"\n{'=' * 40}")
            print(f"  Hash     : {target_hash}")
            print(f"  Password : {result}")
            print(f"{'=' * 40}\n")
        else:
            print("\n[-] Hash could not be cracked with this wordlist.\n")

    elif mode == "2":
        hashes_file = input("\nEnter path to hashes file (.txt, one hash per line):\n> ").strip()
        crack_from_file(hashes_file, wordlist_path)

    else:
        print("[!] Invalid option.")
        sys.exit(1)


if __name__ == "__main__":
    main()
