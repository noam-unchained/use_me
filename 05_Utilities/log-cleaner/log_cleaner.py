#!/usr/bin/env python3

import argparse
import os
import sys
import subprocess
import struct
import time

LOG_FILES = {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "syslog": ["/var/log/syslog", "/var/log/messages"],
    "lastlog": ["/var/log/lastlog"],
    "wtmp": ["/var/log/wtmp"],
    "btmp": ["/var/log/btmp"],
    "bash_history": [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
    ],
    "apache": ["/var/log/apache2/access.log", "/var/log/apache2/error.log"],
    "nginx": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
}

def check_root():
    return os.geteuid() == 0

def clear_file(path, overwrite=False):
    if not os.path.exists(path):
        return False, "not found"
    try:
        if overwrite:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.write(os.urandom(size))
                f.flush()
            with open(path, "wb") as f:
                pass
        else:
            with open(path, "wb") as f:
                pass
        return True, "cleared"
    except PermissionError:
        return False, "permission denied"
    except Exception as e:
        return False, str(e)

def clear_bash_history():
    results = []
    for path in LOG_FILES["bash_history"]:
        ok, msg = clear_file(path)
        results.append((path, ok, msg))

    try:
        subprocess.run(["history", "-c"], shell=True, capture_output=True)
    except Exception:
        pass

    os.environ["HISTSIZE"] = "0"

    return results

def grep_and_remove(path, pattern):
    if not os.path.exists(path):
        return False, "not found"
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        filtered = [l for l in lines if pattern not in l]
        removed = len(lines) - len(filtered)
        with open(path, "w") as f:
            f.writelines(filtered)
        return True, f"removed {removed} line(s)"
    except PermissionError:
        return False, "permission denied"
    except Exception as e:
        return False, str(e)

def clear_category(category, overwrite=False):
    if category not in LOG_FILES:
        print(f"[!] Unknown category: {category}")
        return
    for path in LOG_FILES[category]:
        ok, msg = clear_file(path, overwrite)
        status = "+" if ok else "!"
        print(f"  [{status}] {path}: {msg}")

def run_full_clean(overwrite=False, skip=None):
    skip = skip or []
    print("[*] Starting full log clean\n")

    for category in LOG_FILES:
        if category in skip:
            print(f"[*] Skipping: {category}")
            continue
        print(f"[*] Clearing: {category}")
        for path in LOG_FILES[category]:
            ok, msg = clear_file(path, overwrite)
            status = "+" if ok else "!"
            print(f"  [{status}] {path}: {msg}")

    print("\n[*] Clearing shell history")
    for path, ok, msg in clear_bash_history():
        status = "+" if ok else "!"
        print(f"  [{status}] {path}: {msg}")

def main():
    parser = argparse.ArgumentParser(description="Linux log cleaner")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List tracked log files")

    p_clear = sub.add_parser("clear", help="Clear specific log category or file")
    p_clear.add_argument("target", help="Category name or absolute file path")
    p_clear.add_argument("--overwrite", action="store_true", help="Overwrite with random data before clearing")

    p_full = sub.add_parser("full", help="Clear all logs")
    p_full.add_argument("--overwrite", action="store_true")
    p_full.add_argument("--skip", nargs="+", help="Categories to skip")

    p_grep = sub.add_parser("grep-remove", help="Remove lines matching a pattern from a log file")
    p_grep.add_argument("-f", "--file", required=True, help="Log file path")
    p_grep.add_argument("-p", "--pattern", required=True, help="String to remove")

    args = parser.parse_args()

    if args.command == "list":
        for cat, paths in LOG_FILES.items():
            print(f"\n[{cat}]")
            for p in paths:
                exists = "exists" if os.path.exists(p) else "not found"
                print(f"  {p} ({exists})")

    elif args.command == "clear":
        target = args.target
        if target in LOG_FILES:
            clear_category(target, args.overwrite)
        elif os.path.isabs(target):
            ok, msg = clear_file(target, args.overwrite)
            print(f"  [{'+'if ok else '!'}] {target}: {msg}")
        else:
            print("[!] Specify a category name or absolute file path")

    elif args.command == "full":
        if not check_root():
            print("[!] Warning: not running as root, some logs may be skipped")
        run_full_clean(args.overwrite, args.skip)

    elif args.command == "grep-remove":
        ok, msg = grep_and_remove(args.file, args.pattern)
        print(f"  [{'+'if ok else '!'}] {args.file}: {msg}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
