#!/usr/bin/env python3

import argparse
import requests
import sys
import threading
from queue import Queue
from urllib.parse import urljoin

FOUND = []
LOCK = threading.Lock()

DEFAULT_EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".zip", ".js", ".json", ".xml"]

def worker(queue, base_url, extensions, timeout, status_filter, verbose):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; DirEnum/1.0)"
    })

    while not queue.empty():
        word = queue.get()
        for ext in extensions:
            path = f"{word}{ext}"
            url = urljoin(base_url.rstrip("/") + "/", path)
            try:
                r = session.get(url, timeout=timeout, allow_redirects=False)
                if r.status_code in status_filter:
                    with LOCK:
                        FOUND.append((r.status_code, url))
                        print(f"  [{r.status_code}] {url}")
                elif verbose:
                    print(f"  [{r.status_code}] {url}")
            except requests.exceptions.ConnectionError:
                pass
            except Exception:
                pass
        queue.task_done()

def run(base_url, wordlist, threads, extensions, timeout, status_filter, output, verbose):
    try:
        with open(wordlist, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist}")
        sys.exit(1)

    print(f"[*] Target:    {base_url}")
    print(f"[*] Wordlist:  {wordlist} ({len(words)} words)")
    print(f"[*] Threads:   {threads}")
    print(f"[*] Extensions: {extensions}")
    print(f"[*] Filter:    {status_filter}\n")

    queue = Queue()
    for word in words:
        queue.put(word)

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(queue, base_url, extensions, timeout, status_filter, verbose),
            daemon=True
        )
        t.start()
        thread_list.append(t)

    queue.join()

    print(f"\n[+] Done. Found {len(FOUND)} result(s).")

    if output:
        with open(output, "w") as f:
            for code, url in FOUND:
                f.write(f"{code} {url}\n")
        print(f"[+] Results saved to {output}")

def main():
    parser = argparse.ArgumentParser(description="Web directory and file enumerator")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument(
        "-e", "--extensions",
        default="",
        help="Comma-separated extensions (e.g. .php,.html). Default: none"
    )
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument(
        "-s", "--status",
        default="200,204,301,302,307,401,403",
        help="Status codes to show (default: 200,204,301,302,307,401,403)"
    )
    parser.add_argument("-o", "--output", help="Save found results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all responses")
    args = parser.parse_args()

    extensions = [""] + [e if e.startswith(".") else f".{e}" for e in args.extensions.split(",") if e]
    status_filter = [int(s.strip()) for s in args.status.split(",")]

    run(args.url, args.wordlist, args.threads, extensions, args.timeout, status_filter, args.output, args.verbose)

if __name__ == "__main__":
    main()
