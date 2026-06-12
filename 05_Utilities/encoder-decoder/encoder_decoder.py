#!/usr/bin/env python3

import argparse
import base64
import urllib.parse
import html
import sys
import binascii

def b64_encode(data):
    return base64.b64encode(data.encode()).decode()

def b64_decode(data):
    try:
        return base64.b64decode(data).decode()
    except Exception:
        return base64.b64decode(data + "==").decode()

def b64url_encode(data):
    return base64.urlsafe_b64encode(data.encode()).decode()

def b64url_decode(data):
    return base64.urlsafe_b64decode(data + "==").decode()

def hex_encode(data):
    return data.encode().hex()

def hex_decode(data):
    data = data.replace("\\x", "").replace("0x", "").replace(" ", "")
    return bytes.fromhex(data).decode()

def url_encode(data):
    return urllib.parse.quote(data)

def url_decode(data):
    return urllib.parse.unquote(data)

def url_encode_full(data):
    return urllib.parse.quote(data, safe="")

def html_encode(data):
    return html.escape(data)

def html_decode(data):
    return html.unescape(data)

def rot13(data):
    result = []
    for c in data:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)

def xor_encode(data, key):
    key_bytes = key.encode()
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data.encode()))
    return result.hex()

def xor_decode(data, key):
    key_bytes = key.encode()
    raw = bytes.fromhex(data)
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return result.decode()

def binary_encode(data):
    return " ".join(format(ord(c), "08b") for c in data)

def binary_decode(data):
    parts = data.split()
    return "".join(chr(int(b, 2)) for b in parts)

OPERATIONS = {
    "b64enc": b64_encode,
    "b64dec": b64_decode,
    "b64url-enc": b64url_encode,
    "b64url-dec": b64url_decode,
    "hexenc": hex_encode,
    "hexdec": hex_decode,
    "urlenc": url_encode,
    "urldec": url_decode,
    "urlenc-full": url_encode_full,
    "htmlenc": html_encode,
    "htmldec": html_decode,
    "rot13": rot13,
    "binenc": binary_encode,
    "bindec": binary_decode,
}

def main():
    parser = argparse.ArgumentParser(description="Encode/decode data in various formats")
    parser.add_argument(
        "operation",
        choices=list(OPERATIONS.keys()) + ["xorenc", "xordec"],
        help="Operation to perform"
    )
    parser.add_argument("input", nargs="?", help="Input string (or use stdin)")
    parser.add_argument("-k", "--key", help="Key for XOR operations")
    parser.add_argument("-f", "--file", help="Read input from file")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            data = f.read().rstrip("\n")
    elif args.input:
        data = args.input
    elif not sys.stdin.isatty():
        data = sys.stdin.read().rstrip("\n")
    else:
        print("[!] No input provided")
        sys.exit(1)

    if args.operation == "xorenc":
        if not args.key:
            print("[!] --key required for XOR")
            sys.exit(1)
        print(xor_encode(data, args.key))
    elif args.operation == "xordec":
        if not args.key:
            print("[!] --key required for XOR")
            sys.exit(1)
        print(xor_decode(data, args.key))
    else:
        print(OPERATIONS[args.operation](data))

if __name__ == "__main__":
    main()
