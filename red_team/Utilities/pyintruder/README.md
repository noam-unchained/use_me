# PyIntruder

A fast, universal, **Burp-Intruder-style** HTTP fuzzer for authorized web pentesting and
PortSwigger labs — built to work around the artificial speed throttle that Burp Suite
**Community** puts on Intruder.

Burp Community caps Intruder at roughly **1 request per second**. PyIntruder uses
`httpx` + `asyncio` to fire requests **concurrently** (hundreds per second on a lab box),
then writes an **interactive HTML report** that looks and filters like the Intruder
results window.

> **For authorized testing only** — your own labs, CTFs, or engagements you have
> written permission to test.

---

## Features

- **Paste a raw request** straight from Burp Repeater — no rebuilding URLs by hand.
- **Auto-marks** payload positions (`param=§value§`) and asks you to confirm, or mark manually.
- **4 attack types**: `sniper`, `battering ram`, `pitchfork`, `cluster bomb` (with a built-in
  `?` explainer for each).
- **Payloads**: number range (e.g. `0000`–`9999`), wordlist file, or an inline list.
- **Bundled payload wordlists** (`payloads/`) for XSS, SQLi, SSTI, NoSQL, command injection, LFI, XXE, SSRF, open redirect, CRLF, XPath and LDAP — each opens with a **canary** probe so real hits stand out (see below). Wordlist files may use `#` comment lines to label payloads (skipped on load; a lone `#` is still sent).
- **`?` help anywhere**: type `?` at (almost) any prompt for a one-line explanation of that question.
- **Concurrency + optional rate limit** so you can go fast *or* stay gentle on a target.
- **Live anomaly alerts**: learns a baseline from the first responses and prints a highlighted
  alert (with a terminal bell) the moment an outlier appears — without pausing the run.
- **Evasion**: rotate a spoofed IP header (`X-Forwarded-For` and friends) to bypass IP-based
  brute-force blocks, and/or rotate the `User-Agent`, each on its own cadence.
- **Session re-login / refresh** for apps that log you out mid brute-force, including
  **CSRF-token extraction** via `{{PLACEHOLDER}}` + regex — fully generic.
- **HTTP/2** support (falls back to HTTP/1.1 automatically).
- **Optional proxy** (e.g. route through Burp at `127.0.0.1:8080` to watch traffic).
- **Interactive HTML report**: filter by payload, **search inside response bodies**
  (contains / does-NOT-contain), filter by status, show anomalies only, sort any column
  asc/desc. Baseline responses are auto-detected so the odd-one-out stands out.

---

## Install & run

Requires Python 3.9+ (already installed on most machines). The only dependency is `httpx`.
Each block below **installs the dependency, downloads the script, and runs it** — copy the
whole block into your terminal.

**macOS**
```bash
pip3 install 'httpx[http2]'
curl -O https://raw.githubusercontent.com/noam-unchained/use_me/main/red_team/Utilities/pyintruder/pyintruder.py
python3 pyintruder.py
```

**Windows** (CMD or PowerShell — first install Python from
[python.org](https://www.python.org/downloads/) and tick *"Add Python to PATH"*)
```bat
pip install "httpx[http2]"
curl -O https://raw.githubusercontent.com/noam-unchained/use_me/main/red_team/Utilities/pyintruder/pyintruder.py
python pyintruder.py
```

**Linux / Kali**
```bash
pip install 'httpx[http2]' --break-system-packages
curl -O https://raw.githubusercontent.com/noam-unchained/use_me/main/red_team/Utilities/pyintruder/pyintruder.py
python3 pyintruder.py
```

> On Kali, `--break-system-packages` gets past the PEP 668 block. If you prefer to keep the
> system clean, use a venv instead: `python3 -m venv ~/pyi && source ~/pyi/bin/activate`,
> then `pip install 'httpx[http2]'`.

The tool then walks you through it interactively. You can also pass the request from a file:

```bash
python3 pyintruder.py --request request.txt
```

### Flags

| Flag | Meaning |
|------|---------|
| `--request FILE` | Read the raw HTTP request from a file instead of pasting it. |
| `--scheme https\|http` | Force the scheme (default `https`). |
| `--insecure` | Skip TLS certificate verification. |
| `-h`, `--help` | Show usage. |

---

## How it works — step by step

1. **Paste the raw request.** Copy it from Burp (right-click → *Copy to file*, or select all in
   Repeater). Paste it, then type a line containing only `EOF` to finish.

2. **Confirm the marked positions.** PyIntruder wraps every parameter value in `§…§` and shows
   you the result. Press **Enter** to accept, or type `m` to mark values manually
   (paste the exact value you want to attack, one per line, Enter when done).

   ```
   mfa-code=§1426§
   ```

3. **Pick an attack type** (press `?` for full explanations):

   | Type | What it does | Requests |
   |------|--------------|----------|
   | **sniper** | One payload list, tried in each marked spot one at a time. The classic choice. | spots × payloads |
   | **battering ram** | One payload list, same value placed in **all** spots at once. | payloads |
   | **pitchfork** | A separate list per spot, walked in **parallel** (1st with 1st…). Good for known user+pass pairs. | length of shortest list |
   | **cluster bomb** | A separate list per spot, **every combination**. Good for user × pass spraying. | A × B × C … |

4. **Choose payloads** — a number range (with automatic zero-padding, e.g. `5` → `0005`),
   a wordlist file, or a short inline list.

5. **Set speed & detection** (all optional — press Enter for defaults):
   - concurrency (default 15)
   - rate cap in req/s (default: as fast as possible)
   - a keyword to flag in responses (e.g. `Congratulations`)
   - proxy URL (leave blank for a direct, fast connection)

6. **Optional: session re-login** (see below).

7. The **HTML report opens automatically** in your browser. Every report is saved into a
   `results_not_public/` folder (created automatically) with a timestamped filename, so runs never
   overwrite each other.

---

## The HTML report

The report mirrors Burp's Intruder results window, but interactive:

- **payload** — filter by substring.
- **response text** — search inside the response body: `contains` **or** `does NOT contain`.
  Classic use: every failed guess says `Invalid`/`wrong` except the winner — pick
  *does NOT contain* + type `wrong`, and only the winner remains.
- **status** — substring match (e.g. `30` matches 301/302).
- **anomalies only** — show rows whose status or length differ from the most common (baseline)
  response. The successful request usually jumps right out.
- **matched only** — rows that matched your keyword.
- **Click any column header** to sort; click again to flip asc/desc (an arrow shows the direction).

Redirects are **not** followed (just like Intruder), so a logout/success `302` is visible.

---

## Bundled payload wordlists (`payloads/`)

Ready-to-fire lists for a single injection point, one per web-attack class — load one as the
wordlist (option `[2]`):

| File | Attack | File | Attack |
|------|--------|------|--------|
| `xss.txt` | XSS | `xxe.txt` | XXE |
| `sqli.txt` | SQL injection | `ssrf.txt` | SSRF |
| `ssti.txt` | template injection | `open-redirect.txt` | open redirect |
| `nosql.txt` | NoSQL injection | `crlf.txt` | CRLF / response split |
| `command-injection.txt` | OS command injection | `xpath.txt` | XPath injection |
| `lfi.txt` | LFI / RFI | `ldap.txt` | LDAP injection |

Every file:

- **Opens with a `canary` section** — probes carrying a rare token (`xq9z`) or a deterministic
  signal (an echoed token, a math result, a `/etc/passwd` signature, a `~5s` time delay, or an
  OOB callback). Set the grep to that token so **only real reflections/executions get flagged**
  — HTTP 200 alone is never a hit.
- Uses `#` **comment lines** to label each block (skipped on load; a lone `#` is still sent).
- Is **transmit-safe raw** — characters that would break a raw query (`&`, `#`, `+`) are
  pre-encoded, so every payload arrives intact.

See `payloads/INJECTION-PAYLOADS.md` for the full per-attack detection guide.

## Practice target — `xss_lab.py`

A tiny, intentionally-vulnerable local server for testing the wordlists + canary flow safely
(binds to `127.0.0.1` only — Ctrl-C to stop):

```bash
python3 xss_lab.py 8000
# then attack e.g.  http://127.0.0.1:8000/reflect?q=FUZZ  with payloads/xss.txt, grep = xq9z
```

Its endpoints cover HTML-text, attribute, JS-string, href and a *filtered* context, plus a
**safe** (HTML-encoded) one — so you watch the canary flag the vulnerable contexts and stay
quiet on the safe one (even though every response is still `200`).

## Session re-login / refresh (advanced)

Some apps (including several PortSwigger labs) **invalidate your session** after a few failed
attempts, and protect forms with a **CSRF token** that changes on every page load. A naive
brute-force fails once you're logged out. PyIntruder can re-authenticate on the fly.

When prompted, enable refresh and provide:

1. **A sequence of raw requests** that log you back in, separated by a line `---`.
   Example: `GET /login` → `POST /login` → `GET /login2`.
2. **Placeholders**: write `{{NAME}}` anywhere a dynamic value (like a CSRF token) is needed —
   in the refresh requests **and** in the attack request.
3. **Extractors** that pull those values out of a response, one per line:

   ```
   CSRF = name="csrf" value="([^"]+)"
   ```

   (a regex with **one capture group**, searched in the previous response).
4. **A trigger** that means "I got logged out": one or more status codes (e.g. `302`)
   and/or a body regex.

Flow: PyIntruder logs in once at startup to seed cookies + tokens, runs the attack, and
whenever a response matches the trigger it silently re-runs the login sequence, refreshes the
cookies/tokens, and **retries the same payload** so nothing is skipped.

---

## Evasion (IP + User-Agent rotation)

At the end of setup you're offered two independent rotations:

- **Spoofed IP header** — bypasses apps that trust a forwarding header for rate-limiting.
  Pick which header(s) to spoof: `[1]` `X-Forwarded-For` (classic), `[2]` `X-Real-IP`, or
  `[3]` all common IP headers at once (best odds — you don't know which one the app trusts).
  A random public IP is injected, changing every N requests. **Use `1` (every request)** to
  beat a per-IP counter — if the block trips after 3 tries, sharing an IP across requests
  gets you blocked.
- **User-Agent** — cycles through 15 real browser UAs, changing every N requests.

Both are off by default and fully independent. This does **not** change your real source IP —
it only sets headers, so it works against apps that trust those headers (many do, and the
PortSwigger IP-block labs are built for exactly this). For genuinely different source IPs,
route through a proxy instead.

## Routing through Burp (proxy)

PyIntruder connects **directly** to the target — it does **not** use your browser or FoxyProxy.
If you want to *watch* its requests inside Burp (or use Repeater on them), enter a proxy URL
when asked:

```
http://127.0.0.1:8080
```

TLS verification is turned off automatically in this mode (Burp re-signs certificates).
For maximum speed, leave the proxy blank and let it connect directly.

---

## Troubleshooting

- **`Missing dependency`** → `pip install 'httpx[http2]'`
- **HTTP/2 unavailable** → the `[http2]` extra isn't installed; the tool falls back to HTTP/1.1.
- **All responses look "logged out"** → the app is invalidating your session; enable
  **session re-login** (see above).
- **Nothing matches / everything looks the same** → try the *anomalies only* toggle, or sort by
  **Length**; the outlier is usually the answer.
- **Getting blocked / rate-limited** → lower concurrency and set a rate cap.

---

## Legal

This tool is intended solely for **authorized** security testing and education (your own labs,
CTF challenges, and engagements you have explicit permission to perform). You are responsible
for how you use it.
