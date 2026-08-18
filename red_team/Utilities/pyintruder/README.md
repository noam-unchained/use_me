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
- **Concurrency + optional rate limit** so you can go fast *or* stay gentle on a target.
- **Live anomaly alerts**: learns a baseline from the first responses and prints a highlighted
  alert (with a terminal bell) the moment an outlier appears — without pausing the run.
- **Session re-login / refresh** for apps that log you out mid brute-force, including
  **CSRF-token extraction** via `{{PLACEHOLDER}}` + regex — fully generic.
- **HTTP/2** support (falls back to HTTP/1.1 automatically).
- **Optional proxy** (e.g. route through Burp at `127.0.0.1:8080` to watch traffic).
- **Interactive HTML report**: filter by payload, **search inside response bodies**
  (contains / does-NOT-contain), filter by status, show anomalies only, sort any column
  asc/desc. Baseline responses are auto-detected so the odd-one-out stands out.

---

## Install

Requires Python 3.9+ (already installed on most machines). You only need to install one
package — `httpx` (with its HTTP/2 extra).

**macOS / Linux** — in the Terminal:

```bash
pip3 install 'httpx[http2]'
```

**Windows** — in CMD or PowerShell:

```bat
pip install "httpx[http2]"
```

> If `pip3` / `pip` isn't found, install Python from [python.org](https://www.python.org/downloads/)
> (on Windows, tick **"Add Python to PATH"** during setup), then re-run the command.

Alternatively, from the project folder: `pip install -r requirements.txt`

---

## Quick start

```bash
python3 pyintruder.py
```

You'll be walked through it interactively. You can also pass the request from a file:

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
   `results/` folder (created automatically) with a timestamped filename, so runs never
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
