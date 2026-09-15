# Injection payload wordlists

One file per attack, for fuzzing a single injection point with **pyintruder** (`burp_alter`).
Mark the value with `§`, load a file as the payload set, run it, and read the results table.

## Files

| File | Attack | Payloads |
|------|--------|----------|
| `xss.txt` | XSS | 189 — canary probes + every context + WAF bypass + print() + polyglots |
| `sqli.txt` | SQLi | 119 — detection → auth bypass → UNION → error → blind → stacked → WAF |
| `ssti.txt` | SSTI | 51 — `xq9z{{7*7}}` canary → engine fingerprint → per-engine RCE (Jinja2/Twig/Freemarker/Velocity/Spring/ERB/Smarty) |
| `nosql.txt` | NoSQL | 44 — `$where` sleep canary → operator auth bypass (`$ne`/`$gt`/`$regex`) → `$where` JS |
| `command-injection.txt` | Cmd injection | 45 — `;echo xq9z` canary → in-band (Linux/Win) → time/OOB blind → filter bypass → reverse shells |
| `lfi.txt` | LFI / RFI | 55 — `/etc/passwd` canary → traversal + bypass → PHP wrappers → log/proc sinks → RFI |
| `xxe.txt` | XXE | 18 — file-read canary → SSRF → blind OOB → error-based → SVG (goes in an XML body) |
| `ssrf.txt` | SSRF | 44 — OOB-callback canary → internal + cloud metadata → schemes → filter bypass |
| `open-redirect.txt` | Open redirect | 33 — redirect to your domain (watch the Redirect column) → allowlist/backslash/scheme bypass |
| `crlf.txt` | CRLF / response-split | 20 — inject `X-Canary: xq9z` header → encoding bypass → response-splitting XSS |
| `xpath.txt` | XPath injection | 21 — `' or '1'='1` auth bypass → node enumeration → blind boolean |
| `ldap.txt` | LDAP injection | 21 — `*)(uid=*)` auth bypass → wildcards → AND/OR rewrites |

**Canary token used across files: `xq9z`** (a rare marker — set the tool's grep to it; a hit
means your input reached a place that matters). SSRF's canary lands on your own listener; XXE/LFI
detect on file-content signatures (`root:x:0:0`); cmd-injection/SSTI reflect `xq9z` in the response.

## Format

- **One payload per line.** Lines starting with `#` are comments — they label what each block is
  for. `pyintruder` skips them (patched loader; a lone `#` is still sent, so `chars.txt` works).
- Payloads are **raw** and chosen to transmit intact when injected raw (no literal `&`, `#`, or
  `+`-as-plus — those are written `%26`/`%23` etc. and decode server-side to the intended char).
  Every file was tested against a reflect server via httpx (the same client pyintruder uses) and
  transmits correctly. (XXE goes in an XML body, where `&` is fine, so it isn't form-tested.)
- Swap `alert(1)` → `print()` / `confirm(1)` / `alert(document.domain)` as the lab requires.

## Finding real hits — use the CANARY (this fixes the HTTP-200 false positives)

**HTTP 200 is not a hit.** Instead:

1. Run the **canary probes** at the top of `xss.txt` first. In pyintruder set the grep / regex to
   the token **`xq9z`**.
2. Only responses that actually **reflect** the token get flagged — not every 200.
3. Open the flagged rows in the results table and look at the token in the response: if `<` `>`
   `"` `'` appear **unencoded** next to `xq9z`, that spot is injectable → fire the payloads from
   the matching section.

For SQLi: grep for `SQL`/`syntax`/`error` (error & UNION), or watch the **response time ~5s** for
the blind time-based payloads. Never flag on status alone.

## Reading the results — "which payloads worked?"

pyintruder writes an HTML results file (in `../results/`): **one row per payload**, showing the
payload, status, length and time, with the flagged (matched-grep / anomalous) rows highlighted.
So you always see which payload produced which response; the highlighted rows are your hits.

## Usage

```
python3 /Users/noamgolian/desktop/noam_unchained/burp_alter/pyintruder.py
# mark the value with § → [2] wordlist file → point at xss.txt or sqli.txt
# set the grep to xq9z (XSS) so only real reflections get flagged
```

Pair each list with the cheatsheet at `../../cheatsheets/web-app/` (xss/, sqli/, …) to understand
*why* a flagged payload works.
