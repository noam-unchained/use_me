# Phishing Page Detector — URL Risk Analyzer

A Python tool that analyzes any URL and returns a **risk score (0–100)** with a detailed breakdown of exactly why it's suspicious — covering domain analysis, SSL, HTML content, brand impersonation, and more.

> ️ For educational and security research use only.

---

## What It Does

Runs 6 independent checks against a URL and combines their scores into a final risk verdict:

### Check 1 — URL Structure
- Raw IP address instead of domain
- Excessive subdomains (`secure.login.paypal.verify.evil.com`)
- Known brand names in subdomains (subdomain spoofing)
- Trusted domain used as a subdomain of another domain
- Suspicious TLDs (`.tk`, `.ml`, `.xyz`, `.top`, etc.)
- URL-encoded characters hiding the real destination
- `@` symbol trick (browser ignores everything before it)
- Multiple hyphens in domain name

### Check 2 — Domain Age (WHOIS)
Newly registered domains are a major red flag — most phishing domains are 0–30 days old.

### Check 3 — SSL Certificate
- No HTTPS (port 443 refused)
- Free CA certificates (Let's Encrypt, ZeroSSL) — easy to obtain
- Newly issued certificates
- Subject/domain mismatch

### Check 4 — HTML Content
- Password input fields with forms submitting to external domains
- Hidden input fields collecting extra data
- External iframes loading suspicious content
- Disabled right-click (preventing page inspection)
- Phishing keywords ("verify your account", "suspended", "unusual activity")
- Brand name in title but not in domain
- Meta refresh redirects

### Check 5 — Domain Entropy
- High Shannon entropy → randomly generated domain
- Character substitution detection (`paypa1` → `paypal`, `g00gle` → `google`)

### Check 6 — VirusTotal (optional)
Submit the URL to VirusTotal's database and check how many security vendors flagged it.

---

## ️ Installation

```bash
git clone https://github.com/noam-unchained/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
```

---

## ▶️ Usage

**Interactive mode:**
```bash
python phishing_detector.py
```

**Single URL:**
```bash
python phishing_detector.py -u https://suspicious-site.com
```

**With VirusTotal:**
```bash
python phishing_detector.py -u https://site.com --vt-key YOUR_FREE_API_KEY
```

**Batch mode:**
```bash
python phishing_detector.py -f sample_urls.txt
```

---

## Example Output

```
════════════════════════════════════════════════════════════
Analyzing: http://paypal.com.verify-account.tk/login
════════════════════════════════════════════════════════════

[+] Page loaded — status 200 (8,432 bytes)
[*] Running checks...

──────────────────────────────────────────────────────────
1. URL Structure
2. Domain Age (WHOIS)
3. SSL Certificate
4. HTML Content
5. Domain Entropy
──────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════
RISK REPORT
════════════════════════════════════════════════════════════

Risk Indicators:
+ 40 ████████ 'paypal.com' appears as subdomain of another domain
+ 35 ███████ Form submits credentials to different domain
+ 20 ████ Suspicious TLD '.tk'
+ 20 ████ Domain is only 3 days old
+ 20 ████ Page contains 1 password input field
+ 15 ███ Page disables right-click
+ 10 ██ Free SSL certificate (Let's Encrypt)

Safe Indicators:
Uses a domain name (not raw IP)

────────────────────────────────────────────────────────────
Risk Score : 100/100
Verdict : HIGH RISK — Likely Phishing
════════════════════════════════════════════════════════════
```

---

## File Structure

```
phishing-detector/
├── phishing_detector.py # Main analyzer
├── sample_urls.txt # Sample URLs for batch testing
├── requirements.txt # Dependencies
└── README.md
```

---

## Tech Stack

| Library | Purpose |
|---|---|
| `requests` | Page fetching + redirect tracking |
| `beautifulsoup4` | HTML parsing — forms, iframes, meta tags |
| `python-whois` | Domain age lookup |
| `ssl` + `socket` | Certificate analysis |
| `math` | Shannon entropy calculation |

---

## Key Concepts

**Why is HTTPS not enough?**
Phishers routinely use free SSL certificates (Let's Encrypt) to make their sites appear legitimate. The padlock icon only means the connection is encrypted — not that the site is safe.

**What is subdomain spoofing?**
A URL like `paypal.com.evil-domain.tk` appears to contain "paypal.com" but the actual domain is `evil-domain.tk`. The `paypal.com` part is just a subdomain.

**What is Shannon entropy?**
A measure of randomness in a string. Legitimate domains like `google.com` have low entropy. Randomly generated phishing domains like `xk2f9q.tk` have high entropy — this tool uses it to flag suspicious domains.

---

## Possible Extensions

- [ ] Browser extension version
- [ ] Telegram/Slack bot integration
- [ ] Database of previously analyzed URLs
- [ ] Screenshot capture of suspicious pages
- [ ] Integration with URLScan.io API

---

## ️ Disclaimer

For educational and authorized security research only.

---

## License

MIT
