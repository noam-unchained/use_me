# 📧 Email Enumeration Tool — OSINT & Recon

A Python-based OSINT tool that generates corporate email address permutations for a target person and verifies which ones are valid using SMTP — without sending a single email.

> ⚠️ **For educational and authorized use only.** Only use against domains you own or have explicit permission to test.

---

## 🚀 What It Does

### Step 1 — Pattern Generation
Given a full name and domain, generates all common corporate email formats:

| Pattern | Example |
|---|---|
| `first.last@domain` | john.doe@company.com |
| `firstlast@domain` | johndoe@company.com |
| `flast@domain` | jdoe@company.com |
| `firstl@domain` | johnd@company.com |
| `f.last@domain` | j.doe@company.com |
| `first@domain` | john@company.com |
| `last@domain` | doe@company.com |
| `last.first@domain` | doe.john@company.com |
| `first_last@domain` | john_doe@company.com |
| `first-last@domain` | john-doe@company.com |
| + 4 more variations | ... |

### Step 2 — MX Record Lookup
Resolves the domain's MX (Mail Exchange) record to find which mail server handles incoming email for that domain.

### Step 3 — SMTP Verification
Connects to the mail server and uses the `RCPT TO` SMTP command to ask whether each address exists — without sending any email.

Response codes:
- `250` → **VALID** — address exists
- `550` → **INVALID** — address doesn't exist
- other → **UNKNOWN** — server is rate-limiting or greylisting

### Step 4 — Summary
Prints a clean results table and highlights all valid addresses found.

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/email-enum.git
cd email-enum
pip install -r requirements.txt
```

---

## ▶️ Usage

**Interactive mode:**
```bash
python email_enum.py
```

**Single name via CLI:**
```bash
python email_enum.py -d company.com -n "John Doe"
```

**Batch mode (multiple names from file):**
```bash
python email_enum.py -d company.com -f names.txt
```

**Custom delay between checks:**
```bash
python email_enum.py -d company.com -n "John Doe" --delay 2
```

---

## 📸 Example Output

```
═══════════════════════════════════════════════════════
  Target  : John Doe
  Domain  : company.com
═══════════════════════════════════════════════════════

[*] Generated 14 email patterns
[*] Looking up MX record for company.com...
[*] Mail server: mail.company.com

[*] Starting SMTP verification...

  Email                                    Status
  ────────────────────────────────────── ──────────
  john.doe@company.com                   ✓  VALID
  johndoe@company.com                    ✗  INVALID
  jdoe@company.com                       ✗  INVALID
  johnd@company.com                      ✗  INVALID
  j.doe@company.com                      ✓  VALID
  ...

═══════════════════════════════════════════════════════
  Done! 2 valid address(es) found out of 14

  Valid addresses:
    → john.doe@company.com
    → j.doe@company.com
═══════════════════════════════════════════════════════
```

---

## 📁 File Structure

```
email-enum/
├── email_enum.py     # Main enumeration script
├── names.txt         # Sample names file for batch mode
├── requirements.txt  # Python dependencies
└── README.md
```

---

## 🧰 Tech Stack

| Library | Purpose |
|---|---|
| `dnspython` | MX record resolution |
| `smtplib` | Built-in — SMTP connection and RCPT TO verification |
| `socket` | Timeout and connection error handling |
| `argparse` | CLI argument parsing |

---

## 📚 Key Concepts

**What is SMTP RCPT TO verification?**
When you send an email, your mail client connects to the recipient's mail server and says `RCPT TO: <address>`. The server responds with `250` (exists) or `550` (doesn't exist) before any email is actually sent. We exploit this handshake to verify addresses without sending anything.

**Why does this sometimes not work?**
Large providers like Gmail, Outlook, and Google Workspace deliberately return `250` for every address regardless of whether it exists — this is called "catch-all" and is a deliberate anti-enumeration defense.

**What is an MX record?**
A DNS record that tells you which mail server is responsible for receiving email for a domain. Without it, we don't know where to connect for SMTP verification.

---

## 🔮 Possible Extensions

- [ ] Export results to CSV
- [ ] Integration with `Hunter.io` API for additional verification
- [ ] LinkedIn scraping to auto-extract employee names
- [ ] Support for catch-all detection
- [ ] Multi-threading for faster batch processing

---

## ⚠️ Disclaimer

This tool is intended for **authorized penetration testing, bug bounty, and educational use only**.  
Unauthorized email enumeration may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws.

---

## 📄 License

MIT
