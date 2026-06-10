# 🔓 Hash Cracker — Wordlist Attack Tool

A Python-based dictionary attack tool for cracking password hashes using a wordlist (e.g. `rockyou.txt`).  
Supports automatic hash type detection and both single and batch cracking modes.

> ⚠️ **For educational and authorized use only.** Only use against hashes you own or have explicit permission to test.

---

## 🚀 Features

- **Auto-detects hash type** — no need to specify MD5 vs SHA256 manually
- **Supports 6 hash types** — MD5, SHA1, SHA256, SHA512, NTLM, bcrypt
- **Two modes** — single hash (manual input) or batch mode (load from file)
- **Live progress** — shows attempt count and cracking speed in real time
- **Batch summary table** — clean results overview after cracking multiple hashes
- **Interrupt-safe** — press `Ctrl+C` to stop without crashing

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/hash-cracker.git
cd hash-cracker
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python hash_cracker.py
```

**Single hash mode:**
```
Wordlist path (press Enter for default: /usr/share/wordlists/rockyou.txt):
> 

Select mode:
  [1] Single hash (enter manually)
  [2] Batch mode  (load from file)
> 1

Enter hash to crack:
> 5f4dcc3b5aa765d61d8327deb882cf99

[*] Detected hash type: MD5
[*] Cracking: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Wordlist: /usr/share/wordlists/rockyou.txt

[+] CRACKED in 0.03s after 3,241 attempts!

════════════════════════════════════════
  Hash     : 5f4dcc3b5aa765d61d8327deb882cf99
  Password : password
════════════════════════════════════════
```

**Batch mode:**
```
> 2

Enter path to hashes file (.txt, one hash per line):
> sample_hashes.txt

[*] Loaded 6 hash(es) from sample_hashes.txt

════════════════════════════════════════════════════════════
RESULTS SUMMARY
════════════════════════════════════════════════════════════
  5f4dcc3b5aa765d61d8327deb882cf99  → ✓  password
  827ccb0eea8a706c4c34a16891f84e7b  → ✓  12345
  5baa61e4c9b93f3f0682250b6cf8331b... → ✓  password
  ...
════════════════════════════════════════════════════════════
```

---

## 🧰 Tech Stack

| Library | Purpose |
|---|---|
| `hashlib` | Built-in — MD5, SHA1, SHA256, SHA512, NTLM (MD4) hashing |
| `bcrypt` | bcrypt hash verification via `checkpw()` |
| `os` | File existence checks |
| `time` | Cracking speed measurement |

---

## 📚 Key Concepts

**Why `latin-1` encoding for rockyou.txt?**  
`rockyou.txt` contains passwords from real breaches — many include special characters that aren't valid UTF-8. Using `latin-1` prevents the script from crashing on those lines.

**Why can't we just rehash bcrypt and compare?**  
bcrypt embeds a random salt inside the hash itself. Every time you hash the same password, you get a different result. `bcrypt.checkpw()` extracts the salt from the stored hash and uses it to verify — this is the only correct way to compare bcrypt hashes.

**How is hash type auto-detected?**  
By length:
| Length | Type |
|---|---|
| 32 chars | MD5 (default) or NTLM — select manually if NTLM |
| 40 chars | SHA1 |
| 64 chars | SHA256 |
| 128 chars | SHA512 |
| 60 chars + `$2b$` prefix | bcrypt |

> **Why MD5 and NTLM are ambiguous:** both produce a 32-char hex digest. The tool defaults to MD5 on auto-detect. If you know the hash came from a Windows machine (e.g. via Mimikatz or secretsdump), select NTLM manually.

---

## 📁 File Structure

```
hash-cracker/
├── hash_cracker.py     # Main cracking script
├── sample_hashes.txt   # Example hashes for testing
├── requirements.txt    # Python dependencies
└── README.md
```

---

## 🔮 Possible Extensions

- [ ] Multi-threading for faster cracking
- [ ] Rule-based mutations (append numbers, capitalize, etc.)
- [ ] Export results to JSON/CSV
- [ ] Support for NTLM and NetNTLMv2 hashes
- [ ] `--hash` and `--wordlist` CLI flags with `argparse`

---

## ⚠️ Disclaimer

This tool is for **educational use** in CTF and lab environments.  
Do not use against systems or accounts you do not own.

---

## 📄 License

MIT
