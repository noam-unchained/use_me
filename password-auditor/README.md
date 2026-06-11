# Password Strength Auditor

Analyzes a list of passwords from a file (credential dump, internal audit, pentest finding),
grades each one A-F, identifies weakness patterns across the dataset, and generates
a professional remediation report.

No external dependencies — pure Python 3 standard library.

---

## What It Does

### Per-Password Analysis
Every password is checked for:

| Check | What It Catches |
|---|---|
| Length | Too short (< 8), short (< 12), good (12+) |
| Character diversity | Missing uppercase, lowercase, digits, symbols |
| Common passwords | Top 200 from rockyou / known breach lists |
| Keyboard walks | qwerty, 12345, 1q2w3e, asdfgh... |
| Repeated characters | aaa, 111, zzzzz |
| Dictionary words | password, admin, welcome, dragon... |
| l33t speak | p4ssw0rd, @dm1n, s3cur3 |
| Digit-only | 123456, 19901225 |
| Word + number suffix | password1, admin123, football99 |
| Shannon entropy | Bits of entropy based on character pool and length |

### Grades
| Grade | Score | Meaning |
|---|---|---|
| A | 80-100 | Strong |
| B | 65-79 | Good |
| C | 50-64 | Moderate |
| D | 35-49 | Weak |
| F | 0-34 | Critical |

### Dataset Report
After analyzing all passwords:
- Grade distribution with visual bar chart
- Average score, length, entropy
- Top weakness patterns ranked by frequency
- Top N weakest passwords with their issues
- Professional remediation recommendations

---

## Installation

```bash
git clone https://github.com/noam-unchained/password-auditor.git
cd password-auditor
# No pip install needed
```

---

## Usage

```bash
# Basic audit
python password_auditor.py -f passwords.txt

# Show top 20 weakest
python password_auditor.py -f passwords.txt --top 20

# Save report to file
python password_auditor.py -f passwords.txt --report report.txt

# Hide passwords in terminal output
python password_auditor.py -f passwords.txt --hide-passwords
```

---

## Example Output

```
======================================================
  PASSWORD STRENGTH AUDIT REPORT
  Generated: 2024-03-15 14:22:01
======================================================

GRADE DISTRIBUTION
----------------------------------------
  A  ██░░░░░░░░   2 (10.0%)
  B  ████░░░░░░   4 (20.0%)
  C  ████░░░░░░   4 (20.0%)
  D  ██░░░░░░░░   2 (10.0%)
  F  ████████░░   8 (40.0%)

KEY STATISTICS
----------------------------------------
  Total passwords analyzed :  20
  Average score            :  41.0/100
  Average length           :  8.6 chars
  Average entropy          :  34.2 bits
  Weak/Failing (D+F)       :  10 (50.0%)
  Common passwords         :  7 (35.0%)

TOP WEAKNESS PATTERNS
----------------------------------------
  Appears in common password list         7 (35.0%)
  Contains dictionary word                6 (30.0%)
  Word + number suffix (password1)        4 (20.0%)
  Keyboard walk (qwerty, 12345...)        3 (15.0%)

TOP 10 WEAKEST PASSWORDS
------------------------------------------------------------
  Password                  Grade   Score    Issues
  ----------------------------------------------------------
  123456                    F        0       Appears in top common...
  qwerty                    F        0       Keyboard walk pattern...
  password                  F        0       Common password list...

REMEDIATION RECOMMENDATIONS
------------------------------------------------------------
  - 7 password(s) appear in known breach lists — change immediately
  - Average password length is 8.6 — enforce minimum 12 characters
  - 50.0% of passwords are weak — consider enforcing a password policy
  - Enable MFA wherever possible
  - Use a password manager (Bitwarden, 1Password)
```

---

## Input File Format

One password per line. Empty lines are ignored.

```
123456
P@ssw0rd!2024
correct-horse-battery-staple
```

---

## File Structure

```
password-auditor/
├── password_auditor.py    # Main auditor script
├── sample_passwords.txt   # Sample passwords for testing
├── requirements.txt       # No external deps needed
└── README.md
```

---

## Key Concepts

**Why check for l33t speak?**
Substituting `a -> @`, `e -> 3`, `o -> 0` is a well-known pattern that password crackers handle automatically. `p@ssw0rd` offers almost no security benefit over `password`.

**What is Shannon entropy?**
A measure of unpredictability. A password of 8 lowercase letters has ~37 bits of entropy. Adding uppercase, digits and symbols to the same length pushes this to ~50+ bits — exponentially harder to crack.

**What is a keyboard walk?**
Sequences typed by sliding fingers across the keyboard — `qwerty`, `1q2w3e`, `asdfgh`. Crackers have entire wordlists dedicated to these patterns.

---

## Possible Extensions

- [ ] Export report as PDF
- [ ] Check against HaveIBeenPwned API (k-anonymity model)
- [ ] Parse username:password dump format
- [ ] Policy enforcement mode (fail if score below threshold)
- [ ] Multi-threading for large files

---

## Disclaimer

For authorized security auditing only. Do not use on passwords you don't own.

---

## License

MIT
