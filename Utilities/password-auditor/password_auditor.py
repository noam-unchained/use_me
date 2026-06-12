#!/usr/bin/env python3
"""
Password Strength Auditor
==========================
Analyzes a list of passwords from a file (e.g. a credential dump),
grades each one, identifies patterns, and generates a professional
report with statistics and remediation recommendations.

Checks per password:
  - Length
  - Character diversity (uppercase, lowercase, digits, symbols)
  - Common password detection (rockyou top list)
  - Keyboard walk detection (qwerty, 12345, etc.)
  - Repeated characters
  - Dictionary word detection
  - l33t speak detection
  - Shannon entropy score

Output:
  - Per-password grade (A-F)
  - Pattern breakdown
  - Dataset statistics
  - Top weak passwords
  - Professional remediation report (txt)

Usage:
    python password_auditor.py -f passwords.txt
    python password_auditor.py -f dump.txt --report report.txt
    python password_auditor.py -f dump.txt --top 20

Requirements:
    No external dependencies — pure Python 3 standard library
"""

import re
import sys
import math
import argparse
import collections
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# Common Passwords List (top 200 from rockyou)
# ─────────────────────────────────────────────

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon", "123123",
    "baseball", "iloveyou", "trustno1", "sunshine", "master",
    "welcome", "shadow", "ashley", "football", "jesus",
    "michael", "ninja", "mustang", "password1", "123456a",
    "abc123", "letmein", "monkey", "696969", "pass",
    "superman", "qazwsx", "michael", "football", "batman",
    "hello", "charlie", "donald", "password123", "qwerty123",
    "iloveyou1", "admin", "login", "test", "root", "toor",
    "pass123", "1q2w3e", "1q2w3e4r", "zxcvbnm", "asdfghjkl",
    "1234567890", "0987654321", "qwertyuiop", "password2",
    "123321", "654321", "111222", "112233", "121212",
    "000000", "999999", "123qwe", "q1w2e3", "abc", "aaa",
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "qweasd", "zxcasd", "1qaz", "2wsx", "3edc", "4rfv",
    "qazwsx", "1q2w3e", "1q2w3e4r5t", "qazxsw", "!qaz",
    "12345", "123456", "1234567", "12345678", "123456789",
    "0987654321", "98765", "987654",
]

# Simple dictionary words to detect
DICTIONARY_WORDS = {
    "password", "welcome", "hello", "admin", "login", "user",
    "test", "guest", "master", "dragon", "monkey", "shadow",
    "sunshine", "princess", "football", "baseball", "soccer",
    "hockey", "batman", "superman", "spider", "love", "god",
    "sex", "pass", "home", "root", "system", "network",
}

# l33t speak substitutions
LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "@": "a",
    "!": "i", "$": "s", "+": "t",
}


# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(t):    return f"{C.RED}{t}{C.RESET}"
def green(t):  return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"
def cyan(t):   return f"{C.CYAN}{t}{C.RESET}"


# ─────────────────────────────────────────────
# Entropy Calculation
# ─────────────────────────────────────────────

def calc_entropy(password):
    """
    Calculates Shannon entropy of the password.
    Also estimates brute-force search space based on character set used.

    Higher entropy = harder to crack.
    < 28 bits  = very weak
    28-35 bits = weak
    36-59 bits = moderate
    60-127 bits = strong
    128+ bits  = very strong
    """
    # Shannon entropy
    freq = collections.Counter(password)
    length = len(password)
    shannon = -sum(
        (c / length) * math.log2(c / length)
        for c in freq.values()
    )

    # Character pool size
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32

    # Bits of entropy based on pool and length
    bits = math.log2(pool ** length) if pool > 0 else 0

    return round(shannon, 2), round(bits, 1)


# ─────────────────────────────────────────────
# Password Analysis
# ─────────────────────────────────────────────

def analyze_password(password):
    """
    Runs all checks on a single password.
    Returns a dict with score, grade, and all findings.
    """
    score    = 100  # Start at 100, deduct points for weaknesses
    issues   = []
    good     = []
    patterns = []

    lower = password.lower()

    # --- Length ---
    length = len(password)
    if length < 6:
        score -= 40
        issues.append(f"Too short ({length} chars) — minimum 12 recommended")
    elif length < 8:
        score -= 25
        issues.append(f"Short password ({length} chars)")
    elif length < 12:
        score -= 10
        issues.append(f"Moderate length ({length} chars) — 12+ recommended")
    else:
        good.append(f"Good length ({length} chars)")

    # --- Character diversity ---
    has_upper  = bool(re.search(r"[A-Z]", password))
    has_lower  = bool(re.search(r"[a-z]", password))
    has_digit  = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    diversity = sum([has_upper, has_lower, has_digit, has_symbol])

    if not has_upper:
        score -= 10
        issues.append("No uppercase letters")
    if not has_lower:
        score -= 10
        issues.append("No lowercase letters")
    if not has_digit:
        score -= 10
        issues.append("No digits")
    if not has_symbol:
        score -= 10
        issues.append("No special characters")

    if diversity == 4:
        good.append("Uses all character types")
    elif diversity >= 3:
        good.append("Uses 3 character types")

    # --- Common password check ---
    if lower in COMMON_PASSWORDS:
        score -= 50
        issues.append("Appears in top common passwords list")
        patterns.append("common")

    # --- Keyboard walk ---
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            score -= 30
            issues.append(f"Contains keyboard walk pattern: '{walk}'")
            patterns.append("keyboard_walk")
            break

    # --- Repeated characters ---
    if re.search(r"(.)\1{2,}", password):
        score -= 20
        issues.append("Contains 3+ repeated characters in a row")
        patterns.append("repeated_chars")

    # --- All same character ---
    if len(set(password)) == 1:
        score -= 40
        issues.append("All characters are identical")
        patterns.append("all_same")

    # --- Dictionary word ---
    for word in DICTIONARY_WORDS:
        if word in lower:
            score -= 20
            issues.append(f"Contains common dictionary word: '{word}'")
            patterns.append("dictionary")
            break

    # --- l33t speak detection ---
    normalized = lower
    for leet_char, real_char in LEET_MAP.items():
        normalized = normalized.replace(leet_char, real_char)

    for word in DICTIONARY_WORDS:
        if word in normalized and word not in lower:
            score -= 15
            issues.append(f"l33t speak detected — '{password}' normalizes to contain '{word}'")
            patterns.append("leet")
            break

    # --- Only digits ---
    if password.isdigit():
        score -= 25
        issues.append("Password is all digits — easily brute-forced")
        patterns.append("all_digits")

    # --- Ends with digit(s) only ---
    if re.match(r"^[a-zA-Z]+\d{1,4}$", password):
        score -= 10
        issues.append("Word + number suffix pattern (e.g. 'password1') — very common")
        patterns.append("word_number")

    # --- Entropy ---
    shannon, bits = calc_entropy(password)
    if bits < 28:
        score -= 20
        issues.append(f"Very low entropy ({bits} bits) — trivially crackable")
    elif bits < 36:
        score -= 10
        issues.append(f"Low entropy ({bits} bits)")
    elif bits >= 60:
        good.append(f"High entropy ({bits} bits)")
    else:
        good.append(f"Moderate entropy ({bits} bits)")

    # --- Final score and grade ---
    score = max(0, min(100, score))

    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {
        "password": password,
        "score":    score,
        "grade":    grade,
        "length":   length,
        "entropy":  bits,
        "shannon":  shannon,
        "issues":   issues,
        "good":     good,
        "patterns": list(set(patterns)),
        "diversity": diversity,
    }


# ─────────────────────────────────────────────
# Grade Color
# ─────────────────────────────────────────────

def grade_color(grade):
    colors = {
        "A": green,
        "B": green,
        "C": yellow,
        "D": yellow,
        "F": red,
    }
    return colors.get(grade, lambda x: x)(grade)


# ─────────────────────────────────────────────
# Dataset Statistics
# ─────────────────────────────────────────────

def compute_stats(results):
    """Computes aggregate statistics across all analyzed passwords."""
    total = len(results)
    if total == 0:
        return {}

    grades   = collections.Counter(r["grade"] for r in results)
    patterns = collections.Counter(p for r in results for p in r["patterns"])
    lengths  = [r["length"] for r in results]
    entropies = [r["entropy"] for r in results]
    scores   = [r["score"] for r in results]

    grade_f_count = grades.get("F", 0)
    grade_d_count = grades.get("D", 0)
    weak_count = grade_f_count + grade_d_count

    return {
        "total":         total,
        "grades":        grades,
        "patterns":      patterns,
        "avg_length":    round(sum(lengths) / total, 1),
        "min_length":    min(lengths),
        "max_length":    max(lengths),
        "avg_entropy":   round(sum(entropies) / total, 1),
        "avg_score":     round(sum(scores) / total, 1),
        "weak_count":    weak_count,
        "weak_pct":      round((weak_count / total) * 100, 1),
        "common_count":  patterns.get("common", 0),
        "common_pct":    round((patterns.get("common", 0) / total) * 100, 1),
    }


# ─────────────────────────────────────────────
# Print Report to Terminal
# ─────────────────────────────────────────────

def print_report(results, stats, top_n=10, show_passwords=True):
    """Prints the full audit report to the terminal."""

    print(f"\n{'=' * 60}")
    print(bold(cyan("  PASSWORD STRENGTH AUDIT REPORT")))
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}")

    # Grade distribution
    print(f"\n{bold('GRADE DISTRIBUTION')}")
    print(f"{'─' * 40}")
    grade_bar_chars = {"A": green, "B": green, "C": yellow, "D": yellow, "F": red}
    for grade in ["A", "B", "C", "D", "F"]:
        count = stats["grades"].get(grade, 0)
        pct   = round((count / stats["total"]) * 100, 1)
        bar   = grade_bar_chars[grade]("█" * int(pct // 2))
        print(f"  {grade}  {bar} {count:>5} ({pct}%)")

    # Key statistics
    print(f"\n{bold('KEY STATISTICS')}")
    print(f"{'─' * 40}")
    print(f"  Total passwords analyzed : {stats['total']}")
    print(f"  Average score            : {stats['avg_score']}/100")
    print(f"  Average length           : {stats['avg_length']} chars")
    print(f"  Average entropy          : {stats['avg_entropy']} bits")
    print(f"  Weak/Failing (D+F)       : {red(str(stats['weak_count']))} ({stats['weak_pct']}%)")
    print(f"  Common passwords         : {red(str(stats['common_count']))} ({stats['common_pct']}%)")

    # Top patterns found
    if stats["patterns"]:
        print(f"\n{bold('TOP WEAKNESS PATTERNS')}")
        print(f"{'─' * 40}")
        pattern_labels = {
            "common":        "Appears in common password list",
            "keyboard_walk": "Keyboard walk (qwerty, 12345...)",
            "repeated_chars": "Repeated characters (aaa, 111...)",
            "dictionary":    "Contains dictionary word",
            "leet":          "l33t speak substitution",
            "all_digits":    "All digits",
            "word_number":   "Word + number suffix (password1)",
            "all_same":      "All identical characters",
        }
        for pattern, count in stats["patterns"].most_common():
            label = pattern_labels.get(pattern, pattern)
            pct   = round((count / stats["total"]) * 100, 1)
            print(f"  {label:<45} {count:>5} ({pct}%)")

    # Top weakest passwords
    weakest = sorted(results, key=lambda x: x["score"])[:top_n]
    print(f"\n{bold(f'TOP {top_n} WEAKEST PASSWORDS')}")
    print(f"{'─' * 60}")
    print(f"  {'Password':<25} {'Grade':<7} {'Score':<8} {'Issues'}")
    print(f"  {'─' * 58}")
    for r in weakest:
        pw = r["password"][:22] + "..." if len(r["password"]) > 22 else r["password"]
        if show_passwords:
            pw_display = pw
        else:
            pw_display = "*" * min(len(r["password"]), 10)
        grade_str = grade_color(r["grade"])
        print(f"  {pw_display:<25} {grade_str:<16} {r['score']:<8} {r['issues'][0] if r['issues'] else ''}")

    # Recommendations
    print(f"\n{bold('REMEDIATION RECOMMENDATIONS')}")
    print(f"{'─' * 60}")

    recs = []
    if stats["common_count"] > 0:
        recs.append(f"  {stats['common_count']} password(s) appear in known breach lists — change immediately")
    if stats["patterns"].get("keyboard_walk", 0) > 0:
        recs.append(f"  {stats['patterns']['keyboard_walk']} keyboard walk pattern(s) found — avoid sequential keys")
    if stats["avg_length"] < 12:
        recs.append(f"  Average password length is {stats['avg_length']} — enforce minimum 12 characters")
    if stats["patterns"].get("all_digits", 0) > 0:
        recs.append(f"  {stats['patterns']['all_digits']} digit-only password(s) — require mixed character types")
    if stats["weak_pct"] > 30:
        recs.append(f"  {stats['weak_pct']}% of passwords are weak — consider enforcing a password policy")
    if stats["avg_entropy"] < 40:
        recs.append(f"  Low average entropy ({stats['avg_entropy']} bits) — encourage use of passphrases or a password manager")

    recs.append("  Enable MFA wherever possible — even weak passwords are safer with MFA")
    recs.append("  Use a password manager (Bitwarden, 1Password) to generate and store strong passwords")

    for rec in recs:
        print(f"  - {rec.strip()}")

    print(f"\n{'=' * 60}\n")


# ─────────────────────────────────────────────
# Save Report to File
# ─────────────────────────────────────────────

def save_report(results, stats, output_path):
    """Saves a plain-text version of the report to a file."""
    lines = []
    lines.append("PASSWORD STRENGTH AUDIT REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    lines.append("\nKEY STATISTICS")
    lines.append(f"  Total passwords  : {stats['total']}")
    lines.append(f"  Average score    : {stats['avg_score']}/100")
    lines.append(f"  Average length   : {stats['avg_length']}")
    lines.append(f"  Weak (D+F)       : {stats['weak_count']} ({stats['weak_pct']}%)")
    lines.append(f"  Common passwords : {stats['common_count']} ({stats['common_pct']}%)")

    lines.append("\nGRADE DISTRIBUTION")
    for grade in ["A", "B", "C", "D", "F"]:
        count = stats["grades"].get(grade, 0)
        pct   = round((count / stats["total"]) * 100, 1)
        lines.append(f"  {grade}  {count:>5} ({pct}%)")

    lines.append("\nFULL PASSWORD ANALYSIS")
    lines.append("-" * 60)
    for r in sorted(results, key=lambda x: x["score"]):
        lines.append(f"\n  Password : {r['password']}")
        lines.append(f"  Grade    : {r['grade']}  Score: {r['score']}/100")
        lines.append(f"  Length   : {r['length']}  Entropy: {r['entropy']} bits")
        if r["issues"]:
            lines.append(f"  Issues   : {'; '.join(r['issues'])}")
        if r["good"]:
            lines.append(f"  Positives: {'; '.join(r['good'])}")

    lines.append("\n" + "=" * 60)

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(green(f"\n[+] Report saved to: {output_path}"))


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Auditor — Analyze credential dumps"
    )
    parser.add_argument("-f", "--file",   required=True, help="Input file — one password per line")
    parser.add_argument("--report",       help="Save full report to text file")
    parser.add_argument("--top",          type=int, default=10, help="Show top N weakest (default: 10)")
    parser.add_argument("--hide-passwords", action="store_true", help="Mask passwords in output")
    args = parser.parse_args()

    # Load passwords
    path = Path(args.file)
    if not path.exists():
        print(red(f"[!] File not found: {args.file}"))
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        print(red("[!] No passwords found in file."))
        sys.exit(1)

    print(f"\n{bold(cyan('[*]'))} Loaded {len(passwords)} passwords from {args.file}")
    print(f"{bold(cyan('[*]'))} Analyzing...\n")

    # Analyze all passwords
    results = [analyze_password(pw) for pw in passwords]
    stats   = compute_stats(results)

    # Print report
    print_report(
        results, stats,
        top_n=args.top,
        show_passwords=not args.hide_passwords
    )

    # Save report if requested
    if args.report:
        save_report(results, stats, args.report)


if __name__ == "__main__":
    main()
