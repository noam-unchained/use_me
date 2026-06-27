"""
runner.py — Downloads missing tools (if internet available) and runs them.
Each tool writes its raw output to output_dir/raw/.
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import shutil
import time

from core.wizard import C, _section, _info


# ---------------------------------------------------------------------------
# Tool definitions — where to download and how to run each one
# ---------------------------------------------------------------------------

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")

TOOL_DEFS = {
    "winpeas": {
        "exe":  "winPEASx64.exe",
        "url":  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe",
        "args": ["--color"],
    },
    "sharphound": {
        "exe":  "SharpHound.exe",
        "url":  "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe",
        "args": ["-c", "All", "--zipfilename", "bloodhound_data"],
    },
    "seatbelt": {
        "exe":  "Seatbelt.exe",
        "url":  None,  # must be compiled — we'll warn the user
        "args": ["-group=all"],
    },
    "powerup": {
        # PowerUp is a PowerShell script
        "exe":  "PowerUp.ps1",
        "url":  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1",
        "args": [],
    },
    "powerview": {
        "exe":  "PowerView.ps1",
        "url":  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1",
        "args": [],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status(msg):
    print(f"  {C.CYAN}[*]{C.RESET} {msg}")


def _ok(msg):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")


def _warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def _err(msg):
    print(f"  {C.RED}[-]{C.RESET} {msg}")


def _tool_path(tool_name):
    return os.path.join(TOOLS_DIR, TOOL_DEFS[tool_name]["exe"])


def _download(tool_name, url):
    dest = _tool_path(tool_name)
    _status(f"Downloading {tool_name} from GitHub...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
        _ok(f"Downloaded → {dest}")
        return True
    except Exception as e:
        _err(f"Failed to download {tool_name}: {e}")
        return False


def _ensure_tool(tool_name, has_internet):
    """Make sure the tool binary exists. Download if needed and possible."""
    path = _tool_path(tool_name)
    if os.path.exists(path):
        _ok(f"{tool_name} found at {path}")
        return True

    url = TOOL_DEFS[tool_name].get("url")

    if not url:
        _warn(f"{tool_name} must be compiled manually (no pre-built binary available).")
        _info(f"Place the compiled binary at: {path}")
        return False

    if not has_internet:
        _warn(f"{tool_name} not found locally and no internet — skipping.")
        return False

    return _download(tool_name, url)


# ---------------------------------------------------------------------------
# Individual runners
# ---------------------------------------------------------------------------

def _run_exe(tool_name, extra_args, output_file, timeout=300):
    """Run an .exe tool and capture output."""
    path = _tool_path(tool_name)
    args = TOOL_DEFS[tool_name]["args"] + extra_args
    cmd  = [path] + args

    _status(f"Running {tool_name}... (timeout {timeout}s)")
    try:
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
        )
        elapsed = round(time.time() - start, 1)
        output = result.stdout + result.stderr
        with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write(output)
        _ok(f"{tool_name} finished in {elapsed}s → {output_file}")
        return output
    except subprocess.TimeoutExpired:
        _warn(f"{tool_name} timed out after {timeout}s — partial output saved.")
        return None
    except Exception as e:
        _err(f"{tool_name} failed: {e}")
        return None


def _run_ps1(tool_name, commands, output_file, timeout=120):
    """
    Run a PowerShell script by importing it and running a list of commands.
    commands: list of PS commands to run after importing the script.
    """
    path = _tool_path(tool_name)
    ps_block = f". '{path}'\n" + "\n".join(commands)

    _status(f"Running {tool_name} via PowerShell... (timeout {timeout}s)")
    try:
        start = time.time()
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_block,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
        )
        elapsed = round(time.time() - start, 1)
        output = result.stdout + result.stderr
        with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write(output)
        _ok(f"{tool_name} finished in {elapsed}s → {output_file}")
        return output
    except subprocess.TimeoutExpired:
        _warn(f"{tool_name} timed out after {timeout}s — partial output saved.")
        return None
    except Exception as e:
        _err(f"{tool_name} failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Per-tool run functions
# ---------------------------------------------------------------------------

def run_winpeas(raw_dir, config):
    output_file = os.path.join(raw_dir, "winpeas.txt")
    return _run_exe("winpeas", [], output_file, timeout=300)


def run_sharphound(raw_dir, config):
    output_file = os.path.join(raw_dir, "sharphound.txt")
    target = config["target"]
    extra  = ["--domain", target["domain"]]
    if target.get("dc_ip"):
        extra += ["--domaincontroller", target["dc_ip"]]
    # SharpHound drops its ZIP in cwd — we want it in raw_dir
    extra += ["--outputdirectory", raw_dir]
    return _run_exe("sharphound", extra, output_file, timeout=180)


def run_seatbelt(raw_dir, config):
    output_file = os.path.join(raw_dir, "seatbelt.txt")
    return _run_exe("seatbelt", [], output_file, timeout=180)


def run_powerview(raw_dir, config):
    """Run a standard set of PowerView commands and save combined output."""
    output_file = os.path.join(raw_dir, "powerview.txt")
    target = config["target"]
    domain = target["domain"]

    commands = [
        f'Write-Output "=== DOMAIN INFO ==="',
        f'Get-Domain -Domain {domain} | Format-List',

        f'Write-Output "=== DOMAIN CONTROLLERS ==="',
        f'Get-DomainController -Domain {domain} | Format-List',

        f'Write-Output "=== DOMAIN USERS ==="',
        f'Get-DomainUser -Domain {domain} | Select-Object samaccountname,description,memberof,pwdlastset,lastlogon | Format-Table -AutoSize',

        f'Write-Output "=== KERBEROASTABLE USERS ==="',
        f'Get-DomainUser -SPN -Domain {domain} | Select-Object samaccountname,serviceprincipalname,memberof | Format-Table -AutoSize',

        f'Write-Output "=== ASREP ROASTABLE USERS ==="',
        f'Get-DomainUser -PreauthNotRequired -Domain {domain} | Select-Object samaccountname | Format-Table -AutoSize',

        f'Write-Output "=== DOMAIN GROUPS ==="',
        f'Get-DomainGroup -Domain {domain} | Select-Object samaccountname,description | Format-Table -AutoSize',

        f'Write-Output "=== DOMAIN ADMINS ==="',
        f'Get-DomainGroupMember "Domain Admins" -Domain {domain} | Select-Object MemberName,MemberSID | Format-Table -AutoSize',

        f'Write-Output "=== DOMAIN COMPUTERS ==="',
        f'Get-DomainComputer -Domain {domain} | Select-Object dnshostname,operatingsystem,lastlogon | Format-Table -AutoSize',

        f'Write-Output "=== UNCONSTRAINED DELEGATION ==="',
        f'Get-DomainComputer -Unconstrained -Domain {domain} | Select-Object dnshostname,useraccountcontrol | Format-Table -AutoSize',
        f'Get-DomainUser -AllowDelegation -Domain {domain} | Select-Object samaccountname | Format-Table -AutoSize',

        f'Write-Output "=== CONSTRAINED DELEGATION ==="',
        f'Get-DomainUser -TrustedToAuth -Domain {domain} | Select-Object samaccountname,msds-allowedtodelegateto | Format-Table -AutoSize',
        f'Get-DomainComputer -TrustedToAuth -Domain {domain} | Select-Object dnshostname,msds-allowedtodelegateto | Format-Table -AutoSize',

        f'Write-Output "=== GPO LIST ==="',
        f'Get-DomainGPO -Domain {domain} | Select-Object displayname,gpcfilesyspath | Format-Table -AutoSize',

        f'Write-Output "=== PASSWORD POLICY ==="',
        f'Get-DomainPolicyData -Domain {domain} | Select-Object -ExpandProperty SystemAccess | Format-List',

        f'Write-Output "=== DOMAIN TRUSTS ==="',
        f'Get-DomainTrust -Domain {domain} | Format-Table -AutoSize',

        f'Write-Output "=== ACL MISCONFIGS (WriteDACL/GenericAll on DAs) ==="',
        f'Find-InterestingDomainAcl -Domain {domain} -ResolveGUIDs | Where-Object {{$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|GenericWrite|ForceChangePassword"}} | Format-Table -AutoSize',

        f'Write-Output "=== SMB SHARES ==="',
        f'Find-DomainShare -Domain {domain} | Format-Table -AutoSize',

        f'Write-Output "=== PASSWD NOTREQD USERS ==="',
        f'Get-DomainUser -UACFilter PASSWD_NOTREQD -Domain {domain} | Select-Object samaccountname,description | Format-Table -AutoSize',

        f'Write-Output "=== ADMINCOUNT USERS ==="',
        f'Get-DomainUser -AdminCount -Domain {domain} | Select-Object samaccountname,memberof | Format-Table -AutoSize',
    ]

    return _run_ps1("powerview", commands, output_file, timeout=300)


def run_powerup(raw_dir, config):
    output_file = os.path.join(raw_dir, "powerup.txt")
    commands = [
        'Write-Output "=== POWERUP PRIVESC CHECKS ==="',
        'Invoke-AllChecks | Format-List',
    ]
    return _run_ps1("powerup", commands, output_file, timeout=120)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

TOOL_MAP = {
    "run_winpeas":    ("winpeas",    run_winpeas),
    "run_sharphound": ("sharphound", run_sharphound),
    "run_seatbelt":   ("seatbelt",   run_seatbelt),
    "run_powerview":  ("powerview",  run_powerview),
}


TOOL_SOURCES = {
    "winpeas":    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe",
    "sharphound": "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe",
    "seatbelt":   "https://github.com/GhostPack/Seatbelt  (must compile yourself — Visual Studio)",
    "powerview":  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1",
    "powerup":    "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1",
}


def _offline_check(scope):
    """
    When there is no internet, scan tools/ and warn the user about anything missing.
    Prints a clear table so they know exactly what to drop in before running.
    Returns True if at least one tool is available, False if nothing can run.
    """
    scope_to_tool = {
        "run_winpeas":    "winpeas",
        "run_sharphound": "sharphound",
        "run_seatbelt":   "seatbelt",
        "run_powerview":  "powerview",
        "run_powerup":    "powerup",
    }

    missing = []
    present = []

    for scope_key, tool_name in scope_to_tool.items():
        if not scope.get(scope_key, False):
            continue
        path = _tool_path(tool_name)
        if os.path.exists(path):
            present.append((tool_name, path))
        else:
            missing.append((tool_name, TOOL_DEFS[tool_name]["exe"]))

    if missing:
        print()
        _warn("No internet detected. The following tools are missing from the tools/ folder:")
        print()
        for tool_name, exe in missing:
            print(f"    {C.RED}[✗]{C.RESET}  {exe:<25} {C.DIM}→ get it from: {TOOL_SOURCES.get(tool_name, 'unknown')}{C.RESET}")
        if present:
            print()
            _ok("These tools were found locally and will still run:")
            for tool_name, path in present:
                print(f"    {C.GREEN}[✓]{C.RESET}  {path}")
        print()
        print(f"  {C.DIM}Copy the missing binaries into the tools/ folder on this machine, then re-run.{C.RESET}")
        print(f"  {C.DIM}Missing tools will be skipped — enumeration will continue with what's available.{C.RESET}")
        print()

    return len(present) > 0 or len(missing) == 0


def run_all(config):
    """
    Download missing tools (if online) or use local copies (if offline), then run everything.
    Returns a dict of raw outputs keyed by tool name.
    """
    _section("PHASE 2 — Enumeration")

    scope        = config["scope"]
    output_dir   = scope["output_dir"]
    has_internet = config["discovery"]["internet"]

    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(TOOLS_DIR, exist_ok=True)

    if not has_internet:
        _offline_check(scope)

    results = {}

    for scope_key, (tool_name, run_fn) in TOOL_MAP.items():
        if not scope.get(scope_key, False):
            _info(f"Skipping {tool_name} (disabled by user).")
            continue

        print()
        if not _ensure_tool(tool_name, has_internet):
            _warn(f"Skipping {tool_name} — binary not available.")
            continue

        output = run_fn(raw_dir, config)
        if output:
            results[tool_name] = output

    # Always run PowerUp if PowerView ran (same PS script download)
    if scope.get("run_powerview") and os.path.exists(_tool_path("powerup")):
        print()
        output = run_powerup(raw_dir, config)
        if output:
            results["powerup"] = output

    _section("Enumeration Complete")
    print(f"  {C.GREEN}[✓]{C.RESET} Raw output saved to: {raw_dir}")
    print(f"  {C.GREEN}[✓]{C.RESET} Tools ran: {', '.join(results.keys()) or 'none'}\n")

    return results
