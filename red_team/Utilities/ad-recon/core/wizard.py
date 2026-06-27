"""
wizard.py — Phase 0 (auto-discovery) + Phase 1 (interactive wizard).

Phase 0 silently discovers as much as possible about the environment.
Phase 1 only asks the user to fill in what Phase 0 couldn't determine.
"""

import os
import sys
import socket
import subprocess
import getpass
import ctypes
import json


# ---------------------------------------------------------------------------
# ANSI colors (Windows 10+ supports these)
# ---------------------------------------------------------------------------
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"
    MAGENTA = "\033[95m"


BANNER = r"""
 ▄▄▄      ▓█████▄     ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █
▒████▄    ▒██▀ ██▌   ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █
▒██  ▀█▄  ░██   █▌   ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒
░██▄▄▄▄██ ░▓█▄   ▌   ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒
 ▓█   ▓██▒░▒████▓    ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░
 ▒▒   ▓▒█░ ▒▒▓  ▒    ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒
  ▒   ▒▒ ░ ░ ▒  ▒      ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ▒    ░ ░  ░      ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░
      ░  ░   ░          ░        ░  ░░ ░          ░ ░           ░
           ░                         ░

         Windows Active Directory Recon & Reporting Tool
         For educational use only — run only on machines you own or have permission to test.
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=8):
    """Run a shell command, return stdout as string or None on failure."""
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL,
            timeout=timeout, shell=isinstance(cmd, str)
        ).decode(errors="ignore").strip()
    except Exception:
        return None


def _ask(prompt, default=None, secret=False):
    suffix = f" [{C.DIM}{default}{C.RESET}]" if default else ""
    full   = f"  {C.CYAN}>{C.RESET} {prompt}{suffix}: "
    if secret:
        val = getpass.getpass(full)
    else:
        val = input(full).strip()
    return val if val else default


def _ask_choice(prompt, choices, default=None):
    print(f"\n  {C.BOLD}{prompt}{C.RESET}")
    for i, (key, label) in enumerate(choices, 1):
        tag = f"{C.GREEN}[{i}]{C.RESET}"
        def_tag = f"  {C.DIM}← default{C.RESET}" if key == default else ""
        print(f"    {tag} {label}{def_tag}")
    while True:
        raw = input(f"\n  {C.CYAN}>{C.RESET} Choice [1-{len(choices)}]: ").strip()
        if not raw and default:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1][0]
        print(f"  {C.YELLOW}Enter a number between 1 and {len(choices)}.{C.RESET}")


def _section(title):
    print(f"\n{C.BOLD}{C.MAGENTA}{'─' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'─' * 60}{C.RESET}\n")


def _found(label, value):
    print(f"  {C.GREEN}[+]{C.RESET} {label:<30} {C.BOLD}{value}{C.RESET}")


def _missing(label):
    print(f"  {C.YELLOW}[?]{C.RESET} {label:<30} {C.DIM}not detected{C.RESET}")


def _info(msg):
    print(f"  {C.DIM}    {msg}{C.RESET}")


# ---------------------------------------------------------------------------
# Phase 0 — Auto-Discovery
# ---------------------------------------------------------------------------

def _discover_privileges():
    """Check if running as admin / SYSTEM."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    username = os.environ.get("USERNAME", "")
    is_system = username.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM")
    return {
        "is_admin":  bool(is_admin),
        "is_system": is_system,
        "username":  username,
    }


def _discover_domain():
    """Try multiple methods to detect domain name and DC."""
    domain  = None
    dc_ip   = None
    dc_name = None

    # Method 1: environment variables
    domain = os.environ.get("USERDNSDOMAIN") or os.environ.get("USERDOMAIN")

    # Method 2: nltest
    out = _run(["nltest", "/dsgetdc:" + (domain or "")])
    if out:
        for line in out.splitlines():
            line = line.strip()
            if "DC: \\\\" in line:
                dc_name = line.split("\\\\")[-1].strip()
            if "DNS Domain" in line or "Dns Domain" in line:
                domain = domain or line.split(":")[-1].strip()

    # Method 3: ipconfig /all for DNS suffix
    if not domain:
        out = _run("ipconfig /all")
        if out:
            for line in out.splitlines():
                if "Connection-specific DNS Suffix" in line or "Primary Dns Suffix" in line:
                    val = line.split(":")[-1].strip()
                    if val and "." in val:
                        domain = val
                        break

    # Method 4: wmic computersystem
    if not domain:
        out = _run("wmic computersystem get Domain /value")
        if out:
            for line in out.splitlines():
                if "Domain=" in line:
                    val = line.split("=")[-1].strip()
                    if val and "WORKGROUP" not in val.upper():
                        domain = val

    # Resolve DC IP
    if dc_name:
        try:
            dc_ip = socket.gethostbyname(dc_name)
        except Exception:
            pass
    if not dc_ip and domain:
        try:
            dc_ip = socket.gethostbyname(domain)
        except Exception:
            pass

    return {"domain": domain, "dc_ip": dc_ip, "dc_hostname": dc_name}


def _discover_network():
    """Get local IP, hostname, network info."""
    hostname = socket.gethostname()
    local_ip = None
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        pass
    return {"hostname": hostname, "local_ip": local_ip}


def _discover_current_user():
    """Get current domain user info."""
    username  = os.environ.get("USERNAME", "")
    userdomain = os.environ.get("USERDOMAIN", "")
    full_user  = f"{userdomain}\\{username}" if userdomain else username

    # Get group memberships via whoami /groups
    groups = []
    out = _run("whoami /groups")
    if out:
        for line in out.splitlines()[3:]:  # skip header
            parts = line.split()
            if parts:
                groups.append(parts[0])

    return {
        "username":   full_user,
        "groups":     groups[:10],  # cap for display
    }


def _check_internet():
    """Quick check if internet is reachable."""
    try:
        socket.setdefaulttimeout(3)
        socket.create_connection(("8.8.8.8", 53))
        return True
    except Exception:
        return False


def phase0_discover():
    """
    Run all auto-discovery checks silently, then print a summary.
    Returns a discovery dict that pre-fills the wizard.
    """
    _section("PHASE 0 — Environment Auto-Discovery")
    print(f"  {C.DIM}Scanning your environment before we ask you anything...{C.RESET}\n")

    privs   = _discover_privileges()
    domain  = _discover_domain()
    network = _discover_network()
    user    = _discover_current_user()
    internet = _check_internet()

    # Print summary
    print(f"  {C.BOLD}Current User{C.RESET}")
    _found("Logged in as", user["username"])
    if privs["is_system"]:
        _found("Privilege level", f"{C.RED}NT AUTHORITY\\SYSTEM — already at top{C.RESET}")
    elif privs["is_admin"]:
        _found("Privilege level", f"{C.YELLOW}Local Administrator{C.RESET}")
    else:
        _found("Privilege level", "Standard user — privesc paths will be enumerated")

    print()
    print(f"  {C.BOLD}Machine{C.RESET}")
    _found("Hostname", network["hostname"])
    if network["local_ip"]:
        _found("Local IP", network["local_ip"])
    else:
        _missing("Local IP")

    print()
    print(f"  {C.BOLD}Active Directory{C.RESET}")
    if domain["domain"]:
        _found("Domain", domain["domain"])
    else:
        _missing("Domain")

    if domain["dc_ip"]:
        _found("DC IP", domain["dc_ip"])
    else:
        _missing("DC IP")

    if domain["dc_hostname"]:
        _found("DC Hostname", domain["dc_hostname"])

    print()
    print(f"  {C.BOLD}Connectivity{C.RESET}")
    if internet:
        _found("Internet", f"{C.GREEN}reachable — tools will be downloaded if missing{C.RESET}")
    else:
        _found("Internet", f"{C.YELLOW}not reachable — offline mode, using local tools only{C.RESET}")

    return {
        "privs":    privs,
        "domain":   domain,
        "network":  network,
        "user":     user,
        "internet": internet,
    }


# ---------------------------------------------------------------------------
# Phase 1 — Interactive Wizard (fills in what Phase 0 couldn't find)
# ---------------------------------------------------------------------------

def phase1_wizard(discovery):
    _section("PHASE 1 — Setup Wizard")

    d      = discovery
    is_top = d["privs"]["is_system"]

    # --- Auth context ---
    print(f"  {C.BOLD}Authentication{C.RESET}")

    if is_top:
        print(f"  {C.GREEN}[+]{C.RESET} Running as SYSTEM — no extra credentials needed for local enumeration.")
        _info("AD enumeration will use the machine account context.")
        auth = {"type": "system"}
    else:
        auth_type = _ask_choice(
            "What credentials do you have?",
            [
                ("domain_joined", "Already running as a domain user (no extra creds)"),
                ("user_pass",     "I have a domain username + password"),
                ("ntlm_hash",     "I have an NTLM hash (Pass-the-Hash)"),
                ("kerb_ticket",   "I have a Kerberos ticket (.ccache)"),
                ("nothing",       "No credentials — null session / anonymous only"),
            ],
            default="domain_joined"
        )

        auth = {"type": auth_type}

        if auth_type == "user_pass":
            auth["username"] = _ask("Domain username (e.g. CORP\\john or john@corp.local)")
            auth["password"] = _ask("Password", secret=True)

        elif auth_type == "ntlm_hash":
            auth["username"] = _ask("Domain username")
            auth["hash"]     = _ask("NTLM hash (format: LM:NT or just NT)")

        elif auth_type == "kerb_ticket":
            auth["ccache"] = _ask("Path to .ccache file")
            if auth["ccache"] and not os.path.exists(auth["ccache"]):
                print(f"  {C.YELLOW}[!] File not found — continuing anyway.{C.RESET}")

    # --- Target (pre-fill from discovery, ask only what's missing) ---
    print(f"\n  {C.BOLD}Target{C.RESET}")

    domain_val = d["domain"]["domain"]
    dc_ip_val  = d["domain"]["dc_ip"]

    if not domain_val:
        print(f"  {C.YELLOW}[!] Could not auto-detect domain. Please enter it manually.{C.RESET}")
        domain_val = _ask("Domain name (e.g. corp.local)")
    else:
        override = _ask(f"Domain name", default=domain_val)
        domain_val = override

    if not dc_ip_val:
        print(f"  {C.YELLOW}[!] Could not auto-detect DC IP. Please enter it manually.{C.RESET}")
        dc_ip_val = _ask("Domain Controller IP")
    else:
        override = _ask("Domain Controller IP", default=dc_ip_val)
        dc_ip_val = override

    target = {
        "domain":      domain_val,
        "dc_ip":       dc_ip_val,
        "dc_hostname": d["domain"]["dc_hostname"],
    }

    # --- Auto-determine scope from what the user told us ---
    scope = _auto_scope(auth, discovery)

    output_dir = _ask("\n  Output directory for reports", default="./results")
    os.makedirs(output_dir, exist_ok=True)
    scope["output_dir"] = output_dir

    return {"auth": auth, "target": target, "scope": scope}


def _auto_scope(auth, discovery):
    """
    Decide which tools to run based on auth context and environment.
    No manual tool selection — the script figures it out.
    """
    auth_type    = auth["type"]
    is_system    = discovery["privs"]["is_system"]
    is_admin     = discovery["privs"]["is_admin"]
    has_internet = discovery["internet"]
    has_domain   = bool(discovery["domain"]["domain"])

    scope = {
        # winPEAS: always useful for local enum (skip if already SYSTEM — we know we're top)
        "run_winpeas":    not is_system,

        # SharpHound: needs domain context
        "run_sharphound": has_domain and auth_type != "nothing",

        # PowerView: needs at least domain user creds or domain-joined context
        "run_powerview":  has_domain and auth_type in ("domain_joined", "user_pass", "ntlm_hash", "kerb_ticket", "system"),

        # Seatbelt: always useful for Windows config enum
        "run_seatbelt":   True,

        # PowerUp: skip if already SYSTEM (no point looking for privesc paths)
        "run_powerup":    not is_system,
    }

    # Print what we decided and why
    print(f"\n  {C.BOLD}What will run (auto-selected based on your context):{C.RESET}")
    reasons = {
        "run_winpeas":    "local Windows enumeration" if scope["run_winpeas"]    else "skipped — already SYSTEM",
        "run_sharphound": "BloodHound data collection" if scope["run_sharphound"] else "skipped — no domain/creds",
        "run_powerview":  "Active Directory enumeration" if scope["run_powerview"] else "skipped — no domain/creds",
        "run_seatbelt":   "Windows configuration checks",
        "run_powerup":    "local privilege escalation checks" if scope["run_powerup"] else "skipped — already SYSTEM",
    }
    labels = {
        "run_winpeas": "winPEAS", "run_sharphound": "SharpHound",
        "run_powerview": "PowerView", "run_seatbelt": "Seatbelt", "run_powerup": "PowerUp",
    }
    for key, label in labels.items():
        enabled = scope[key]
        icon    = f"{C.GREEN}[✓]{C.RESET}" if enabled else f"{C.DIM}[–]{C.RESET}"
        reason  = reasons[key]
        print(f"    {icon} {label:<14} {C.DIM}{reason}{C.RESET}")

    return scope


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run():
    if sys.platform == "win32":
        os.system("color")  # enable ANSI on Windows cmd

    print(C.RED + BANNER + C.RESET)

    discovery = phase0_discover()

    print(f"\n  {C.DIM}Press Enter to continue to the setup wizard...{C.RESET}", end="")
    input()

    config = phase1_wizard(discovery)
    config["discovery"] = discovery

    _section("Ready")
    print(f"  {C.GREEN}[✓]{C.RESET} Configuration complete. Starting enumeration...\n")

    return config


if __name__ == "__main__":
    cfg = run()
    print(json.dumps(cfg, indent=2, default=str))
