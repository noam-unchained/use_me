"""
parser.py — Parses raw tool output into structured Finding objects.

Each Finding has:
  - id:          unique slug (e.g. "kerberoastable_users")
  - title:       short human-readable title
  - severity:    CRITICAL / HIGH / MEDIUM / LOW / INFO
  - category:    Kerberos / Delegation / ACL / LocalPrivesc / Enumeration / etc.
  - description: what was found
  - evidence:    list of raw evidence strings (usernames, hostnames, etc.)
  - tool:        which tool found it
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Severity → CSS color class used in the HTML report
SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffdd00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
}


@dataclass
class Finding:
    id:          str
    title:       str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    str
    description: str
    evidence:    List[str] = field(default_factory=list)
    tool:        str = ""
    raw_section: str = ""     # the raw output block that triggered this finding


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _extract_section(text, header):
    """Extract lines between two === HEADER === markers."""
    pattern = rf"===\s*{re.escape(header)}\s*===\s*\n(.*?)(?====|\Z)"
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _nonempty_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip()]


def _table_rows(text):
    """Return non-header, non-separator rows from a PS Format-Table output."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or set(line) <= set("- "):
            continue
        rows.append(line)
    return rows[2:] if len(rows) > 2 else []  # skip header + separator


# ---------------------------------------------------------------------------
# PowerView parsers
# ---------------------------------------------------------------------------

def _parse_kerberoastable(pv_text):
    section = _extract_section(pv_text, "KERBEROASTABLE USERS")
    rows = _table_rows(section)
    if not rows:
        return []
    return [Finding(
        id          = "kerberoastable_users",
        title       = "Kerberoastable Service Accounts",
        severity    = "HIGH",
        category    = "Kerberos",
        description = (
            f"Found {len(rows)} account(s) with Service Principal Names (SPNs). "
            "These can be Kerberoasted — any domain user can request their TGS tickets "
            "and crack them offline."
        ),
        evidence    = rows,
        tool        = "PowerView",
        raw_section = section,
    )]


def _parse_asrep(pv_text):
    section = _extract_section(pv_text, "ASREP ROASTABLE USERS")
    rows = _table_rows(section)
    if not rows:
        return []
    return [Finding(
        id          = "asrep_roastable",
        title       = "AS-REP Roastable Accounts",
        severity    = "HIGH",
        category    = "Kerberos",
        description = (
            f"Found {len(rows)} account(s) with 'Do not require Kerberos preauthentication' set. "
            "These can be AS-REP roasted without any credentials — you can request their AS-REP "
            "hash and crack it offline."
        ),
        evidence    = rows,
        tool        = "PowerView",
        raw_section = section,
    )]


def _parse_unconstrained_delegation(pv_text):
    section = _extract_section(pv_text, "UNCONSTRAINED DELEGATION")
    rows = _table_rows(section)
    # Filter out DCs (they have unconstrained delegation by design)
    non_dc = [r for r in rows if "DC" not in r.upper() and "DOMAIN CONTROLLER" not in r.upper()]
    if not non_dc:
        return []
    return [Finding(
        id          = "unconstrained_delegation",
        title       = "Unconstrained Delegation (Non-DC)",
        severity    = "CRITICAL",
        category    = "Delegation",
        description = (
            f"Found {len(non_dc)} non-DC machine(s)/account(s) with unconstrained delegation. "
            "If you can compromise any of these and coerce a DC to authenticate to them "
            "(e.g. via PrinterBug/SpoolSample), you can capture the DC's TGT and gain full domain control."
        ),
        evidence    = non_dc,
        tool        = "PowerView",
        raw_section = section,
    )]


def _parse_constrained_delegation(pv_text):
    section = _extract_section(pv_text, "CONSTRAINED DELEGATION")
    rows = _table_rows(section)
    if not rows:
        return []
    return [Finding(
        id          = "constrained_delegation",
        title       = "Constrained Delegation",
        severity    = "HIGH",
        category    = "Delegation",
        description = (
            f"Found {len(rows)} account(s) with constrained delegation configured. "
            "If compromised, S4U2Self/S4U2Proxy attacks may allow impersonating domain admin "
            "to the delegated service."
        ),
        evidence    = rows,
        tool        = "PowerView",
        raw_section = section,
    )]


def _parse_acl_misconfigs(pv_text):
    section = _extract_section(pv_text, "ACL MISCONFIGS")
    rows = _table_rows(section)
    if not rows:
        return []

    critical_rights = ["GenericAll", "WriteDACL", "WriteOwner"]
    high_rights     = ["GenericWrite", "ForceChangePassword"]

    critical = [r for r in rows if any(x.lower() in r.lower() for x in critical_rights)]
    high     = [r for r in rows if any(x.lower() in r.lower() for x in high_rights)]

    findings = []
    if critical:
        findings.append(Finding(
            id          = "acl_critical",
            title       = "Critical ACL Misconfigurations (GenericAll / WriteDACL / WriteOwner)",
            severity    = "CRITICAL",
            category    = "ACL",
            description = (
                f"Found {len(critical)} critical ACE(s). GenericAll/WriteDACL/WriteOwner on a "
                "high-value target (Domain Admin, Domain object) allows full takeover via "
                "DCSync, shadow credentials, or adding yourself to privileged groups."
            ),
            evidence    = critical,
            tool        = "PowerView",
            raw_section = section,
        ))
    if high:
        findings.append(Finding(
            id          = "acl_high",
            title       = "High-Risk ACL Misconfigurations (GenericWrite / ForceChangePassword)",
            severity    = "HIGH",
            category    = "ACL",
            description = (
                f"Found {len(high)} high-risk ACE(s). GenericWrite allows writing to sensitive "
                "attributes (SPN for targeted Kerberoasting, scriptPath for logon scripts). "
                "ForceChangePassword allows resetting a user's password without knowing it."
            ),
            evidence    = high,
            tool        = "PowerView",
            raw_section = section,
        ))
    return findings


def _parse_domain_trusts(pv_text):
    section = _extract_section(pv_text, "DOMAIN TRUSTS")
    rows = _table_rows(section)
    if not rows:
        return []
    return [Finding(
        id          = "domain_trusts",
        title       = "Domain Trusts Identified",
        severity    = "MEDIUM",
        category    = "Enumeration",
        description = (
            f"Found {len(rows)} domain trust(s). Bidirectional trusts or trusts with "
            "SID history enabled can allow cross-domain privilege escalation."
        ),
        evidence    = rows,
        tool        = "PowerView",
        raw_section = section,
    )]


def _parse_password_policy(pv_text):
    section = _extract_section(pv_text, "PASSWORD POLICY")
    lines   = _nonempty_lines(section)
    findings = []

    # Check lockout threshold
    for line in lines:
        if "LockoutBadCount" in line:
            m = re.search(r"LockoutBadCount\s*=\s*(\d+)", line)
            if m:
                count = int(m.group(1))
                if count == 0:
                    findings.append(Finding(
                        id          = "no_lockout",
                        title       = "No Account Lockout Policy",
                        severity    = "HIGH",
                        category    = "PasswordPolicy",
                        description = "Account lockout is disabled (LockoutBadCount = 0). Password spraying can be performed without risk of locking accounts.",
                        evidence    = [line],
                        tool        = "PowerView",
                        raw_section = section,
                    ))

        if "MinimumPasswordLength" in line:
            m = re.search(r"MinimumPasswordLength\s*=\s*(\d+)", line)
            if m and int(m.group(1)) < 8:
                findings.append(Finding(
                    id          = "weak_password_policy",
                    title       = "Weak Minimum Password Length",
                    severity    = "MEDIUM",
                    category    = "PasswordPolicy",
                    description = f"Minimum password length is {m.group(1)} characters — below recommended 12+.",
                    evidence    = [line],
                    tool        = "PowerView",
                    raw_section = section,
                ))

    if not findings:
        findings.append(Finding(
            id          = "password_policy_info",
            title       = "Password Policy",
            severity    = "INFO",
            category    = "PasswordPolicy",
            description = "Password policy was retrieved. No immediately exploitable misconfigurations detected.",
            evidence    = lines[:10],
            tool        = "PowerView",
            raw_section = section,
        ))

    return findings


def _parse_domain_info(pv_text):
    section = _extract_section(pv_text, "DOMAIN INFO")
    lines   = _nonempty_lines(section)
    return [Finding(
        id          = "domain_info",
        title       = "Domain Information",
        severity    = "INFO",
        category    = "Enumeration",
        description = "Basic domain information collected.",
        evidence    = lines[:15],
        tool        = "PowerView",
        raw_section = section,
    )] if lines else []


def _parse_domain_admins(pv_text):
    section = _extract_section(pv_text, "DOMAIN ADMINS")
    rows    = _table_rows(section)
    return [Finding(
        id          = "domain_admins",
        title       = f"Domain Admins ({len(rows)} members)",
        severity    = "INFO",
        category    = "Enumeration",
        description = "Members of the Domain Admins group. These are your targets.",
        evidence    = rows,
        tool        = "PowerView",
        raw_section = section,
    )] if rows else []


# ---------------------------------------------------------------------------
# winPEAS parsers
# ---------------------------------------------------------------------------

def _parse_winpeas(text):
    findings = []

    # AlwaysInstallElevated
    if re.search(r"AlwaysInstallElevated.*1", text, re.IGNORECASE):
        findings.append(Finding(
            id          = "always_install_elevated",
            title       = "AlwaysInstallElevated Enabled",
            severity    = "CRITICAL",
            category    = "LocalPrivesc",
            description = (
                "AlwaysInstallElevated is enabled in both HKLM and HKCU. "
                "Any user can install an MSI package as SYSTEM."
            ),
            evidence    = ["AlwaysInstallElevated = 1 (both HKLM and HKCU)"],
            tool        = "winPEAS",
        ))

    # Unquoted service paths
    unquoted = re.findall(
        r"Unquoted Service Path[^\n]*\n([^\n]+)", text, re.IGNORECASE
    )
    if unquoted:
        findings.append(Finding(
            id          = "unquoted_service_paths",
            title       = f"Unquoted Service Paths ({len(unquoted)} found)",
            severity    = "HIGH",
            category    = "LocalPrivesc",
            description = (
                "Service(s) with unquoted paths containing spaces. If you can write to "
                "a directory in the path, you can plant a binary that runs as SYSTEM when "
                "the service starts."
            ),
            evidence    = unquoted[:10],
            tool        = "winPEAS",
        ))

    # Weak service permissions
    weak_svc = re.findall(
        r"([\w\s]+) \(.*?WRITE_DAC|WRITE_OWNER|ALL_ACCESS|SERVICE_ALL_ACCESS.*?\)",
        text, re.IGNORECASE
    )
    if weak_svc:
        findings.append(Finding(
            id          = "weak_service_permissions",
            title       = f"Weak Service Permissions ({len(weak_svc)} found)",
            severity    = "HIGH",
            category    = "LocalPrivesc",
            description = (
                "Service(s) where the current user has write permissions. "
                "You can replace the binary path or reconfigure the service to run your own payload as SYSTEM."
            ),
            evidence    = weak_svc[:10],
            tool        = "winPEAS",
        ))

    # Stored credentials / cmdkey
    creds = re.findall(r"(cmdkey|Credential Manager|stored credentials)[^\n]*\n([^\n]+)", text, re.IGNORECASE)
    if creds:
        findings.append(Finding(
            id          = "stored_credentials",
            title       = "Stored Credentials Found",
            severity    = "HIGH",
            category    = "LocalPrivesc",
            description = "Credentials stored in Windows Credential Manager or via cmdkey.",
            evidence    = [f"{a}: {b}" for a, b in creds[:10]],
            tool        = "winPEAS",
        ))

    # Autologon credentials
    autologon = re.findall(r"(AutoAdminLogon|DefaultUserName|DefaultPassword)[^\n]*", text, re.IGNORECASE)
    if autologon:
        findings.append(Finding(
            id          = "autologon_creds",
            title       = "AutoLogon Credentials in Registry",
            severity    = "CRITICAL",
            category    = "LocalPrivesc",
            description = "AutoLogon credentials found in the registry — plaintext username and possibly password.",
            evidence    = autologon[:5],
            tool        = "winPEAS",
        ))

    # Modifiable scheduled tasks
    sched = re.findall(r"(Task.*?modifiable|ScheduledTask.*?write)[^\n]*", text, re.IGNORECASE)
    if sched:
        findings.append(Finding(
            id          = "weak_scheduled_tasks",
            title       = f"Modifiable Scheduled Tasks ({len(sched)} found)",
            severity    = "MEDIUM",
            category    = "LocalPrivesc",
            description = "Scheduled task(s) whose binary the current user can modify.",
            evidence    = sched[:10],
            tool        = "winPEAS",
        ))

    # Interesting files (passwords in files)
    pw_files = re.findall(r"(?:password|passwd|credentials?)[^\n]*\.(?:txt|xml|ini|config|cfg)[^\n]*", text, re.IGNORECASE)
    if pw_files:
        findings.append(Finding(
            id          = "password_files",
            title       = f"Potential Credential Files ({len(pw_files)} found)",
            severity    = "MEDIUM",
            category    = "LocalPrivesc",
            description = "Files whose names or paths suggest they may contain credentials.",
            evidence    = pw_files[:15],
            tool        = "winPEAS",
        ))

    return findings


# ---------------------------------------------------------------------------
# PowerUp parsers
# ---------------------------------------------------------------------------

def _parse_powerup(text):
    findings = []

    # ModifiableServiceFile
    mods = re.findall(r"ModifiableFile\s*:\s*([^\n]+)", text, re.IGNORECASE)
    if mods:
        findings.append(Finding(
            id          = "modifiable_service_files",
            title       = f"Modifiable Service Binaries ({len(mods)} found)",
            severity    = "HIGH",
            category    = "LocalPrivesc",
            description = "Current user can overwrite the binary for a service that runs as SYSTEM.",
            evidence    = mods[:10],
            tool        = "PowerUp",
        ))

    # TokenPrivileges
    privs = re.findall(r"(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege|SeDebugPrivilege)[^\n]*", text)
    if privs:
        findings.append(Finding(
            id          = "token_privileges",
            title       = "Dangerous Token Privileges",
            severity    = "HIGH",
            category    = "LocalPrivesc",
            description = (
                "Dangerous token privilege(s) assigned to current user. "
                "SeImpersonate/SeAssignPrimaryToken → Potato attacks (GodPotato, PrintSpoofer). "
                "SeDebug → inject into SYSTEM processes. SeTcb → act as part of the OS."
            ),
            evidence    = list(set(privs)),
            tool        = "PowerUp",
        ))

    return findings


# ---------------------------------------------------------------------------
# Seatbelt parsers
# ---------------------------------------------------------------------------

def _parse_seatbelt(text):
    findings = []

    # LAPS
    if re.search(r"LAPS.*?not installed|LAPSv2.*?not installed", text, re.IGNORECASE):
        findings.append(Finding(
            id          = "no_laps",
            title       = "LAPS Not Installed",
            severity    = "MEDIUM",
            category    = "Enumeration",
            description = "Local Administrator Password Solution (LAPS) is not deployed. Local admin passwords may be shared across machines (pass-the-hash lateral movement).",
            evidence    = ["LAPS not detected"],
            tool        = "Seatbelt",
        ))

    # WSL
    if re.search(r"WSL.*installed|WindowsSubsystemLinux", text, re.IGNORECASE):
        findings.append(Finding(
            id          = "wsl_installed",
            title       = "WSL Installed",
            severity    = "LOW",
            category    = "LocalPrivesc",
            description = "Windows Subsystem for Linux is installed. May be leveraged for living-off-the-land techniques or pivoting.",
            evidence    = ["WSL detected"],
            tool        = "Seatbelt",
        ))

    # PowerShell v2
    if re.search(r"PowerShell v2.*enabled|PSVersion.*2\.", text, re.IGNORECASE):
        findings.append(Finding(
            id          = "powershell_v2",
            title       = "PowerShell v2 Enabled",
            severity    = "MEDIUM",
            category    = "Defense Evasion",
            description = "PowerShell version 2 is enabled. It lacks ScriptBlock logging and AMSI — useful for AV evasion.",
            evidence    = ["PowerShell v2 detected"],
            tool        = "Seatbelt",
        ))

    # AppLocker
    if re.search(r"AppLocker.*not configured|AppLocker.*disabled", text, re.IGNORECASE):
        findings.append(Finding(
            id          = "no_applocker",
            title       = "AppLocker Not Configured",
            severity    = "LOW",
            category    = "Defense Evasion",
            description = "AppLocker is not configured — no application whitelisting in place.",
            evidence    = ["AppLocker not configured"],
            tool        = "Seatbelt",
        ))

    return findings


# ---------------------------------------------------------------------------
# Loot collector — structured intel table for the report
# ---------------------------------------------------------------------------

def collect_loot(raw_outputs: dict, config: dict) -> dict:
    """
    Extract structured loot from raw tool outputs for the summary table.
    Returns a dict with lists of strings for each category.
    """
    pv = raw_outputs.get("powerview", "")
    wp = raw_outputs.get("winpeas",   "")
    sb = raw_outputs.get("seatbelt",  "")

    loot = {
        "domain_users":        [],
        "domain_admins":       [],
        "domain_computers":    [],
        "domain_controllers":  [],
        "kerberoastable":      [],
        "asrep_roastable":     [],
        "spns":                [],
        "hashes_found":        [],
        "passwords_found":     [],
        "interesting_files":   [],
        "password_policy":     [],
        "domain_trusts":       [],
        "gpos":                [],
    }

    if pv:
        # Domain users (samaccountname column, first word per row)
        section = _extract_section(pv, "DOMAIN USERS")
        for row in _table_rows(section):
            name = row.split()[0]
            if name and name not in ("samaccountname",):
                loot["domain_users"].append(name)

        # Domain admins
        section = _extract_section(pv, "DOMAIN ADMINS")
        for row in _table_rows(section):
            name = row.split()[0]
            if name:
                loot["domain_admins"].append(name)

        # Computers
        section = _extract_section(pv, "DOMAIN COMPUTERS")
        for row in _table_rows(section):
            parts = row.split()
            if parts:
                loot["domain_computers"].append(parts[0])

        # Domain controllers
        section = _extract_section(pv, "DOMAIN CONTROLLERS")
        for line in _nonempty_lines(section):
            if "Name" in line or "dnshostname" in line.lower():
                val = line.split(":")[-1].strip()
                if val:
                    loot["domain_controllers"].append(val)

        # Kerberoastable
        section = _extract_section(pv, "KERBEROASTABLE USERS")
        for row in _table_rows(section):
            parts = row.split()
            if parts:
                user = parts[0]
                spn  = parts[1] if len(parts) > 1 else ""
                loot["kerberoastable"].append(user)
                if spn:
                    loot["spns"].append(f"{user} → {spn}")

        # AS-REP roastable
        section = _extract_section(pv, "ASREP ROASTABLE USERS")
        for row in _table_rows(section):
            name = row.split()[0]
            if name:
                loot["asrep_roastable"].append(name)

        # Password policy key values
        section = _extract_section(pv, "PASSWORD POLICY")
        for line in _nonempty_lines(section):
            for key in ("MinimumPasswordLength", "LockoutBadCount", "PasswordHistorySize",
                        "MaximumPasswordAge", "PasswordComplexity"):
                if key in line:
                    loot["password_policy"].append(line.strip())

        # Trusts
        section = _extract_section(pv, "DOMAIN TRUSTS")
        for row in _table_rows(section):
            if row:
                loot["domain_trusts"].append(row)

        # GPOs
        section = _extract_section(pv, "GPO LIST")
        for row in _table_rows(section):
            name = row.split()[0] if row.split() else ""
            if name:
                loot["gpos"].append(name)

    if wp:
        # NTLM hashes from winPEAS (SAM / LSASS dump hints)
        hashes = re.findall(r"([a-fA-F0-9]{32}:[a-fA-F0-9]{32})", wp)
        loot["hashes_found"] = list(set(hashes))[:20]

        # Cleartext passwords
        pw_matches = re.findall(
            r"(?:password|pwd|pass)\s*[=:]\s*([^\s\n]{4,})", wp, re.IGNORECASE
        )
        loot["passwords_found"] = list(set(pw_matches))[:20]

        # Interesting files
        files = re.findall(
            r"(?:C:\\[^\s\n]*\.(?:txt|xml|ini|config|cfg|bat|ps1|kdbx|rdg|vnc))",
            wp, re.IGNORECASE
        )
        loot["interesting_files"] = list(set(files))[:20]

    return loot


# ---------------------------------------------------------------------------
# Main parse entry point
# ---------------------------------------------------------------------------

def parse_all(raw_outputs: dict) -> List[Finding]:
    """
    Takes the dict of {tool_name: raw_output_string} from runner.py
    and returns a sorted list of Finding objects.
    """
    findings = []

    pv = raw_outputs.get("powerview", "")
    if pv:
        findings += _parse_kerberoastable(pv)
        findings += _parse_asrep(pv)
        findings += _parse_unconstrained_delegation(pv)
        findings += _parse_constrained_delegation(pv)
        findings += _parse_acl_misconfigs(pv)
        findings += _parse_domain_trusts(pv)
        findings += _parse_password_policy(pv)
        findings += _parse_domain_info(pv)
        findings += _parse_domain_admins(pv)

    wp = raw_outputs.get("winpeas", "")
    if wp:
        findings += _parse_winpeas(wp)

    pu = raw_outputs.get("powerup", "")
    if pu:
        findings += _parse_powerup(pu)

    sb = raw_outputs.get("seatbelt", "")
    if sb:
        findings += _parse_seatbelt(sb)

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    return findings
