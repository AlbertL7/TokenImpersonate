#ifndef TOKEN_IMPERSONATE_H
#define TOKEN_IMPERSONATE_H

#include <windows.h>
#include <tlhelp32.h>

#define MAX_PROCESSES 1024

typedef struct ProcessInfo {
    DWORD PID;
    WCHAR Name_Process[260];
    CHAR Domain_User_Name[256];
    PSID SID_OwnerP;
    BOOL Valid;
    BOOL IsElevated;
    CHAR IntegrityLevel[32];
} ProcessInfo, *PProcessInfo;

typedef struct ProcessList {
    ProcessInfo processes[MAX_PROCESSES];
    int count;
} ProcessList, *PProcessList;

class tokenImpersonate {
public:
    void CombineUserDomainName(PCHAR Domain, PCHAR UserName, PCHAR Output, size_t OutputSize);
    BOOL GetProcessInfo(PROCESSENTRY32* processEntry32, PProcessInfo Process);
    PProcessList EnumerateProcesses();
    BOOL hasImpersonatePrivilege();
    BOOL EnableDebugPrivilege();
    int FindBestSystemProcess();  // NEW FUNCTION
    int ImpersonateTokenAndSpawnNewProcess(int TargetPID, PWCHAR ProcessToLaunch);
    int ImpersonateTokenAndExecuteCommand(int TargetPID, PWCHAR CommandLine);
    int FindProcessesByUsername(const char* username, int* pidArray, int maxPids);
    int BruteForceImpersonateByUsername(const char* username, PWCHAR command);
};

#endif
