/*
 * enum_tokens_bof.c
 *
 * BOF version of enum_tokens.c -- enumerates accessible process tokens
 * and evaluates impersonation viability.
 *
 * Arguments (packed via bof_pack):
 *   int  target_pid   - 0 for all processes, >0 for specific PID
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c -o enum_tokens_bof.x64.o enum_tokens_bof.c
 */

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ── Win32 API declarations (DFR) ──────────────────────────────────── */

/* kernel32 */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);

/* advapi32 */
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$PrivilegeCheck(HANDLE, PPRIVILEGE_SET, LPBOOL);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT DWORD  WINAPI ADVAPI32$GetLengthSid(PSID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CopySid(DWORD, PSID, PSID);
DECLSPEC_IMPORT PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);

/* msvcrt */
DECLSPEC_IMPORT void  *MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   MSVCRT$free(void*);
DECLSPEC_IMPORT int    MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT void  *MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    MSVCRT$_snprintf(char*, size_t, const char*, ...);

/* ── Interesting privileges ────────────────────────────────────────── */

static const char *interesting_privs[] = {
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeCreateTokenPrivilege",
    "SeEnableDelegationPrivilege",
    "SeMachineAccountPrivilege",
    "SeRelabelPrivilege",
    NULL
};

static BOOL is_interesting_priv(const char *name) {
    for (const char **p = interesting_privs; *p; p++)
        if (MSVCRT$_stricmp(name, *p) == 0) return TRUE;
    return FALSE;
}

/* ── Token helpers ─────────────────────────────────────────────────── */

static DWORD get_integrity_rid(HANDLE tok) {
    DWORD len = 0;
    ADVAPI32$GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);
    if (!len) return 0;

    TOKEN_MANDATORY_LABEL *tml = MSVCRT$malloc(len);
    if (!tml) return 0;

    DWORD rid = 0;
    if (ADVAPI32$GetTokenInformation(tok, TokenIntegrityLevel, tml, len, &len)) {
        BYTE count = *ADVAPI32$GetSidSubAuthorityCount(tml->Label.Sid);
        rid = *ADVAPI32$GetSidSubAuthority(tml->Label.Sid, count - 1);
    }
    MSVCRT$free(tml);
    return rid;
}

static PSID get_token_user_sid(HANDLE tok) {
    DWORD len = 0;
    ADVAPI32$GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    if (!len) return NULL;

    TOKEN_USER *tu = MSVCRT$malloc(len);
    if (!tu) return NULL;

    PSID copy = NULL;
    if (ADVAPI32$GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        DWORD sidlen = ADVAPI32$GetLengthSid(tu->User.Sid);
        copy = MSVCRT$malloc(sidlen);
        if (copy) ADVAPI32$CopySid(sidlen, copy, tu->User.Sid);
    }
    MSVCRT$free(tu);
    return copy;
}

static BOOL has_privilege_enabled(HANDLE tok, const char *priv_name) {
    LUID luid;
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, priv_name, &luid))
        return FALSE;

    PRIVILEGE_SET ps;
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    ps.Privilege[0].Luid = luid;
    ps.Privilege[0].Attributes = 0;

    BOOL result = FALSE;
    ADVAPI32$PrivilegeCheck(tok, &ps, &result);
    return result;
}

static SECURITY_IMPERSONATION_LEVEL get_imp_level(HANDLE tok) {
    TOKEN_TYPE tt;
    DWORD len;
    if (!ADVAPI32$GetTokenInformation(tok, TokenType, &tt, sizeof(tt), &len))
        return SecurityImpersonation;
    if (tt == TokenPrimary)
        return SecurityImpersonation;

    SECURITY_IMPERSONATION_LEVEL il = SecurityAnonymous;
    ADVAPI32$GetTokenInformation(tok, TokenImpersonationLevel, &il, sizeof(il), &len);
    return il;
}

/* ── Caller context ────────────────────────────────────────────────── */

typedef struct {
    PSID  user_sid;
    DWORD integrity_rid;
    BOOL  has_impersonate_priv;
} caller_ctx;

static void init_caller_ctx(caller_ctx *ctx) {
    MSVCRT$memset(ctx, 0, sizeof(*ctx));
    HANDLE tok;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok))
        return;
    ctx->user_sid             = get_token_user_sid(tok);
    ctx->integrity_rid        = get_integrity_rid(tok);
    ctx->has_impersonate_priv = has_privilege_enabled(tok, "SeImpersonatePrivilege");
    KERNEL32$CloseHandle(tok);
}

/* ── Impersonation verdict ─────────────────────────────────────────── */

typedef enum { IMP_USABLE, IMP_IDENTIFICATION_ONLY, IMP_RESTRICTED } imp_verdict;

static const char *verdict_str(imp_verdict v) {
    switch (v) {
    case IMP_USABLE:              return "USABLE";
    case IMP_IDENTIFICATION_ONLY: return "IDENT_ONLY";
    case IMP_RESTRICTED:          return "RESTRICTED";
    }
    return "?";
}

static imp_verdict evaluate_impersonation(HANDLE target_tok, caller_ctx *ctx) {
    SECURITY_IMPERSONATION_LEVEL il = get_imp_level(target_tok);
    if (il < SecurityImpersonation)
        return IMP_IDENTIFICATION_ONLY;
    if (ctx->has_impersonate_priv)
        return IMP_USABLE;

    DWORD target_il = get_integrity_rid(target_tok);
    PSID  target_sid = get_token_user_sid(target_tok);
    BOOL  same_user = target_sid && ctx->user_sid &&
                      ADVAPI32$EqualSid(ctx->user_sid, target_sid);
    MSVCRT$free(target_sid);

    if (ctx->integrity_rid <= target_il && same_user)
        return IMP_USABLE;
    return IMP_RESTRICTED;
}

/* ── Display helpers ───────────────────────────────────────────────── */

static const char *integrity_str(DWORD rid) {
    switch (rid) {
    case SECURITY_MANDATORY_UNTRUSTED_RID:   return "Untrusted";
    case SECURITY_MANDATORY_LOW_RID:         return "Low";
    case SECURITY_MANDATORY_MEDIUM_RID:      return "Medium";
    case SECURITY_MANDATORY_MEDIUM_PLUS_RID: return "Medium+";
    case SECURITY_MANDATORY_HIGH_RID:        return "High";
    case SECURITY_MANDATORY_SYSTEM_RID:      return "System";
    default:                                 return "Unknown";
    }
}

static void enable_debug_priv(void) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok))
        return;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

/* ── Print token for a single process ──────────────────────────────── */

static void print_process_token(DWORD pid, const char *name, caller_ctx *ctx) {
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc)
        proc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PID %-6lu %-22s ACCESS DENIED", pid, name);
        return;
    }

    HANDLE tok;
    if (!ADVAPI32$OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PID %-6lu %-22s OpenProcessToken DENIED (err %lu)",
                     pid, name, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(proc);
        return;
    }

    char user[128] = "?", sid_buf[80] = "?";
    PSID sid = get_token_user_sid(tok);
    if (sid) {
        char uname[256] = {0}, domain[256] = {0};
        DWORD nlen = sizeof(uname), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (ADVAPI32$LookupAccountSidA(NULL, sid, uname, &nlen, domain, &dlen, &use)) {
            if (domain[0])
                MSVCRT$_snprintf(user, sizeof(user), "%s\\%s", domain, uname);
            else
                MSVCRT$_snprintf(user, sizeof(user), "%s", uname);
        }
        char *ss = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(sid, &ss)) {
            MSVCRT$_snprintf(sid_buf, sizeof(sid_buf), "%s", ss);
            KERNEL32$LocalFree(ss);
        }
        MSVCRT$free(sid);
    }

    DWORD rid = get_integrity_rid(tok);
    imp_verdict v = evaluate_impersonation(tok, ctx);

    BeaconPrintf(CALLBACK_OUTPUT,
        "PID %-6lu %-22s %-28s %-26s %-10s %s",
        pid, name, user, sid_buf, integrity_str(rid), verdict_str(v));

    /* Print interesting enabled privileges */
    DWORD plen = 0;
    ADVAPI32$GetTokenInformation(tok, TokenPrivileges, NULL, 0, &plen);
    if (plen) {
        TOKEN_PRIVILEGES *tp = MSVCRT$malloc(plen);
        if (tp && ADVAPI32$GetTokenInformation(tok, TokenPrivileges, tp, plen, &plen)) {
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                char pname[256];
                DWORD pnlen = sizeof(pname);
                if (!ADVAPI32$LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, pname, &pnlen))
                    continue;
                if (is_interesting_priv(pname) && (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                    BeaconPrintf(CALLBACK_OUTPUT, "  >> %s (Enabled)", pname);
            }
        }
        MSVCRT$free(tp);
    }

    KERNEL32$CloseHandle(tok);
    KERNEL32$CloseHandle(proc);
}

/* ── BOF entry point ───────────────────────────────────────────────── */

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int target_pid = BeaconDataInt(&parser);

    enable_debug_priv();

    caller_ctx ctx;
    init_caller_ctx(&ctx);

    /* Print caller context */
    {
        char *sid_str = NULL;
        if (ctx.user_sid && ADVAPI32$ConvertSidToStringSidA(ctx.user_sid, &sid_str)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Caller: %s  Integrity: %s (0x%04lx)  SeImpersonate: %s",
                         sid_str, integrity_str(ctx.integrity_rid), ctx.integrity_rid,
                         ctx.has_impersonate_priv ? "YES" : "NO");
            KERNEL32$LocalFree(sid_str);
        }
        BeaconPrintf(CALLBACK_OUTPUT,
            "%-8s %-22s %-28s %-26s %-10s %s",
            "PID", "PROCESS", "USER", "SID", "INTEGRITY", "VERDICT");
    }

    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: %lu",
                     KERNEL32$GetLastError());
        MSVCRT$free(ctx.user_sid);
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!KERNEL32$Process32First(snap, &pe)) {
        KERNEL32$CloseHandle(snap);
        MSVCRT$free(ctx.user_sid);
        return;
    }

    do {
        if (target_pid > 0 && pe.th32ProcessID != (DWORD)target_pid)
            continue;
        print_process_token(pe.th32ProcessID, pe.szExeFile, &ctx);
    } while (KERNEL32$Process32Next(snap, &pe));

    KERNEL32$CloseHandle(snap);
    MSVCRT$free(ctx.user_sid);
}
