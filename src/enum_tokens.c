/*
 * enum_tokens.c
 *
 * Enumerates accessible process tokens and evaluates whether the current
 * process could use each token for impersonation, based on the Windows
 * impersonation access check:
 *
 *   1. If token imp level < SecurityImpersonation -> ALLOW (identification
 *      only, can't run code -- harmless).
 *   2. If caller has SeImpersonatePrivilege -> ALLOW.
 *   3. If caller integrity <= token integrity AND caller user == token user
 *      -> ALLOW, else restrict to Identification level.
 *
 * Usage:
 *   enum_tokens.exe              - dump all process tokens
 *   enum_tokens.exe 1234         - target a specific PID
 *   enum_tokens.exe notepad.exe  - target by process name
 *
 * Cross-compile from macOS:
 *   x86_64-w64-mingw32-gcc -o enum_tokens.exe enum_tokens.c -ladvapi32
 */

#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── ANSI color support ────────────────────────────────────────────── */

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static BOOL g_color = FALSE;

static void init_console_color(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(out, &mode)) {
        if (SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            g_color = TRUE;
    }
}

#define C_RESET   (g_color ? "\033[0m"    : "")
#define C_RED     (g_color ? "\033[1;31m" : "")
#define C_GREEN   (g_color ? "\033[1;32m" : "")
#define C_YELLOW  (g_color ? "\033[1;33m" : "")
#define C_CYAN    (g_color ? "\033[1;36m" : "")

/* Privileges worth paying attention to -- commonly abused for
   escalation, impersonation, or credential access. */
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
        if (_stricmp(name, *p) == 0) return TRUE;
    return FALSE;
}

/* ── helpers to query token properties ─────────────────────────────── */

static DWORD get_integrity_rid(HANDLE tok) {
    DWORD len = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);
    if (!len) return 0;

    TOKEN_MANDATORY_LABEL *tml = malloc(len);
    if (!tml) return 0;

    DWORD rid = 0;
    if (GetTokenInformation(tok, TokenIntegrityLevel, tml, len, &len)) {
        BYTE count = *GetSidSubAuthorityCount(tml->Label.Sid);
        rid = *GetSidSubAuthority(tml->Label.Sid, count - 1);
    }
    free(tml);
    return rid;
}

/* Returns a malloc'd SID; caller must free(). NULL on failure. */
static PSID get_token_user_sid(HANDLE tok) {
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    if (!len) return NULL;

    TOKEN_USER *tu = malloc(len);
    if (!tu) return NULL;

    PSID copy = NULL;
    if (GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        DWORD sidlen = GetLengthSid(tu->User.Sid);
        copy = malloc(sidlen);
        if (copy) CopySid(sidlen, copy, tu->User.Sid);
    }
    free(tu);
    return copy;
}

static BOOL has_privilege_enabled(HANDLE tok, const char *priv_name) {
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, priv_name, &luid))
        return FALSE;

    PRIVILEGE_SET ps;
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    ps.Privilege[0].Luid = luid;
    ps.Privilege[0].Attributes = 0;

    BOOL result = FALSE;
    PrivilegeCheck(tok, &ps, &result);
    return result;
}

static SECURITY_IMPERSONATION_LEVEL get_imp_level(HANDLE tok) {
    TOKEN_TYPE tt;
    DWORD len;
    if (!GetTokenInformation(tok, TokenType, &tt, sizeof(tt), &len))
        return SecurityImpersonation; /* assume worst case */
    if (tt == TokenPrimary)
        return SecurityImpersonation; /* primary tokens are usable */

    SECURITY_IMPERSONATION_LEVEL il = SecurityAnonymous;
    GetTokenInformation(tok, TokenImpersonationLevel, &il, sizeof(il), &len);
    return il;
}

/* ── caller context (cached once at startup) ───────────────────────── */

typedef struct {
    PSID  user_sid;
    DWORD integrity_rid;
    BOOL  has_impersonate_priv;
} caller_ctx;

static caller_ctx g_caller;

static void init_caller_ctx(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return;
    g_caller.user_sid            = get_token_user_sid(tok);
    g_caller.integrity_rid       = get_integrity_rid(tok);
    g_caller.has_impersonate_priv = has_privilege_enabled(tok, "SeImpersonatePrivilege");
    CloseHandle(tok);
}

/* ── impersonation usability check (the core logic) ────────────────── */

typedef enum { IMP_USABLE, IMP_IDENTIFICATION_ONLY, IMP_RESTRICTED } imp_verdict;

static const char *verdict_str(imp_verdict v) {
    switch (v) {
    case IMP_USABLE:              return "USABLE (full impersonation)";
    case IMP_IDENTIFICATION_ONLY: return "IDENTIFICATION ONLY (token level too low to run code)";
    case IMP_RESTRICTED:          return "RESTRICTED to Identification (would be downgraded)";
    }
    return "UNKNOWN";
}

static const char *verdict_reason(imp_verdict v, SECURITY_IMPERSONATION_LEVEL il,
                                  BOOL same_user, DWORD caller_il, DWORD target_il) {
    static char buf[256];
    switch (v) {
    case IMP_IDENTIFICATION_ONLY:
        _snprintf(buf, sizeof(buf), "imp level = %s (< Impersonation)",
                  il == SecurityAnonymous ? "Anonymous" : "Identification");
        break;
    case IMP_USABLE:
        if (il < SecurityImpersonation)
            _snprintf(buf, sizeof(buf), "identification level -- harmless");
        else
            _snprintf(buf, sizeof(buf), "SeImpersonatePrivilege held by caller");
        if (!g_caller.has_impersonate_priv)
            _snprintf(buf, sizeof(buf), "same user + caller integrity 0x%04lx <= target 0x%04lx",
                      caller_il, target_il);
        break;
    case IMP_RESTRICTED:
        _snprintf(buf, sizeof(buf), "different user or caller integrity 0x%04lx > target 0x%04lx",
                  caller_il, target_il);
        break;
    }
    return buf;
}

/*
 * Evaluate whether our process could impersonate the given target token.
 *
 *   1. level < Impersonation  -> identification only (allow, but can't run code)
 *   2. caller has SeImpersonatePrivilege -> usable
 *   3. caller integrity <= target integrity AND same user -> usable
 *      else -> restricted to identification
 */
static imp_verdict evaluate_impersonation(HANDLE target_tok) {
    SECURITY_IMPERSONATION_LEVEL il = get_imp_level(target_tok);

    /* Rule 1: below Impersonation level -- harmless, can't execute code */
    if (il < SecurityImpersonation)
        return IMP_IDENTIFICATION_ONLY;

    /* Rule 2: caller holds SeImpersonatePrivilege */
    if (g_caller.has_impersonate_priv)
        return IMP_USABLE;

    /* Rule 3: integrity + user check */
    DWORD target_il = get_integrity_rid(target_tok);
    PSID  target_sid = get_token_user_sid(target_tok);
    BOOL  same_user = target_sid && g_caller.user_sid &&
                      EqualSid(g_caller.user_sid, target_sid);
    free(target_sid);

    if (g_caller.integrity_rid <= target_il && same_user)
        return IMP_USABLE;

    return IMP_RESTRICTED;
}

/* ── display helpers ───────────────────────────────────────────────── */

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

static const char *imp_level_str(SECURITY_IMPERSONATION_LEVEL lvl) {
    switch (lvl) {
    case SecurityAnonymous:      return "Anonymous";
    case SecurityIdentification: return "Identification";
    case SecurityImpersonation:  return "Impersonation";
    case SecurityDelegation:     return "Delegation";
    default:                     return "Unknown";
    }
}

static void print_sid_inline(PSID sid, const char *label) {
    char *str = NULL;
    char name[256] = {0}, domain[256] = {0};
    DWORD name_len = sizeof(name), domain_len = sizeof(domain);
    SID_NAME_USE use;

    if (LookupAccountSidA(NULL, sid, name, &name_len, domain, &domain_len, &use)) {
        if (domain[0])
            printf("  %-15s: %s\\%s\n", label, domain, name);
        else
            printf("  %-15s: %s\n", label, name);
    }

    if (ConvertSidToStringSidA(sid, &str)) {
        printf("  %-15s: %s\n", "SID", str);
        LocalFree(str);
    }
}

static void print_token_info(HANDLE tok) {
    /* Type + impersonation level */
    TOKEN_TYPE tt;
    DWORD len;
    if (GetTokenInformation(tok, TokenType, &tt, sizeof(tt), &len)) {
        printf("  Token Type     : %s\n", tt == TokenPrimary ? "Primary" : "Impersonation");
        if (tt == TokenImpersonation) {
            SECURITY_IMPERSONATION_LEVEL il;
            if (GetTokenInformation(tok, TokenImpersonationLevel, &il, sizeof(il), &len))
                printf("  Imp. Level     : %s\n", imp_level_str(il));
        }
    }

    /* User SID */
    PSID sid = get_token_user_sid(tok);
    if (sid) { print_sid_inline(sid, "User SID"); free(sid); }

    /* Integrity */
    DWORD rid = get_integrity_rid(tok);
    printf("  Integrity      : %s (0x%04lx)\n", integrity_str(rid), rid);
}

static void print_privileges(HANDLE tok) {
    DWORD len = 0;
    GetTokenInformation(tok, TokenPrivileges, NULL, 0, &len);
    if (!len) return;

    TOKEN_PRIVILEGES *tp = malloc(len);
    if (!tp) return;

    if (GetTokenInformation(tok, TokenPrivileges, tp, len, &len)) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            char name[256];
            DWORD nlen = sizeof(name);
            if (!LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &nlen))
                continue;

            DWORD attr = tp->Privileges[i].Attributes;
            const char *state = (attr & SE_PRIVILEGE_ENABLED) ? "Enabled" :
                                (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? "Default" : "Disabled";

            BOOL interesting = is_interesting_priv(name);
            BOOL hot = interesting && (attr & SE_PRIVILEGE_ENABLED);

            if (hot)
                printf("    %s%-40s %s%s  <<\n", C_CYAN, name, state, C_RESET);
            else if (interesting)
                printf("    %s%-40s %s%s\n", C_YELLOW, name, state, C_RESET);
            else
                printf("    %-40s %s\n", name, state);
        }
    }
    free(tp);
}

static void print_impersonation_verdict(HANDLE tok) {
    imp_verdict v = evaluate_impersonation(tok);

    SECURITY_IMPERSONATION_LEVEL il = get_imp_level(tok);
    DWORD target_il = get_integrity_rid(tok);
    PSID  target_sid = get_token_user_sid(tok);
    BOOL  same_user = target_sid && g_caller.user_sid &&
                      EqualSid(g_caller.user_sid, target_sid);
    free(target_sid);

    const char *color;
    switch (v) {
    case IMP_USABLE:              color = C_GREEN;  break;
    case IMP_IDENTIFICATION_ONLY: color = C_YELLOW; break;
    case IMP_RESTRICTED:          color = C_RED;    break;
    default:                      color = C_RESET;  break;
    }

    printf("  Imp. Verdict   : %s%s%s\n", color, verdict_str(v), C_RESET);
    printf("  Reason         : %s\n",
           verdict_reason(v, il, same_user, g_caller.integrity_rid, target_il));
}

/* ── PPL (Protected Process Light) detection ───────────────────────── */

#define ProcessProtectionInformation 61

typedef struct {
    UCHAR Type;
    UCHAR Audit;
    UCHAR Signer;
} PS_PROTECTION;

typedef LONG (NTAPI *NtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtQueryInformationProcess_t pNtQueryInformationProcess;

static void init_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        pNtQueryInformationProcess = (NtQueryInformationProcess_t)
            GetProcAddress(ntdll, "NtQueryInformationProcess");
}

static BOOL is_process_protected(HANDLE proc, PS_PROTECTION *prot) {
    if (!pNtQueryInformationProcess) return FALSE;
    ULONG len;
    memset(prot, 0, sizeof(*prot));
    if (pNtQueryInformationProcess(proc, ProcessProtectionInformation,
                                   prot, sizeof(*prot), &len) != 0)
        return FALSE;
    /* Type must be 1 (PP) or 2 (PPL) with a valid signer */
    return (prot->Type == 1 || prot->Type == 2) && prot->Signer != 0;
}

static const char *protection_type_str(UCHAR type) {
    switch (type) {
    case 1: return "Protected (PP)";
    case 2: return "Protected Light (PPL)";
    default: return "Unknown";
    }
}

static const char *protection_signer_str(UCHAR signer) {
    switch (signer) {
    case 0: return "None";
    case 1: return "Authenticode";
    case 2: return "CodeGen";
    case 3: return "Antimalware";
    case 4: return "Lsa";
    case 5: return "Windows";
    case 6: return "WinTcb";
    case 7: return "WinSystem";
    default: return "Unknown";
    }
}

/* ── privilege escalation + process enumeration ────────────────────── */

static void enable_debug_priv(void) {
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok))
        return;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(tok);
}

static int match_filter(PROCESSENTRY32 *pe, const char *filter) {
    if (!filter) return 1;
    char *end;
    DWORD pid = strtoul(filter, &end, 10);
    if (*end == '\0') return pe->th32ProcessID == pid;
    /* Exact match first, then substring (case-insensitive) */
    if (_stricmp(pe->szExeFile, filter) == 0) return 1;
    char hay[MAX_PATH], needle[MAX_PATH];
    for (int i = 0; pe->szExeFile[i]; i++) hay[i] = tolower(pe->szExeFile[i]);
    hay[strlen(pe->szExeFile)] = '\0';
    for (int i = 0; filter[i]; i++) needle[i] = tolower(filter[i]);
    needle[strlen(filter)] = '\0';
    return strstr(hay, needle) != NULL;
}

/* Case-insensitive substring helper */
static BOOL istrstr(const char *hay, const char *needle) {
    char h[512], n[512];
    size_t hlen = strlen(hay), nlen = strlen(needle);
    if (hlen >= sizeof(h)) hlen = sizeof(h) - 1;
    if (nlen >= sizeof(n)) nlen = sizeof(n) - 1;
    for (size_t i = 0; i < hlen; i++) h[i] = tolower(hay[i]);
    h[hlen] = '\0';
    for (size_t i = 0; i < nlen; i++) n[i] = tolower(needle[i]);
    n[nlen] = '\0';
    return strstr(h, n) != NULL;
}

/* Match token user/SID against a lazy filter string */
static BOOL match_user_filter(HANDLE tok, const char *uf) {
    if (!uf) return TRUE;

    PSID sid = get_token_user_sid(tok);
    if (!sid) return FALSE;

    BOOL match = FALSE;

    /* Check against SID string */
    char *sid_str = NULL;
    if (ConvertSidToStringSidA(sid, &sid_str)) {
        if (istrstr(sid_str, uf)) match = TRUE;
        LocalFree(sid_str);
    }

    /* Check against resolved DOMAIN\user and bare username */
    if (!match) {
        char name[256] = {0}, domain[256] = {0}, full[512];
        DWORD nlen = sizeof(name), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use)) {
            _snprintf(full, sizeof(full), "%s\\%s", domain, name);
            if (istrstr(full, uf) || istrstr(name, uf))
                match = TRUE;
        }
    }

    free(sid);
    return match;
}

static void print_caller_context(void) {
    char *sid_str = NULL;
    if (g_caller.user_sid && ConvertSidToStringSidA(g_caller.user_sid, &sid_str)) {
        printf("Caller SID       : %s\n", sid_str);
        LocalFree(sid_str);
    }
    printf("Caller Integrity : %s (0x%04lx)\n",
           integrity_str(g_caller.integrity_rid), g_caller.integrity_rid);
    printf("SeImpersonatePriv: %s\n\n",
           g_caller.has_impersonate_priv ? "YES" : "NO");
}

int main(int argc, char *argv[]) {
    const char *filter = NULL;
    const char *user_filter = NULL;
    BOOL exclude_protected = FALSE;
    BOOL table_view = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-x") == 0)
            exclude_protected = TRUE;
        else if (strcmp(argv[i], "-t") == 0)
            table_view = TRUE;
        else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
            user_filter = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("enum_tokens - Enumerate process tokens and assess impersonation viability\n\n"
                   "Usage: enum_tokens.exe [options] [target]\n\n"
                   "Target:\n"
                   "  <PID>            Filter by process ID\n"
                   "  <name.exe>       Filter by process name (case-insensitive, substring)\n\n"
                   "Options:\n"
                   "  -t               Table view (compact one-line-per-process summary)\n"
                   "  -x               Exclude protected and inaccessible processes\n"
                   "  -u <user>        Filter by token user, SID, or substring\n"
                   "                   (e.g. SYSTEM, S-1-5-18, NETWORK)\n"
                   "  -h, --help       Show this help\n\n"
                   "Examples:\n"
                   "  enum_tokens.exe              Show all process tokens\n"
                   "  enum_tokens.exe -t -x        Table view, skip protected processes\n"
                   "  enum_tokens.exe svchost.exe  Show tokens for svchost instances\n"
                   "  enum_tokens.exe -u SYSTEM    Show all processes running as SYSTEM\n"
                   "  enum_tokens.exe -u S-1-5-18  Filter by SID\n"
                   "  enum_tokens.exe 928          Show token for PID 928\n");
            return 0;
        } else
            filter = argv[i];
    }

    enable_debug_priv();
    init_console_color();
    init_ntdll();
    init_caller_ctx();
    if (!table_view)
        print_caller_context();
    else
        printf("%-8s %-22s %-28s %-26s %-10s %s\n",
               "PID", "PROCESS", "USER", "SID", "INTEGRITY", "VERDICT");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return 1; }

    int found = 0;
    do {
        if (!match_filter(&pe, filter)) continue;
        found++;

        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
        if (!proc)
            proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);

        if (!proc) {
            if (!exclude_protected) {
                printf("=== PID %-6lu  %s ===\n", pe.th32ProcessID, pe.szExeFile);
                printf("  %s[ACCESS DENIED -- protected/minimal process]%s\n\n",
                       C_RED, C_RESET);
            }
            continue;
        }

        /* Check PPL status */
        PS_PROTECTION prot;
        BOOL is_ppl = is_process_protected(proc, &prot);

        HANDLE tok;
        if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
            if (!exclude_protected) {
                printf("=== PID %-6lu  %s ===\n", pe.th32ProcessID, pe.szExeFile);
                if (is_ppl)
                    printf("  %s[PROTECTED: %s / Signer: %s -- token inaccessible]%s\n\n",
                           C_YELLOW, protection_type_str(prot.Type),
                           protection_signer_str(prot.Signer), C_RESET);
                else
                    printf("  %s[OpenProcessToken DENIED -- error %lu]%s\n\n",
                           C_RED, GetLastError(), C_RESET);
            }
            CloseHandle(proc);
            continue;
        }

        if (exclude_protected && is_ppl) {
            CloseHandle(tok);
            CloseHandle(proc);
            continue;
        }

        if (!match_user_filter(tok, user_filter)) {
            CloseHandle(tok);
            CloseHandle(proc);
            continue;
        }

        if (table_view) {
            char user[64] = "?", sid_buf[80] = "?";
            PSID sid = get_token_user_sid(tok);
            if (sid) {
                char name[256] = {0}, domain[256] = {0};
                DWORD nlen = sizeof(name), dlen = sizeof(domain);
                SID_NAME_USE use;
                if (LookupAccountSidA(NULL, sid, name, &nlen, domain, &dlen, &use)) {
                    if (domain[0])
                        _snprintf(user, sizeof(user), "%s\\%s", domain, name);
                    else
                        _snprintf(user, sizeof(user), "%s", name);
                }
                char *ss = NULL;
                if (ConvertSidToStringSidA(sid, &ss)) {
                    _snprintf(sid_buf, sizeof(sid_buf), "%s", ss);
                    LocalFree(ss);
                }
                free(sid);
            }
            DWORD rid = get_integrity_rid(tok);
            imp_verdict v = evaluate_impersonation(tok);
            const char *vc, *vs;
            switch (v) {
            case IMP_USABLE:              vc = C_GREEN;  vs = "USABLE";   break;
            case IMP_IDENTIFICATION_ONLY: vc = C_YELLOW; vs = "IDENT";    break;
            case IMP_RESTRICTED:          vc = C_RED;    vs = "RESTRICT"; break;
            default:                      vc = C_RESET;  vs = "?";        break;
            }
            printf("%-8lu %-22s %-28s %-26s %-10s %s%s%s%s\n",
                   pe.th32ProcessID, pe.szExeFile, user, sid_buf,
                   integrity_str(rid), vc, vs,
                   is_ppl ? " [PPL]" : "", C_RESET);
        } else {
            printf("=== PID %-6lu  %s ===\n", pe.th32ProcessID, pe.szExeFile);
            if (is_ppl)
                printf("  %s[PROTECTED: %s / Signer: %s]%s\n",
                       C_YELLOW, protection_type_str(prot.Type),
                       protection_signer_str(prot.Signer), C_RESET);
            print_token_info(tok);
            print_impersonation_verdict(tok);
            printf("  Privileges:\n");
            print_privileges(tok);
            printf("\n");
        }
        CloseHandle(tok);
        CloseHandle(proc);
    } while (Process32Next(snap, &pe));

    if (filter && !found)
        fprintf(stderr, "No process found matching '%s'\n", filter);

    free(g_caller.user_sid);
    CloseHandle(snap);
    return (filter && !found) ? 1 : 0;
}
