/*
 * enum_logontype_bof.c
 *
 * BOF that queries the logon session type for the current process token.
 * Reports logon type, logon ID, user, logon server, and auth package.
 *
 * Arguments: none
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c -o enum_logontype_bof.x64.o enum_logontype_bof.c
 */

#include <windows.h>
#include <ntsecapi.h>
#include "beacon.h"

/* ── Win32 API declarations (DFR) ──────────────────────────────────── */

/* kernel32 */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);

/* advapi32 */
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* secur32 */
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA *);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);

/* ── Entry point ───────────────────────────────────────────────────── */

void go(char *args, int len)
{
    HANDLE hToken = NULL;
    TOKEN_STATISTICS stats;
    DWORD dwLen = 0;
    PSECURITY_LOGON_SESSION_DATA pSession = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu", KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &dwLen)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }
    KERNEL32$CloseHandle(hToken);

    NTSTATUS status = SECUR32$LsaGetLogonSessionData(&stats.AuthenticationId, &pSession);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaGetLogonSessionData failed: 0x%08lX", status);
        return;
    }

    const char *typeName;
    switch (pSession->LogonType) {
        case 2:  typeName = "Interactive";       break;
        case 3:  typeName = "Network";           break;
        case 4:  typeName = "Batch";             break;
        case 5:  typeName = "Service";           break;
        case 7:  typeName = "Unlock";            break;
        case 8:  typeName = "NetworkCleartext";  break;
        case 9:  typeName = "NewCredentials";    break;
        case 10: typeName = "RemoteInteractive"; break;
        case 11: typeName = "CachedInteractive"; break;
        default: typeName = "Unknown";           break;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "Logon Type     : %lu (%s)\n"
        "Logon ID       : %08lX:%08lX\n"
        "User           : %.*S\\%.*S\n"
        "Logon Server   : %.*S\n"
        "Auth Package   : %.*S",
        pSession->LogonType, typeName,
        stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart,
        pSession->LogonDomain.Length / 2, pSession->LogonDomain.Buffer,
        pSession->UserName.Length / 2, pSession->UserName.Buffer,
        pSession->LogonServer.Length / 2, pSession->LogonServer.Buffer,
        pSession->AuthenticationPackage.Length / 2, pSession->AuthenticationPackage.Buffer);

    SECUR32$LsaFreeReturnBuffer(pSession);
}
