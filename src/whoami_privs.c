#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>


static const char *logon_type_str(ULONG type) {
    switch (type) {
        case 2:  return "Interactive";
        case 3:  return "Network";
        case 4:  return "Batch";
        case 5:  return "Service";
        case 7:  return "Unlock";
        case 8:  return "NetworkCleartext";
        case 9:  return "NewCredentials";
        case 10: return "RemoteInteractive";
        case 11: return "CachedInteractive";
        default: return "Unknown";
    }
}

int main() {
    HANDLE hToken;
    DWORD dwSize = 0;
    char username[256];
    DWORD username_len = sizeof(username);
    TOKEN_PRIVILEGES *pPrivileges = NULL;
    DWORD i;
    char privName[256];
    DWORD privNameLen;

    // Get current username
    if (GetUserNameA(username, &username_len)) {
        printf("Current User: %s\n", username);
    }

    // Get integrity level and logon type from the same token handle
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token\n");
        return 1;
    }

    // Logon session type
    TOKEN_STATISTICS stats;
    DWORD statsLen = 0;
    if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &statsLen)) {
        PSECURITY_LOGON_SESSION_DATA pSession = NULL;
        if (LsaGetLogonSessionData(&stats.AuthenticationId, &pSession) == 0) {
            printf("Logon Type:      %lu (%s)\n", pSession->LogonType, logon_type_str(pSession->LogonType));
            printf("Logon Server:    %.*S\n", pSession->LogonServer.Length / 2, pSession->LogonServer.Buffer);
            printf("Auth Package:    %.*S\n", pSession->AuthenticationPackage.Length / 2, pSession->AuthenticationPackage.Buffer);
            LsaFreeReturnBuffer(pSession);
        }
    }

    // Integrity level
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    TOKEN_MANDATORY_LABEL *pTIL = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        DWORD integrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
        
        const char *level;
        if (integrityLevel < SECURITY_MANDATORY_LOW_RID)
            level = "Untrusted";
        else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
            level = "Low";
        else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID)
            level = "Medium";
        else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
            level = "High";
        else
            level = "System";
        
        printf("Integrity Level: %s\n\n", level);
    }
    free(pTIL);
    CloseHandle(hToken);

    // Open process token again for privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token\n");
        return 1;
    }

    // Get token privileges size
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    pPrivileges = (TOKEN_PRIVILEGES*)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenPrivileges, pPrivileges, dwSize, &dwSize)) {
        printf("Failed to get token information\n");
        CloseHandle(hToken);
        free(pPrivileges);
        return 1;
    }

    printf("Privileges:\n");
    printf("%-50s %s\n", "Privilege Name", "State");
    printf("========================================================================\n");

    for (i = 0; i < pPrivileges->PrivilegeCount; i++) {
        privNameLen = sizeof(privName);
        if (LookupPrivilegeNameA(NULL, &pPrivileges->Privileges[i].Luid, privName, &privNameLen)) {
            const char *state;
            DWORD attr = pPrivileges->Privileges[i].Attributes;
            
            if (attr & SE_PRIVILEGE_ENABLED)
                state = "Enabled";
            else if (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                state = "Enabled (Default)";
            else
                state = "Disabled";

            printf("%-50s %s\n", privName, state);
        }
    }

    free(pPrivileges);
    CloseHandle(hToken);
    return 0;
}
