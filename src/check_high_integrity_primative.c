#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hToken;
    DWORD dwSize = 0;
    TOKEN_MANDATORY_LABEL *pTIL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("FAILURE: Could not open process token\n");
        return 1;
    }

    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    pTIL = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        printf("FAILURE: Could not get integrity level\n");
        free(pTIL);
        CloseHandle(hToken);
        return 1;
    }

    DWORD integrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
    
    free(pTIL);
    CloseHandle(hToken);

    if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        printf("SUCCESS: Running with High Integrity\n");
        return 0;
    } else {
        printf("FAILURE: Not running with High Integrity\n");
        return 1;
    }
}
