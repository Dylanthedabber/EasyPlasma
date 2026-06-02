# EasyPlasma

Local privilege escalation from standard user to **NT AUTHORITY\SYSTEM** on Windows 10/11.

Based on CVE-2020-17103 (Cloud Files TOCTOU) — no admin required, no UAC prompt.

---

## How it works

Windows has a driver called `cldflt.sys` (Cloud Files) that handles OneDrive sync.
When you call a specific API on it, the driver checks who you are before writing to the registry — but there is a race window between the check and the write.
By rapidly swapping your thread identity to anonymous at exactly the right moment, the driver falls back to writing to the `.DEFAULT` (system) registry hive instead of your user hive.

This gives write access to system registry keys that normally require admin. That access is used to redirect where Windows Error Reporting looks for `wermgr.exe` — pointing it at a payload. WER runs as SYSTEM, finds the payload, executes it as SYSTEM.

---

## Requirements

- Windows 10 or 11 (any standard user account)
- No admin, no UAC, no special privileges needed
- .NET Framework 4.x (built into Windows)
- Cloud Files filter driver (`cldflt.sys`) — present by default on all modern Windows installs

---

## Quick start — portable (no install)

Download `priv.bat`, `priv.exe`, and `syshost.exe` into the same folder. Double-click `priv.bat` or run in cmd:

```cmd
priv.bat
```

That's it. It will escalate and drop you into a SYSTEM cmd in the same window. All registry artifacts are cleaned up automatically when done.

---

## Quick start — installed (type `priv` anywhere)

**Step 1 — Download** `priv.exe` and `syshost.exe` into the same folder.

**Step 2 — Install** (adds `priv` to your user PATH and sets a persistent alias):

```cmd
priv.exe install
```

**Step 3 — Open a new cmd window and type:**

```cmd
priv
```

You will be dropped into a SYSTEM shell in the same terminal window.

---

## Inside the SYSTEM shell

Once escalated the prompt changes to `SYSTEM C:\...>`. The following commands are available:

| Command | What it does |
|---------|-------------|
| `power` | Switch to PowerShell as SYSTEM in the same window |
| `power new` | Open a new SYSTEM PowerShell window |
| `cmdnew` | Open a new SYSTEM cmd window |
| `psnew` | Open a new SYSTEM PowerShell window |
| `unpriv` | Clean up all artifacts and exit back to normal user |

Any other command runs normally as SYSTEM — `whoami`, `net user`, `reg`, etc.

To exit without running `unpriv`, just type `exit`. Run `priv.exe --unpriv` afterward to clean up.

---

## Uninstall / cleanup

```cmd
priv.exe --unpriv
```

or inside the SYSTEM shell:

```cmd
unpriv
```

This removes:
- All registry changes made by the exploit (CloudFiles key, Volatile Environment changes)
- The PATH entry
- The persistent doskey alias
- The Run key backdoor (if installed)
- All temp files

---

## Build from source

Requires Visual Studio Developer Command Prompt (cl.exe + csc.exe on PATH).

```cmd
build.bat
```

Outputs: `priv.exe`, `syshost.exe`, `priv.bat`

### Manual build

```cmd
:: SYSTEM shell host (C)
cl.exe syshost.c /Fe:syshost.exe /nologo /O2 /MT /link kernel32.lib

:: Main tool (C#)
csc.exe /platform:x64 /optimize /out:priv.exe priv.cs
```

---

## Files

| File | Description |
|------|-------------|
| `priv.exe` | Main tool — escalation + interactive SYSTEM shell |
| `syshost.exe` | SYSTEM shell host — runs as SYSTEM, attaches to your terminal |
| `priv.bat` | Portable wrapper — no install needed, auto-cleans on exit |
| `build.bat` | Builds everything from source |
| `miniplasma.cs` | Standalone CVE-2020-17103 proof-of-concept |
| `syshost.c` | Source for syshost.exe |
| `priv.cs` | Source for priv.exe |
| `GreenPlasma.cpp` | CTF section symlink exploit (related research) |

---

## Technical details

### Exploit chain

```
1. CfAbortOperation TOCTOU
   Race thread token between normal and anonymous while
   calling CfAbortOperation(Block) in a tight loop.
   cldflt.sys falls back to .DEFAULT hive.
   Result: .DEFAULT\Software\Policies\Microsoft\CloudFiles
           created with world-writable DACL.

2. Registry symlink (via PowerShell to avoid Defender)
   Delete .DEFAULT\Volatile Environment so it gets
   created fresh with permissive DACL.
   Create symlink: CloudFiles\BlockedApps
               --> .DEFAULT\Volatile Environment
   TOCTOU again — driver writes through symlink.
   Result: Volatile Environment world-writable.

3. windir hijack
   Write windir = C:\ProgramData\mp_<id> to Volatile Environment.
   Drop syshost.exe as C:\ProgramData\mp_<id>\System32\wermgr.exe.
   Trigger WER QueueReporting scheduled task.
   WER runs as SYSTEM, resolves wermgr.exe via %windir%,
   finds our syshost.exe, executes it as SYSTEM.

4. Console takeover
   syshost.exe (SYSTEM) attaches to priv.exe console,
   spawns cmd.exe as SYSTEM with inherited console handles.
   priv.exe waits for SYSTEM shell to exit then cleans up.

5. Cleanup
   CloudFiles key, Volatile Environment, and run dir
   deleted as soon as WER fires (~1.5s after trigger).
```

### Defender evasion

- Registry symlink creation delegated to `powershell.exe` (Microsoft-signed) to avoid `Behavior:Win32/SymlinkPlasma` detection
- All registry path strings built at runtime — no static `.DEFAULT\Volatile Environment` string in binary
- MiniPlasma artifacts cleaned before SYSTEM shell opens

---

## Disclaimer

For authorized security testing and educational use only.
