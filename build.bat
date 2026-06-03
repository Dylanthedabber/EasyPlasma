@echo off
where csc.exe >nul 2>&1
if errorlevel 1 (set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe) else (set CSC=csc.exe)

echo [*] Compiling stub.c (native WER callback)...
cl.exe stub.c /Fe:stub.exe /nologo /O2 /MT /D_CRT_SECURE_NO_WARNINGS /link kernel32.lib
if errorlevel 1 (echo [-] stub build failed & exit /b 1)
echo [+] Build successful: stub.exe

echo [*] Compiling easyplasma.cs (embeds stub.exe)...
%CSC% /nologo /platform:x64 /optimize /out:easyplasma.exe easyplasma.cs /res:stub.exe,stub.exe
if errorlevel 1 (echo [-] easyplasma build failed & exit /b 1)
echo [+] Build successful: easyplasma.exe

echo.
echo Usage:
echo   easyplasma.exe           - escalate (instant if already installed)
echo   easyplasma.exe install   - install to user PATH
echo   easyplasma.exe update    - update from GitHub
echo   easyplasma.exe --unpriv  - cleanup and uninstall
