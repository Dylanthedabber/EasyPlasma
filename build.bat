@echo off
where csc.exe >nul 2>&1
if errorlevel 1 (set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe) else (set CSC=csc.exe)

echo [*] Compiling easyplasma.cs...
%CSC% /nologo /platform:x64 /optimize /out:easyplasma.exe easyplasma.cs
if errorlevel 1 (echo [-] easyplasma build failed & exit /b 1)
echo [+] Build successful: easyplasma.exe

echo.
echo Usage:
echo   easyplasma.exe           - escalate (instant if already installed)
echo   easyplasma.exe install   - install to user PATH
echo   easyplasma.exe update    - update from GitHub
echo   easyplasma.exe --unpriv  - cleanup and uninstall
