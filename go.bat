@echo off
setlocal

set SRC=Z:\public share\phantomrpc-poc-main\phantomrpc-poc-main\POCs\GreenPlasma
set DST=C:\Users\unpriv\Music
set OUT=Z:\public share\EasyPlasma

:: If not restarted yet, sync then re-launch from TEMP (CMD locks the running bat)
if not "%~1"=="go" (
    taskkill /F /IM GreenPlasma.exe /T >nul 2>&1
    taskkill /F /IM ctf_alpc.exe    /T >nul 2>&1
    timeout /T 2 /NOBREAK >nul

    if not exist "%SRC%\easyplasma.cs" (
        echo [-] Source not found: %SRC%
        exit /b 1
    )

    :: Sync source files (robocopy skips locked go.bat, still updates build.bat)
    robocopy "%SRC%" "%DST%" easyplasma.cs build.bat go.bat /IS /Z /COPY:DAT /W:1 /R:1 /NFL /NDL /NJH /NJS

    :: Copy latest go.bat to TEMP and restart from there (avoids CMD file lock)
    copy /Y "%SRC%\go.bat" "%TEMP%\go_runner.bat" >nul
    call "%TEMP%\go_runner.bat" go
    exit /b
)

:: Build (capture errorlevel before pipe swallows it)
cd /d "%DST%"
call build.bat > "%TEMP%\build_out.tmp" 2>&1
set BUILD_ERR=%errorlevel%
type "%TEMP%\build_out.tmp" | findstr /V "C4005" | findstr /V "previously declared"
del "%TEMP%\build_out.tmp" >nul 2>&1
if %BUILD_ERR% neq 0 (
    echo [-] Build failed
    exit /b 1
)

:: Copy built outputs back to both shared folders
echo.
echo [*] Copying outputs back...
if not exist "%OUT%" mkdir "%OUT%"
for %%f in (easyplasma.exe) do (
    if exist "%DST%\%%f" (
        copy /Y "%DST%\%%f" "%SRC%\%%f" >nul 2>&1 || echo [!] SRC copy skipped for %%f
        copy /Y "%DST%\%%f" "%OUT%\%%f" >nul 2>&1
        echo [+] %%f
    )
)

:: Launch easyplasma
echo.
echo [*] Launching easyplasma.exe...
easyplasma.exe
