@echo off
setlocal

set SRC=Z:\public share\phantomrpc-poc-main\phantomrpc-poc-main\POCs\GreenPlasma
set DST=C:\Users\unpriv\Music

if not "%~1"=="go" (
    if not exist "%SRC%\easyplasma.cs" (
        echo [-] Source not found: %SRC%
        exit /b 1
    )
    robocopy "%SRC%" "%DST%" easyplasma.cs build.bat go.bat /IS /Z /COPY:DAT /W:1 /R:1 /NFL /NDL /NJH /NJS
    copy /Y "%SRC%\go.bat" "%TEMP%\go_runner.bat" >nul
    call "%TEMP%\go_runner.bat" go
    exit /b
)

cd /d "%DST%"
call build.bat > "%TEMP%\build_out.tmp" 2>&1
set BUILD_ERR=%errorlevel%
type "%TEMP%\build_out.tmp"
del "%TEMP%\build_out.tmp" >nul 2>&1
if %BUILD_ERR% neq 0 (echo [-] Build failed & exit /b 1)

echo.
echo [*] Launching easyplasma.exe...
easyplasma.exe
