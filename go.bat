@echo off
setlocal

set SRC=Z:\public share\phantomrpc-poc-main\phantomrpc-poc-main\POCs\GreenPlasma
set BUILD=C:\Users\unpriv\Music

:: Sync latest source to build dir
robocopy "%SRC%" "%BUILD%" easyplasma.cs stub.c build.bat /IS /Z /COPY:DAT /W:1 /R:1 /NFL /NDL /NJH /NJS

:: Build
cd /d "%BUILD%"
call build.bat
if errorlevel 1 exit /b 1

:: Run
echo.
easyplasma.exe
