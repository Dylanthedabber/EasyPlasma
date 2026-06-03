@echo off
setlocal

set SRC=Z:\public share\phantomrpc-poc-main\phantomrpc-poc-main\POCs\GreenPlasma
set BUILD=C:\Users\unpriv\Music

if "%~1"=="run" goto run

:: Step 1: resync go.bat from share, then re-run fresh copy
copy /Y "%SRC%\go.bat" "%TEMP%\go.bat" >nul
call "%TEMP%\go.bat" run
exit /b

:run
:: Step 2: sync source, build, run
robocopy "%SRC%" "%BUILD%" easyplasma.cs stub.c stub_dll.c build.bat /IS /Z /COPY:DAT /W:1 /R:1 /NFL /NDL /NJH /NJS
cd /d "%BUILD%"
call build.bat
if errorlevel 1 exit /b 1
echo.
easyplasma.exe
