@echo off
setlocal

rem Network Topology Mapper launcher.
rem Keep this file ASCII-only. cmd.exe can misread UTF-8 comments before
rem the code page is changed, which prevents double-click launch.

cd /d "%~dp0"
if errorlevel 1 (
    echo Failed to open the application folder.
    pause
    exit /b 1
)

chcp 65001 >nul 2>&1

set "NTM_ROOT=%~dp0"
set "NTM_START=%~dp0Start.ps1"

if not exist "%NTM_START%" (
    echo Start.ps1 was not found.
    echo Folder: %NTM_ROOT%
    pause
    exit /b 1
)

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

where.exe pwsh.exe >nul 2>&1
if not errorlevel 1 (
    pwsh.exe -NoLogo -NoProfile -Command "exit 0" >nul 2>&1
    if not errorlevel 1 set "PS_EXE=pwsh.exe"
)

"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%NTM_START%"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Network Topology Mapper failed to start. Exit code: %EXIT_CODE%
    echo Try Run.vbs, or run this command from PowerShell:
    echo powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%NTM_START%"
    echo.
    pause
)

exit /b %EXIT_CODE%
