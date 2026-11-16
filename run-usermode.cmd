@echo off
setlocal
set "debugger=%LOCALAPPDATA%\hyper-reV\bin\usermode.exe"
if not exist "%debugger%" (
    echo Published debugger is missing. Build and publish it first:
    echo powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build-usermode.ps1" -Publish
    exit /b 1
)
"%debugger%" %*
exit /b %errorlevel%
