@echo off
setlocal
set "SK_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "SK_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%SK_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch.ps1" -Action Install
exit /b %errorlevel%
