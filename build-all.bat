Логин@echo off
setlocal
cd /d "%~dp0"
set VERSION=%~1
set RELEASE=%~2

if "%RELEASE%"=="" (
    for /f "tokens=1,2 delims=|" %%A in ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\next-build.ps1" -Version "%VERSION%"') do (
        set VERSION=%%A
        set RELEASE=%%B
    )
)

echo [0/2] Cleaning previous build artifacts...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '.\dist') { Remove-Item -LiteralPath '.\dist' -Recurse -Force }"
if errorlevel 1 exit /b 1

echo [1/2] Building qWDTT binaries...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\build-qwdtt.ps1" -Version "%VERSION%" -Release "%RELEASE%"
if errorlevel 1 exit /b 1

echo [2/2] Packaging qWDTT IPK files...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\package-qwdtt.ps1" -Version "%VERSION%" -Release "%RELEASE%"
if errorlevel 1 exit /b 1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\next-build.ps1" -Version "%VERSION%" -Release "%RELEASE%" -Commit
if errorlevel 1 exit /b 1

echo.
echo qWDTT build completed.
dir /b dist\qwdtt-linux-* dist\ipk\qwdtt_*.ipk
endlocal
