@echo off
setlocal
title Gemini Web2API Windows Setup
cd /d "%~dp0"
set "GATEWAY_ROOT=%~dp0"

echo ============================================================
echo   Gemini Web2API - Windows Setup
echo ============================================================
echo.

where py >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python launcher ^(py.exe^) was not found.
  echo Install Python and run this setup again.
  pause
  exit /b 1
)

if not exist "config.json" (
  copy /Y "config.hardened.example.json" "config.json" >nul
  echo [OK] Created config.json.
) else (
  echo [OK] Existing config.json kept unchanged.
)

echo [SETUP] Checking Python dependency...
py -c "import httpx" >nul 2>nul
if errorlevel 1 (
  py -m pip install httpx
  if errorlevel 1 (
    echo [ERROR] Could not install httpx.
    pause
    exit /b 1
  )
)
echo [OK] Python dependency ready.

if exist "gemini-auth.json" (
  echo [OK] gemini-auth.json found.
) else (
  echo [WARNING] gemini-auth.json is not in this folder yet.
  echo Export it from Gemini Cookie Sync before expecting authenticated Pro routing.
)

echo [SETUP] Creating Desktop shortcut...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$root=$env:GATEWAY_ROOT; $desktop=[Environment]::GetFolderPath('Desktop'); $ws=New-Object -ComObject WScript.Shell; $s=$ws.CreateShortcut((Join-Path $desktop 'Gemini Gateway.lnk')); $s.TargetPath=(Join-Path $root 'START-GEMINI-GATEWAY.bat'); $s.WorkingDirectory=$root; $s.IconLocation=($env:SystemRoot + '\System32\shell32.dll,13'); $s.Description='Start local Gemini Web2API gateway'; $s.Save()"
if errorlevel 1 (
  echo [WARNING] Could not create the Desktop shortcut automatically.
  echo You can still double-click START-GEMINI-GATEWAY.bat in this folder.
) else (
  echo [OK] Desktop shortcut created: Gemini Gateway
)

echo.
echo Setup complete.
echo Double-click "Gemini Gateway" on your Desktop to start the server.
echo Use TEST-GEMINI-GATEWAY.bat any time to verify Flash and Pro routing.
echo.
pause
