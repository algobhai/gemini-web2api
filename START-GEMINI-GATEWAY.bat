@echo off
setlocal
title Gemini Web2API Gateway
cd /d "%~dp0"

echo ============================================================
echo   Gemini Web2API - Local Gateway
echo ============================================================
echo.

where py >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python launcher ^(py.exe^) was not found.
  echo Install Python, then run this file again.
  pause
  exit /b 1
)

if not exist "config.json" (
  if not exist "config.hardened.example.json" (
    echo [ERROR] config.hardened.example.json is missing.
    pause
    exit /b 1
  )
  copy /Y "config.hardened.example.json" "config.json" >nul
  echo [OK] Created config.json from the hardened example.
)

py -c "import httpx" >nul 2>nul
if errorlevel 1 (
  echo [SETUP] Installing httpx...
  py -m pip install httpx
  if errorlevel 1 (
    echo [ERROR] Could not install httpx.
    pause
    exit /b 1
  )
)

if not exist "gemini-auth.json" (
  echo [WARNING] gemini-auth.json is missing.
  echo The gateway can still start, but authenticated Flash/Pro routing may downgrade.
  echo Export a fresh file with the Gemini Cookie Sync extension and place it here.
  echo.
)

curl.exe -s --max-time 1 "http://127.0.0.1:8081/v1/_diagnostics/routing" >nul 2>nul
if not errorlevel 1 (
  echo [OK] Gemini Gateway is already running at:
  echo      http://127.0.0.1:8081/v1
  echo.
  echo You can close this window.
  pause
  exit /b 0
)

echo [STARTING] Local-only gateway...
echo Base URL: http://127.0.0.1:8081/v1
echo.
echo Keep this window open while using Gemini through another app.
echo Press Ctrl+C when you want to stop the gateway.
echo ============================================================
echo.

py hardened_gateway.py --config config.json

echo.
echo Gateway stopped.
pause
