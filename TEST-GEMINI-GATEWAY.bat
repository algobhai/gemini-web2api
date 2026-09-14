@echo off
setlocal
title Gemini Web2API Test
cd /d "%~dp0"

echo ============================================================
echo   Gemini Web2API - Flash + Pro Test
echo ============================================================
echo.

curl.exe -s --max-time 2 "http://127.0.0.1:8081/" >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Gateway is not running.
  echo Double-click START-GEMINI-GATEWAY.bat first.
  pause
  exit /b 1
)

echo [1/4] Testing Flash...
curl.exe -sS --max-time 240 -X POST "http://127.0.0.1:8081/v1/chat/completions" -H "Content-Type: application/json" --data-binary "{\"model\":\"gemini-3.7-flash\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply exactly: flash-ok\"}]}"
echo.
echo.

echo [2/4] Flash routing diagnostics...
curl.exe -sS --max-time 10 "http://127.0.0.1:8081/v1/_diagnostics/routing"
echo.
echo.

echo [3/4] Testing Pro...
curl.exe -sS --max-time 300 -X POST "http://127.0.0.1:8081/v1/chat/completions" -H "Content-Type: application/json" --data-binary "{\"model\":\"gemini-3.1-pro\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply exactly: pro-ok\"}]}"
echo.
echo.

echo [4/4] Pro routing diagnostics...
curl.exe -sS --max-time 10 "http://127.0.0.1:8081/v1/_diagnostics/routing"
echo.
echo.

echo ============================================================
echo Look for: "status": "ok"
echo Flash may be reported by Google as a newer Flash label.
echo Pro should report a Pro label and status ok.
echo ============================================================
pause
