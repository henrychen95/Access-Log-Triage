@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"
set "APP_URL=http://127.0.0.1:8000"

if not exist "%PYTHON%" (
    echo Access Log Triage virtual environment was not found.
    echo.
    echo Run these commands first:
    echo   py -3.12 -m venv .venv
    echo   .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
    echo.
    pause
    exit /b 1
)

echo Starting Access Log Triage at %APP_URL%
echo Press Ctrl+C to stop the server.
start "" /b powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Milliseconds 900; Start-Process '%APP_URL%'"
"%PYTHON%" -m access_log_triage

endlocal
