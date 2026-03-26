@echo off
setlocal

echo ==========================================================
echo   TRUSTCORE SENTINEL X - PRODUCTION BOOTSTRAP
echo ==========================================================
echo.

cd /d %~dp0

echo [1/4] Verifying Python...
python --version
if %ERRORLEVEL% neq 0 (
    echo Python not found. Install Python and retry.
    pause
    exit /b
)

echo.
echo [2/4] Installing dependencies...

if not exist requirements.txt (
    echo requirements.txt NOT FOUND in root directory.
    pause
    exit /b
)

python -m pip install -r requirements.txt

if %ERRORLEVEL% neq 0 (
    echo Failed to install dependencies.
    pause
    exit /b
)

echo.
echo [3/4] Setting environment...

set PYTHONPATH=%CD%\backend

echo.
echo [4/4] Launching server...

echo Trying port 5050...
uvicorn backend.main:app --host 127.0.0.1 --port 5050

if %ERRORLEVEL% neq 0 (
    echo Port 5050 failed. Trying 5051...
    uvicorn backend.main:app --host 127.0.0.1 --port 5051
)

if %ERRORLEVEL% neq 0 (
    echo Port 5051 failed. Trying 5052...
    uvicorn backend.main:app --host 127.0.0.1 --port 5052
)

echo.
echo If server started successfully, open browser:
echo http://127.0.0.1:5050 OR 5051 OR 5052
echo.

pause
endlocal