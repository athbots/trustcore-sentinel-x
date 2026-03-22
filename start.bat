@echo off
TITLE TrustCore Sentinel X Launcher
echo ===================================================
echo     Shielding the Perimeter... Starting Sentinel
echo ===================================================

:: Run the compiled CLI wrapper to start the server asynchronously in a new terminal window
if exist "release\sentinel.exe" (
    echo Detected Native Sentinel Executable Binary
    start "TrustCore Sentinel X Server" cmd /k "release\sentinel.exe run"
) else (
    echo [WARNING] Compiled release binary not found. Falling back to native python execution.
    start "TrustCore Sentinel X Server" cmd /k "python cli.py run"
)

echo Waiting for AI FastAPI Boot Sequences to Initialize...
timeout /t 5 /nobreak >nul

:: Launch default system browser to the dashboard natively
echo Securely Opening the Security Operations Dashboard...
start http://127.0.0.1:8000/
exit
