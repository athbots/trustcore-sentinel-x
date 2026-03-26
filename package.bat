@echo off
echo ==============================================
echo    TRUSTCORE SENTINEL™ - ENTERPRISE BUILD
echo ==============================================
echo.

echo [1/3] Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate

echo [2/3] Installing Prod Dependencies (This may take a while for PyTorch/Transformers)...
pip install -r requirements.txt
pip install pyinstaller

echo [3/3] Building Standalone Executable...
:: We package the FastAPI engine into a single executable
pyinstaller --name "TrustCore_Sentinel" --onefile --hidden-import="trust_engine" --hidden-import="uvicorn.logging" trust_engine\api\main.py

echo.
echo Build Complete! Executable located in \dist\TrustCore_Sentinel.exe
echo To run: dist\TrustCore_Sentinel.exe
pause
