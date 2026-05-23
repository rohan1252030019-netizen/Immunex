@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM IMMUNEX Layer 5 — Windows Startup Script
REM ─────────────────────────────────────────────────────────────────────────────

setlocal enabledelayedexpansion

cd /d "%~dp0\.."

echo =============================================================
echo    IMMUNEX Autonomous SOC -- Layer 5 Startup
echo =============================================================
echo.

REM ── Check Python ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version') do set PY_VER=%%v
echo [OK] Python %PY_VER%

REM ── Create data directories ───────────────────────────────────────────────────
if not exist "data\logs"            mkdir "data\logs"
if not exist "data\models"          mkdir "data\models"
if not exist "data\baseline_vectors" mkdir "data\baseline_vectors"
if not exist "data\memory"          mkdir "data\memory"
if not exist "data\drift"           mkdir "data\drift"
if not exist "data\retrain_archive" mkdir "data\retrain_archive"
if not exist "data\mutations"       mkdir "data\mutations"
if not exist "data\reports"         mkdir "data\reports"
echo [OK] Data directories ready

REM ── Check/install dependencies ────────────────────────────────────────────────
set DEPS_OK=1
python -c "import fastapi" >nul 2>&1
if errorlevel 1 set DEPS_OK=0
python -c "import jwt" >nul 2>&1
if errorlevel 1 set DEPS_OK=0
python -c "import reportlab" >nul 2>&1
if errorlevel 1 set DEPS_OK=0

if "%DEPS_OK%"=="0" (
    echo [INFO] Installing CPU-only PyTorch...
    pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet
    echo [INFO] Installing remaining dependencies...
    pip install -r requirements.txt --quiet
    echo [OK] Dependencies installed
) else (
    echo [OK] Dependencies already installed
)

REM ── Parse mode argument ───────────────────────────────────────────────────────
set MODE=pipeline
if "%1"=="--api"      set MODE=pipeline+api
if "%1"=="--api-only" set MODE=api-only
echo [OK] Mode: %MODE%
echo.

REM ── Launch ────────────────────────────────────────────────────────────────────
if "%MODE%"=="pipeline+api" (
    echo [START] IMMUNEX pipeline + REST API on :8080
    python main.py --api
) else if "%MODE%"=="api-only" (
    echo [START] IMMUNEX REST API only on :8080
    python main.py --api-only
) else (
    echo [START] IMMUNEX pipeline (dashboard mode)
    python main.py
)

if errorlevel 1 (
    echo.
    echo ERROR: IMMUNEX exited with an error. Check data\logs\immunex.log
    pause
)
endlocal
