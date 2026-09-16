@echo off
echo ============================================
echo   Biometric Sync
echo ============================================
echo.
echo Starting automatic setup and launch...
echo.

:: Try python first, then python3
where python >nul 2>&1
if %ERRORLEVEL% == 0 (
    python "%~dp0run.py"
) else (
    where python3 >nul 2>&1
    if %ERRORLEVEL% == 0 (
        python3 "%~dp0run.py"
    ) else (
        echo [ERROR] Python is not installed or not in PATH.
        echo         Download Python from https://www.python.org/downloads/
        echo         Make sure to check "Add Python to PATH" during installation.
        echo.
        pause
        exit /b 1
    )
)

pause
