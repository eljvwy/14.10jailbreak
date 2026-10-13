@echo off
REM Double-click entry point for PS5-JB-14.10 host
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python 3 is not installed or not on PATH.
  echo Install from https://www.python.org/downloads/ ^(check "Add to PATH"^).
  pause
  exit /b 1
)
python -m pip install -r requirements.txt --quiet --disable-pip-version-check
python src\main.py
if errorlevel 1 pause
