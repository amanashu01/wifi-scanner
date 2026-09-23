@echo off
REM NetGuard launcher for Windows.
REM Run from an Administrator prompt for live firewall mode.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Creating virtual environment in .venv ...
  python -m venv .venv || goto :error
  .venv\Scripts\python -m pip install --quiet --upgrade pip
  .venv\Scripts\python -m pip install --quiet -r requirements.txt || goto :error
)
.venv\Scripts\python app.py %*
goto :eof
:error
echo Setup failed. Make sure Python 3.9+ is installed and on PATH.
exit /b 1
