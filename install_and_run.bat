@echo off
cd /d "%~dp0"
echo WakeDeck setup
echo.
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
  echo [ERROR] Python 3 not found.
  echo Install Python 3.11+ from https://www.python.org/downloads/
  echo and check "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)
python -c "import paramiko" 2>nul
if %ERRORLEVEL% neq 0 (
  echo Installing paramiko...
  python -m pip install -r requirements.txt
)
echo Starting WakeDeck...
start "" pythonw wake_deck.py
exit /b 0
