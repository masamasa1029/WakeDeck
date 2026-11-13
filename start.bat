@echo off
cd /d "%~dp0"
if exist "WakeDeck.exe" (
  start "" "WakeDeck.exe"
  exit /b 0
)
where pythonw >nul 2>nul
if %ERRORLEVEL%==0 (
  start "" pythonw wake_deck.py
) else (
  echo Python not found. Run install_and_run.bat first.
  pause
)
