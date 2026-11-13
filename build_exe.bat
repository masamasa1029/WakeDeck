@echo off
cd /d "%~dp0"
echo Building WakeDeck.exe (single file, no console window)
python -m pip install -r requirements.txt pyinstaller
if %ERRORLEVEL% neq 0 exit /b 1
python -m PyInstaller --noconfirm --onefile --noconsole --name WakeDeck --icon "assets\wakedeck.ico" --add-data "assets\wakedeck.ico;assets" --add-data "assets\wakedeck.png;assets" wake_deck.py
if %ERRORLEVEL% neq 0 exit /b 1
copy /y "dist\WakeDeck.exe" "WakeDeck.exe" >nul
echo.
echo Done: WakeDeck.exe
echo config.json will be stored next to the exe.
pause
