@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
    echo Python not found. Please install Python with Tkinter.
    pause
    exit /b 1
)
where node >nul 2>nul
if errorlevel 1 (
    echo Node.js not found. The preview still uses the existing safety core.
    pause
    exit /b 1
)
start "" pythonw "%~dp0run.py"
