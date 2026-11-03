@echo off
chcp 65001 >nul
cd /d "%~dp0"
start "" pythonw logcat_viewer.py
if errorlevel 1 (
    python logcat_viewer.py
)
