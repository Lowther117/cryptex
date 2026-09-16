@echo off
setlocal EnableExtensions
REM Run Cryptex from source on Windows, setting up a virtual environment the
REM first time. Use build-exe.bat if you want a standalone .exe instead.
cd /d "%~dp0"
set "VENV=%~dp0.venv"
if not exist "%VENV%\Scripts\python.exe" (
  echo First run - setting Python up. This happens once.
  for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_python.ps1"`) do set "PY=%%P"
  if not defined PY ( echo Could not find or install Python. & pause & exit /b 1 )
  "%PY%" -m venv "%VENV%" || ( echo Could not create the environment. & pause & exit /b 1 )
  "%VENV%\Scripts\python.exe" -m pip install --upgrade pip >nul
  "%VENV%\Scripts\python.exe" -m pip install --only-binary :all: -r "%~dp0requirements.txt" || ( pause & exit /b 1 )
)
start "" "%VENV%\Scripts\pythonw.exe" "%~dp0cryptex.py"
exit /b 0
