@echo off
rem dropgate - panel w przegladarce + tunel. Dwuklik i tyle.
chcp 65001 >nul
cd /d "%~dp0"
set "PY=%~dp0python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" dropgate.py go %*
echo.
echo (okno mozna zamknac - zamkniecie konczy serwowanie)
pause >nul
