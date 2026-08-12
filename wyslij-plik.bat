@echo off
rem Przeciagnij plik(i) na ten plik - dropgate wystawi link i wrzuci go do schowka.
chcp 65001 >nul
cd /d "%~dp0"
set "PY=%~dp0python\python.exe"
if not exist "%PY%" set "PY=python"
if "%~1"=="" (
  echo.
  echo   Przeciagnij plik na ikone tego pliku ^(wyslij-plik.bat^).
  echo   Albo odpal dropgate.bat, zeby dostac panel w przegladarce.
  echo.
  pause
  exit /b
)
"%PY%" dropgate.py share %*
echo.
echo (okno mozna zamknac - zamkniecie konczy serwowanie)
pause >nul
