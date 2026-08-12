@echo off
rem dropgate - panel w przegladarce + tunel. Dwuklik i tyle.
chcp 65001 >nul
cd /d "%~dp0"

rem Straznik. ensure_base() w dropgate.py generuje NOWY secret.key, gdy go nie
rem zastanie - a wtedy wszystkie dotychczasowe linki przestaja dzialac po cichu.
rem Jesli stan jest zaszyfrowany, lepiej stanac tutaj niz stracic baze udostepnien.
if exist "%~dp0state.7z" if not exist "%~dp0state\secret.key" (
  echo.
  echo   STAN JEST ZASZYFROWANY.
  echo.
  echo   Odpal najpierw odszyfruj-stan.bat. Gdybym wystartowal teraz, dropgate
  echo   wygenerowalby nowy sekret i WSZYSTKIE dotychczasowe linki przestalyby
  echo   dzialac - bez ostrzezenia.
  echo.
  pause
  exit /b 1
)

set "PY=%~dp0python\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" dropgate.py go %*
echo.
echo (okno mozna zamknac - zamkniecie konczy serwowanie)
pause >nul
