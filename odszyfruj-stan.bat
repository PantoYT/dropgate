@echo off
rem Rozpakowuje state.7z z powrotem do state\. Odpalac przed dropgate.bat.
chcp 65001 >nul
cd /d "%~dp0"

set "SZ=%~dp0bin\7z.exe"
if not exist "%SZ%" set "SZ=7z"

if not exist "%~dp0state.7z" (
  echo.
  echo   Brak state.7z - nie ma czego odszyfrowac.
  echo.
  pause
  exit /b 1
)

if exist "%~dp0state\secret.key" (
  echo.
  echo   state\ juz istnieje - nic nie robie, zeby nie nadpisac swiezszego stanu.
  echo.
  pause
  exit /b 0
)

"%SZ%" x -p "state.7z" -o"%~dp0"
if errorlevel 1 (
  echo.
  echo   Zle haslo albo uszkodzone archiwum. state\ nie powstal.
  pause
  exit /b 1
)

echo.
echo   Odszyfrowane. Mozesz odpalic dropgate.bat
echo.
echo   Po skonczonej pracy: zaszyfruj-stan.bat - inaczej jawne sekrety
echo   zostaja na nosniku.
echo.
pause
