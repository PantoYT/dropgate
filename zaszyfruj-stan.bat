@echo off
rem Pakuje state\ do state.7z (AES-256, nazwy plikow tez zaszyfrowane) i kasuje
rem jawna wersje. Dla paczki na nosniku wymiennym: zgubiony pendrive przestaje
rem oznaczac oddanie klucza SSH, sekretu serwera i poswiadczen tunelu.
chcp 65001 >nul
cd /d "%~dp0"

set "SZ=%~dp0bin\7z.exe"
if not exist "%SZ%" set "SZ=7z"

if not exist "%~dp0state\secret.key" (
  echo.
  echo   Nie ma czego szyfrowac - brak state\secret.key.
  echo.
  pause
  exit /b 1
)

echo.
echo   Zaszyfruje state\ do state.7z.
echo   Haslo bedzie potrzebne przy KAZDYM uruchomieniu dropgate'a.
echo   ZAPAMIETAJ JE - bez niego stanu nie da sie odzyskac, a razem z nim
echo   przepadaja wszystkie dotychczasowe linki.
echo.

if exist "%~dp0state.7z" del /q "%~dp0state.7z"
"%SZ%" a -t7z -mhe=on -mx=9 -p "state.7z" "state\"
if errorlevel 1 (
  echo.
  echo   Szyfrowanie nie przeszlo. state\ zostaje nietkniety.
  pause
  exit /b 1
)

echo.
echo   Teraz sprawdzam archiwum - podaj to samo haslo jeszcze raz.
echo   Bez tego kasowanie jawnego stanu byloby ruletka.
echo.
"%SZ%" t -p "state.7z"
if errorlevel 1 (
  echo.
  echo   TEST NIE PRZESZEDL - NIE kasuje state\.
  echo   Sprawdz haslo i sprobuj jeszcze raz.
  pause
  exit /b 1
)

rmdir /s /q "%~dp0state"
echo.
echo   Gotowe. Jawny state\ skasowany, zostal state.7z.
echo   Przed kolejnym uruchomieniem: odszyfruj-stan.bat
echo.
pause
