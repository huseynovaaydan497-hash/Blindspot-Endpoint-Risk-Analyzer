@echo off
rem Blindspot server: first run creates .venv and installs requirements, then starts the dashboard.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
if not exist .venv\Scripts\python.exe (
  echo Creating .venv and installing requirements, one time only...
  %PY% -m venv .venv || goto :fail
  .venv\Scripts\python.exe -m pip install -q -r requirements.txt || goto :fail
)
echo.
echo Dashboard: http://localhost:8000
echo Teammates: open "Add a computer" in the dashboard to download the agent.
echo Stop the server with Ctrl+C.
echo.
start "" http://localhost:8000
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
goto :eof
:fail
echo Setup failed. Is Python 3.10+ installed (python.org, tick "Add to PATH")?
pause
