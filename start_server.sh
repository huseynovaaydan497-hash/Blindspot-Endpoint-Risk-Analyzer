#!/bin/sh
# Blindspot server: first run creates .venv and installs requirements, then starts the dashboard.
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo "Creating .venv and installing requirements, one time only..."
  python3 -m venv .venv && .venv/bin/python -m pip install -q -r requirements.txt || exit 1
fi
echo "Dashboard: http://localhost:8000  (Ctrl+C to stop)"
exec .venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
