#!/usr/bin/env bash
# NetGuard launcher for macOS / Linux.
#   ./run.sh              simulation mode (firewall commands shown, not run)
#   sudo ./run.sh         live mode (firewall rules are applied)
#   ./run.sh --port 8080  any extra arguments are passed to app.py
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  echo "Creating virtual environment in .venv ..."
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt
  # when created under sudo, hand the venv back to the real user
  if [ -n "${SUDO_USER:-}" ]; then chown -R "$SUDO_USER" .venv; fi
fi

exec .venv/bin/python app.py "$@"
