#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

PYTHON=".venv/bin/python"
APP_URL="http://127.0.0.1:8000"

if [[ ! -x "$PYTHON" ]]; then
    cat >&2 <<'EOF'
Access Log Triage virtual environment was not found.

Run these commands first:
  python3.12 -m venv .venv
  .venv/bin/python -m pip install -e ".[dev]"
EOF
    exit 1
fi

echo "Starting Access Log Triage at $APP_URL"
echo "Press Ctrl+C to stop the server."

if command -v xdg-open >/dev/null 2>&1; then
    (sleep 0.9; xdg-open "$APP_URL" >/dev/null 2>&1 || true) &
fi

exec "$PYTHON" -m access_log_triage
