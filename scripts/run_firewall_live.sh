#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

VENV_PYTHON="${PROJECT_ROOT}/venv/bin/python"

echo "Starting Live Firewall Daemon..."

sudo PYTHONPATH="${PROJECT_ROOT}" "$VENV_PYTHON" -m agent.enforcer_daemon
