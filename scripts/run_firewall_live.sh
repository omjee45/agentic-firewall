#!/bin/bash
set -e

echo "Starting Live Firewall Daemon with sudo..."
PYTHON_BIN=$(which python3)

# Pass DRY_RUN=false securely into the elevated daemon
sudo DRY_RUN=false $PYTHON_BIN agent/enforcer_daemon.py
