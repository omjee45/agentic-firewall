#!/bin/bash
set -e

echo "Starting Live Firewall Daemon with sudo..."
PYTHON_BIN=$(which python3)

sudo DRY_RUN=false $PYTHON_BIN agent/enforcer_daemon.py
