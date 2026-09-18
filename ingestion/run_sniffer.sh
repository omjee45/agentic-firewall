#!/bin/bash
cd "$(dirname "$0")"
cd ..

# Try to activate venv if present in root
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

cd ingestion

echo "Starting sniffer pipeline with sudo..."
# Use the absolute path to the virtual environment's python executable
PYTHON_BIN=$(which python3)
sudo "$PYTHON_BIN" indexer.py
