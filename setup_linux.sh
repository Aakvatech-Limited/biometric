#!/bin/bash
echo "============================================"
echo "  Biometric Sync"
echo "============================================"
echo ""
echo "Starting automatic setup and launch..."
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Detect python3 or python
if command -v python3 &>/dev/null; then
    python3 "$SCRIPT_DIR/run.py"
elif command -v python &>/dev/null; then
    python "$SCRIPT_DIR/run.py"
else
    echo "[ERROR] Python is not installed."
    echo "        Install Python 3.9+:"
    echo "          Ubuntu/Debian: sudo apt install python3 python3-venv"
    echo "          Fedora:        sudo dnf install python3"
    exit 1
fi
