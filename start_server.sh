#!/bin/bash

# Developed in Feb 2026 to automate X9.150 POC server startup.

# Function to kill background processes on exit
cleanup() {
    echo -e "
[*] Shutting down servers..."
    kill $CERTSERV_PID $APPSERVER_PID $QR_SERVER_PID 2>/dev/null
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

echo "[*] Activating virtual environment..."
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "[!] Error: venv directory not found. Create it with: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

echo "[*] Starting Certificate Server (port 5001)..."
python certserv.py &
CERTSERV_PID=$!

echo "[*] Starting Payee Server (port 5005)..."
python qr_server.py &
QR_SERVER_PID=$!
