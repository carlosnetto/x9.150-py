#!/bin/bash

# Developed in Feb 2026 to automate X9.150 POC server startup.

# Function to kill background processes on exit
cleanup() {
    echo -e "
[*] Shutting down servers..."
    kill $CERTSERV_PID $APPSERVER_PID 2>/dev/null
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

echo "[*] Activating virtual environment..."
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "[!] Error: venv directory not found."
    exit 1
fi

echo "[*] Starting Certificate Server (port 8000)..."
python certserv.py &
CERTSERV_PID=$!

echo "[*] Starting QR App Server (port 5010)..."
python qr_appserver.py --root 'qr_app' &
APPSERVER_PID=$!

# Wait a moment for servers to initialize
sleep 2

echo "[*] Opening Pinggy Tunnel (Reverse Proxy to 5010)..."
echo "[*] Press Ctrl+C to stop all servers."
ssh -p 443 -R0:localhost:5010 free.pinggy.io
