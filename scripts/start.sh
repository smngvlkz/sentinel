#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "SentinelAI — Network Intrusion Detection System"
echo "================================================"
echo ""

# Check dependencies
command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Error: Docker daemon is not running."; exit 1; }

# Create .env if missing
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
fi

# Start infrastructure
echo "Starting infrastructure..."
cd docker
docker compose up -d --build
cd ..

echo ""
echo "Services:"
echo "  Dashboard    http://localhost:3001"
echo "  API          http://localhost:8000"
echo "  API Docs     http://localhost:8000/docs"
echo ""
echo "Packet capture requires root access."
echo "Start it separately:"
echo ""
echo "  sudo python3 capture_service/capture.py"
echo ""
echo "Or with a virtual environment:"
echo ""
echo "  sudo .venv/bin/python capture_service/capture.py"
echo ""
echo "Logs: cd docker && docker compose logs -f"
echo "Stop: cd docker && docker compose down"
