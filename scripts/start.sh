#!/bin/bash
set -e

echo "=== SentinelAI IDS ==="
echo "Starting infrastructure..."

cd "$(dirname "$0")/../docker"

# Start Redis + Postgres
docker compose up -d redis postgres

echo "Waiting for services to be ready..."
sleep 3

# Initialize database
docker compose exec postgres psql -U sentinel -d sentinel_ai -f /docker-entrypoint-initdb.d/schema.sql 2>/dev/null || true

echo "Starting capture service (requires sudo for packet sniffing)..."
echo "Starting analyzer..."
echo "Starting dashboard API..."

docker compose up -d

echo ""
echo "=== All services running ==="
echo "Dashboard API: http://localhost:8000"
echo "API Docs:      http://localhost:8000/docs"
echo ""
echo "View logs:     docker compose -f docker/docker-compose.yml logs -f"
echo "Stop:          docker compose -f docker/docker-compose.yml down"
