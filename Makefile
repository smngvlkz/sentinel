.PHONY: up down logs build capture train clean

# Start infrastructure (Redis, PostgreSQL, analyzer, dashboard)
up:
	cd docker && docker compose up -d

# Stop everything
down:
	cd docker && docker compose down

# Rebuild all images
build:
	cd docker && docker compose build

# View logs
logs:
	cd docker && docker compose logs -f

# Start packet capture (requires sudo)
# Run this on the host machine, not in Docker.
capture:
	sudo .venv/bin/python capture_service/capture.py

# Collect baseline traffic and train the anomaly model
train-collect:
	.venv/bin/python ml-models/train_model.py --collect 3600

train-model:
	.venv/bin/python ml-models/train_model.py --train

# Setup local Python environment
setup-python:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

# Copy example env
setup-env:
	cp -n .env.example .env || true

# Full first-time setup
setup: setup-env setup-python
	cd docker && docker compose up -d redis postgres
	@echo "Waiting for PostgreSQL..."
	@sleep 5
	@echo "Infrastructure ready. Run 'make capture' to start packet capture."

# Remove volumes and built images
clean:
	cd docker && docker compose down -v --rmi local
