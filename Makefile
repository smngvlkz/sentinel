-include .env

# Compose reads .env from the repo root (not docker/), when it exists.
COMPOSE := docker compose -f docker/docker-compose.yml $(if $(wildcard .env),--env-file .env)
PY := .venv/bin/python
UI_URL := http://localhost:$(or $(DASHBOARD_UI_PORT),3001)
# Set when DASHBOARD_BIND lets other devices open the dashboard.
EXPOSED := $(filter-out 127.0.0.1 localhost ::1,$(strip $(DASHBOARD_BIND)))

.DEFAULT_GOAL := help
.PHONY: help demo demo-stop up down password restart logs status build capture setup setup-env setup-python \
        train-collect train-model test evaluate stress lint dashboard-dev install-launchd clean

help: ## Show this help
	@echo "SentinelAI"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(firstword $(MAKEFILE_LIST)) | awk 'BEGIN {FS = ":.*?## "}; {printf "  make %-16s %s\n", $$1, $$2}'

.env:
	@cp .env.example .env
	@echo "Created .env from .env.example"

# ── Try it ──────────────────────────────────────────────────────────────

demo: .env ## Start everything with simulated attacks (no root needed)
	NAMES_ENABLED=true $(COMPOSE) --profile demo up -d --build
	@echo ""
	@echo "SentinelAI is running with simulated traffic."
	@echo "Open $(UI_URL) — the first alerts appear within a few seconds."
	@echo "Stop the simulated traffic with: make demo-stop"

demo-stop: ## Stop the simulated traffic (leaves the dashboard running)
	$(COMPOSE) --profile demo stop simulator

# ── Run it for real ─────────────────────────────────────────────────────

setup: .env setup-python ## First-time setup: .env and a Python venv for capture

setup-python:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

up: .env ## Start Redis, Postgres, analyzer, API and dashboard
	$(COMPOSE) up -d --build
	@echo ""
	@echo "Dashboard: $(UI_URL)"
ifneq ($(EXPOSED),)
	@echo "Other devices can open it too, at this machine's address, port $(or $(DASHBOARD_UI_PORT),3001)."
	@echo "If you haven't set a password yet, it won't start until you run: make password"
endif
	@echo "Next, start packet capture in another terminal: make capture"

capture: ## Capture live packets from CAPTURE_INTERFACE (asks for sudo)
	@test -x $(PY) || { echo "Run 'make setup' first."; exit 1; }
	sudo $(PY) capture_service/capture.py

down: ## Stop all services
	$(COMPOSE) --profile demo down

# A one-off container, so it works while the API is refusing to start for want
# of a password; the restart then lets the API start without waiting.
password: .env ## Set or reset the dashboard password (also logs everyone out)
	$(COMPOSE) run --rm dashboard-api python -m dashboard-api.set_password
	@$(COMPOSE) restart dashboard-api >/dev/null 2>&1 || true

restart: ## Restart the analyzer (after editing config or training a model)
	$(COMPOSE) restart analyzer

status: ## Show which services are running
	$(COMPOSE) --profile demo ps

logs: ## Follow logs from all services
	$(COMPOSE) --profile demo logs -f

build: ## Rebuild all images
	$(COMPOSE) --profile demo build

# ── Anomaly model ───────────────────────────────────────────────────────

train-collect: ## Record normal traffic, up to 1 hour (Ctrl+C to stop early and keep it)
	$(PY) ml-models/train_model.py --collect 3600

train-model: ## Train the anomaly model on recorded traffic, then run make restart
	$(PY) ml-models/train_model.py --train

# ── Development ─────────────────────────────────────────────────────────

test: ## Run the Python test suite
	$(PY) -m pytest

evaluate: ## Check detection quality on a built-in labelled capture
	$(PY) scripts/evaluate.py --self-test

stress: ## Flood the analyzer with 10 million spoofed connections (memory caps)
	$(COMPOSE) run --rm --no-deps -v "$(CURDIR):/app" analyzer python scripts/stress_memory.py

lint: ## Lint Python and the dashboard
	$(PY) -m ruff check .
	cd dashboard && npm run lint

dashboard-dev: ## Run the dashboard with hot reload on http://localhost:3000
	cd dashboard && npm run dev

install-launchd: ## macOS: run capture at boot as a LaunchDaemon (asks for sudo)
	@mkdir -p logs
	sed -e "s|__SENTINEL_DIR__|$(CURDIR)|g" -e "s|__CAPTURE_INTERFACE__|$(or $(CAPTURE_INTERFACE),en0)|g" \
		scripts/com.sentinelai.capture.plist > logs/com.sentinelai.capture.plist
	sudo cp logs/com.sentinelai.capture.plist /Library/LaunchDaemons/
	sudo launchctl load -w /Library/LaunchDaemons/com.sentinelai.capture.plist
	@echo "Capture now starts at boot. Logs: logs/capture.log"

clean: ## Stop everything and delete all stored alerts and images
	$(COMPOSE) --profile demo down -v --rmi local
