# Contributing to SentinelAI

Thanks for helping out. This guide gets you from a fresh clone to a pull request.

## Development setup

You need Docker, Python 3.12+ and Node 22+.

```bash
git clone https://github.com/<your-username>/sentinel.git
cd sentinel
make setup    # .env plus a .venv with runtime and dev dependencies
make demo     # full stack with simulated attacks at http://localhost:3001
```

To work on the dashboard with hot reload, keep the stack running and start
the dev server. It talks to the API from the Docker stack.

```bash
cd dashboard && npm install && cd ..
make dashboard-dev    # http://localhost:3000
```

## Everyday commands

Run `make` on its own for the full list. The ones you'll use while developing:

| Command | When to use it |
|---------|----------------|
| `make up` | After changing Python or dashboard code. The services run from Docker images, so this rebuilds whatever changed and restarts it. |
| `make restart` | After editing `config/detection.toml` or training a model. It only restarts the analyzer, no rebuild. |
| `make demo` / `make demo-stop` | Start and stop simulated attacks, to see detection and the dashboard working. |
| `make status` / `make logs` | See which services are running, and follow their output. |
| `make down` | Stop everything and keep your data. |
| `make clean` | Stop everything and **delete all stored alerts** and built images. Use it for a clean slate. |

To exercise the anomaly model, start capture (`make capture`) or the demo,
then `make train-collect` (Ctrl+C to stop early), `make train-model` and
`make restart`.

## Checks

CI runs three checks on every pull request, and all three must pass before
anything merges into `master`. To run the same things locally:

```bash
# Python lint and tests
make test                       # Python tests
make evaluate                   # detection quality on a synthetic labelled capture (also run by make test)
make lint                       # ruff + dashboard eslint

# Dashboard lint and build
cd dashboard && npx tsc --noEmit && npm run build

# Docker images build from a clean checkout
make build
```

## Where things live

- **Detection logic:** `detection_engine/`. Features come from `analysis_service/`: `feature_extractor.py` for one-way flows, and `connections.py` for two-way connections and per-host activity over 10- and 60-second windows.
- **Database schema:** `database/schema.sql`, applied only when the Postgres volume is first created. Existing installs don't re-run it, so a new column or table must also be added with `IF NOT EXISTS` where the services start (`AlertManager._ensure_schema` in `alert_service/alert_manager.py`, and `_get_pool` in `dashboard-api/main.py`). Upgrades then keep their alerts. Proper migrations are planned in [roadmap 1.2](docs/ROADMAP.md).
- **Demo traffic:** `scripts/simulate_attack.py`.

### Adding a detection rule

A new threat type touches several places. Miss one and it shows up unlabelled or in the wrong severity:

1. A method on `RuleEngine` in `detection_engine/rules.py`, with tests in `tests/test_rules.py`.
2. Its thresholds in `config/detection.toml` and `DEFAULTS` in `detection_engine/config.py`. `tests/test_config.py` checks the two match.
3. Its severity in `SEVERITY` in `dashboard-api/main.py` (used for filtering and counts) **and** in `dashboard/src/lib/threats.ts`, along with its plain-language explanation and next steps.
4. An icon in `THREAT_ICON` in `dashboard/src/components/ui.tsx`. Pick a [Lucide](https://lucide.dev/icons) icon whose shape doesn't clash with the existing ones.
5. A scenario in `scripts/simulate_attack.py`, so `make demo` shows it firing.
6. An attack (and, if it's prone to false alarms, a look-alike normal pattern) in `synthetic_capture()` in `scripts/evaluate.py`, so `make evaluate` guards it.
7. A row in the README's detection rules table.

## Pull requests

1. Fork the repo and branch from `master`. `master` is protected: changes land only through pull requests.
2. Keep each pull request to one change, with tests for new behaviour.
3. Make sure the checks above pass.
4. Open the pull request against `master` and fill in the template.

For anything large, open an issue first so we can agree on the approach.

## Reporting security issues

Please don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
