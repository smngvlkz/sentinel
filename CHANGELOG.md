# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Optional hostname context on alerts: when enabled, capture learns IP →
  name bindings from DNS answers, cleartext HTTP `Host` headers and the TLS
  server name (SNI), and the analyzer attaches those names to alert rows only
  (shown in the dashboard next to the IP). Names are remembered per device,
  so shared CDN addresses show the site that device used. Memory only, off
  by default; see `[names]` in `config/detection.toml` and
  `PAYLOAD_INSPECTION` in `.env`. Names that aren't valid hostnames are
  dropped whole rather than cleaned, so a hostile name can't be turned into a
  real-looking one, and capture logs a count of dropped names at most once a
  minute. TLS handshakes split across packets (common with post-quantum key
  shares in current browsers) are joined, so their server names are read
  too. Replaying 502 real HTTPS connections from a test Mac, the server name
  was read for 81% before and 99.8% after.
- Name your own devices from the alert drawer ("Name this device"), e.g.
  `192.168.1.20` → Living room TV. Names are stored by IP in a new
  `device_names` table and shown everywhere in place of the IP, including on
  older alerts. New API endpoints: `GET /devices`, `POST /devices/name`.

## [0.2.0] - 2026-09-29

### Added

- Two-way connection tracking (who opened each connection, whether it
  completed) and per-device activity counts over 10 and 60 seconds, which
  the new rules below build on.
- Request flood, distributed flood and network sweep rules. HTTP floods
  made of complete, normal-looking requests are now caught by the rules
  alone. Alerts from many sources, or across many devices, are grouped into
  one per victim or scanner, and the dashboard shows how many were involved.
- Regular check-ins rule (`BEACONING`) for botnet-style traffic: a device
  connecting to the same internet server again and again for an hour. Its
  alert repeats at most hourly. **Off by default**, because everyday
  software checks in the same way; `enabled = true` under `[beaconing]` in
  `config/detection.toml` turns it on.
- Held-out evaluation on CIC-IDS2017 Wednesday (attacks) and Monday (no
  attacks), with every threshold frozen before the runs, and results per
  machine as well as per flow.
- `--exclude-pair` option in `scripts/evaluate.py` to leave out known
  mislabelled traffic, so published numbers can be reproduced with one
  command.

### Fixed

- `scripts/evaluate.py` matched labels to connections without checking the
  time. Attack tools reuse source ports throughout the day, so some traffic
  was scored under the wrong attack. Scoring now counts an alert only if it
  was raised on that connection while the labelled flow was happening. All
  published results have been recalculated. The bug was found by the
  held-out Wednesday test.

  Corrected numbers for v0.1.0 (Friday, rescored with v0.1.0's own code):

  | Result | Published | Corrected |
  |---|---|---|
  | Port-scan connections caught | 99.8% | 99.7% of flows |
  | HTTP flood minutes caught, rules alone | 4 of 34 | 0 of 21 |
  | HTTP flood minutes caught, anomaly model | 22 of 34 | 21 of 21 |
  | HTTP flood minutes caught, rules and model | 25 of 34 | 21 of 21 |
  | Normal minutes flagged by the model | 0.56% | 0.57% |

  The flood lasted 21 minutes; the other 13 "flood minutes" were port-scan
  traffic on ports the flood later reused. Normal traffic flagged by the
  rules (0.01%) and botnet detection (none) are unchanged.

### Known limitations

- Several thresholds were chosen on Friday's traffic. Wednesday is a
  held-out test for the flood rules, but there's no held-out botnet day.
- Slow HTTP attacks (Slowloris, most of Slowhttptest) and Heartbleed aren't
  detected.
- The check-in rule can't tell legitimate scheduled software from malware
  by timing alone.

## [0.1.0] - 2026-09-28

> **Correction:** some accuracy figures in this release's notes were
> affected by a scoring bug. The corrected numbers are under
> [0.2.0](#020---2026-09-29) above.

First public release.

- Real-time capture and flow analysis, with rules for SYN floods, port scans,
  packet floods and oversized packets, plus an optional Isolation Forest
  anomaly model trained on your own network.
- Dashboard that explains each alert in plain language, with a review
  workflow for working through alerts.
- Tunable thresholds in `config/detection.toml`.
- `make demo` to try it with simulated attacks, no root access needed.
- Evaluation against CIC-IDS2017, with results in
  [docs/evaluation.md](docs/evaluation.md).

[Unreleased]: https://github.com/smngvlkz/sentinel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/smngvlkz/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/smngvlkz/sentinel/releases/tag/v0.1.0
