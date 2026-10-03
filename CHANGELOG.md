# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-03

### Added

- Hard limits on everything the analyzer keeps in memory, under `[limits]`
  in `config/detection.toml`. Measured in the analyzer's Docker image under
  a flood of 20,000 connections a second from unique made-up addresses:
  0.3.0 grew by about 9.4 GB per million connections and never levelled off
  (on an 8 GB machine it was killed before reaching a million), with single
  packets held up for up to 673 ms. Now ten million such connections leave
  its memory flat at about 410 MB, and no packet waits more than about 15
  ms. The defaults sit far above anything real traffic has reached, so
  detection is unchanged: the CIC-IDS2017 Friday, Wednesday and Monday
  replays give exactly the published results.
- Entries seen more than once are protected from floods of one-off entries,
  so the limits don't let a flood of made-up addresses push a slow port scan
  out of memory before it's caught: under 20,000 made-up connections a
  second, a scan probing one port every 5 seconds is still caught. It has
  limits: that flood still hides a scan probing every 10 seconds, and a
  flood of 50,000 a second hides one probing every 5.
- A "Memory limit reached" alert (`RESOURCE_PRESSURE`, high severity, at
  most every 10 minutes) when any of those limits is hit, since that takes a
  flood far beyond normal traffic and means detection may be degraded.
- `/health` reports how well the analyzer is keeping up: its backlog of
  packets not yet read (`lag`) and in progress (`pending`), packets dropped
  from the stream before it read them (`packets_lost_unread`), every memory
  table's size, limit and entries dropped in the last minute (`tables`), and
  hostnames capture rejected as invalid (`names_dropped_total`).
- `make stress`: floods the analyzer with 10 million made-up connections and
  a hidden slow scan, and reports memory, pauses and whether the scan was
  caught (`scripts/stress_memory.py`).

### Changed

- Cleanup only looks at entries that have expired instead of every entry,
  and the analyzer skips Python's full garbage collections apart from one an
  hour. Under a flood, 0.3.0 paused for up to 673 ms; 0.4.0 stays under
  15 ms.

### Fixed

- The analyzer's count of open flows per source address kept an entry for
  every address it had ever seen, even after its count fell to zero, so its
  memory grew with every new address. On CIC-IDS2017 Friday it peaked at
  8,278 entries, 8,158 of them zero, and a flood from a million spoofed
  addresses would have left a million behind for good. Addresses are now
  removed when their last flow ends.
- Packets the analyzer had read but not finished when it was stopped stayed
  in Redis's list of unfinished work for good, so `pending` on `/health`
  never returned to 0 after a restart. The analyzer now clears them when it
  starts (only ones untouched for over a minute, so a second analyzer's
  in-flight work is left alone). They aren't reprocessed: the flow state
  they belonged to went with the old run.

### Known limitations

- Alerts are still never deleted, so the database keeps growing on a
  long-running install. Deleting old alerts comes in 0.5.0.
- A fast enough flood of made-up addresses can still hide a slow scan: one
  probing every 10 seconds under 20,000 made-up connections a second, or
  every 5 under 50,000. Reaching that point raises the "Memory limit
  reached" alert.
- Packets dropped by the kernel before capture sees them aren't reported
  yet; that comes with the capture rework in roadmap 1.4.
- The garbage-collector change only helps on Python 3.12, which the analyzer
  image uses; Python 3.14's collector works differently.

## [0.3.0] - 2026-10-03

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
  Alerts from the API now include `source_name`, `destination_name`,
  `source_device` and `destination_device`.

### Changed

- `make demo` shows hostnames: it turns name learning on (`NAMES_ENABLED`,
  a new setting that overrides `[names] enabled`) and the simulated
  attackers get made-up names on the reserved `.example` domains. `make up`
  is unaffected.
- Existing installs pick up the new database columns and the
  `device_names` table automatically when the analyzer and API start, so
  upgrading from 0.2.0 keeps all stored alerts.

### Fixed

- A distributed-flood false alarm against your own device when capture or
  the analyzer starts on a busy machine (after a reboot, for example). The
  connections already open were each mistaken for an internet host
  connecting in, because the first packet seen came from the server.
  During capture's first minute, connections seen without their opening
  handshake (TCP without a SYN, and UDP flows) no longer count as new
  connections. After that minute they count again, so floods and sweeps
  that never send a SYN (ACK or RST packets) are counted. Published
  results are unchanged.

### Known limitations

- Hostnames can't be learned from encrypted DNS (DNS over HTTPS/TLS) or
  from QUIC/HTTP3, where the server name is inside encrypted packets.
- Device names are stored by IP address, so a device that gets a new
  address from the router needs naming again.
- Learned hostnames are chosen by whoever sent the traffic: helpful
  context, not proof of identity.

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

[Unreleased]: https://github.com/smngvlkz/sentinel/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/smngvlkz/sentinel/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/smngvlkz/sentinel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/smngvlkz/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/smngvlkz/sentinel/releases/tag/v0.1.0
