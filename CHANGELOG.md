# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

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

[0.1.0]: https://github.com/smngvlkz/sentinel/releases/tag/v0.1.0
