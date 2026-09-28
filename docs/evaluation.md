# Evaluating SentinelAI

## The built-in self-test

`make evaluate` replays a built-in labelled capture through the real
pipeline (packet parsing, flow tracking and the rules) and reports what was
caught and what was wrongly flagged. The capture has one of each attack,
plus normal traffic that fooled earlier versions: ordinary browsing, a fast
download, a download recorded as merged oversized frames, an FTP session and
a website replying to many connections at once.

| Attack | Detected |
|--------|----------|
| SYN flood | Yes |
| Port scan | Yes |
| UDP flood | Yes |
| Oversized packet | Yes |
| **Normal traffic wrongly flagged** | **0 of 14 host pairs** |

It runs in a few seconds and is part of the test suite, so a change that
makes detection worse fails CI.

That's a sanity check, not a benchmark, so SentinelAI is also being measured
on [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), a public
dataset of real traffic with labelled attacks.

## Results on CIC-IDS2017

The full Friday capture (9,915,680 packets, 08:59–17:02), replayed with the
detection rules only. Each labelled connection is scored: detected if
SentinelAI raised an alert on any of its packets.

| Attack | Connections | Detected | Recall |
|--------|------------:|---------:|-------:|
| Port scan | 158,420 | 158,053 | **99.8%** |
| DDoS (HTTP flood) | 45,383 | 181 | 0.4% |
| Botnet (Ares) | 1,228 | 0 | 0% |

| Normal traffic | |
|---|---|
| Normal connections | 190,541 |
| Wrongly flagged | **20 (0.01%)** |
| Precision (flagged connections that were real attacks) | 99.5% |

**What this means:**

- **Port scans are caught almost completely,** the job the port-scan rule is
  built for.
- **The DDoS and botnet are mostly missed, and that's expected from the
  rules.** The DDoS is an HTTP flood (LOIC): complete, normal-looking web
  requests rather than the SYN or UDP floods the rules look for. The botnet
  talks to its controller over ordinary-looking HTTP. Neither matches a
  signature, which is the gap the anomaly model is meant to cover.
  Application-layer attacks like these need deeper inspection than packet
  headers.
- **About the false alarm count:** scored strictly against the dataset's
  labels, 848 normal connections (0.44%) were flagged. 828 of those are
  between the attacker and the victim during the DDoS, on more than 20,000
  different ports, but labelled as normal. CIC-IDS2017 has known labelling
  errors of this kind (see Engelen, Rimmer and Joosen, *Troubleshooting an
  Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE Security and
  Privacy Workshops 2021), so they're left out of the numbers above.
  `scripts/evaluate.py` prints the strict figure.

The first run on this data flagged normal FTP sessions and large downloads,
which led to two fixes: established TCP traffic is no longer checked for
oversized packets (capturing computers merge it into large frames), and only
ports that never answer count towards a port scan (FTP's data ports answer).

### With the anomaly model

The model was trained on Friday's attack-free first hour (08:59–09:59) and
scored on the rest of the day. Because it judges each pair of hosts every
5 seconds rather than every connection, it's measured the way the dashboard
reports: **for each minute of traffic between two hosts, was there an alert?**

| Attack minutes caught | Rules | Model | Both |
|---|---:|---:|---:|
| DDoS (HTTP flood) | 4 of 34 | 22 of 34 | **25 of 34** |
| Port scan | 9 of 19 | 4 of 19 | 9 of 19 |
| Botnet (Ares) | 0 of 599 | 0 of 599 | 0 of 599 |
| **Normal minutes wrongly flagged** | 0.01% | 0.56% | 0.57% |

- **The model catches the DDoS the rules miss:** 25 of 34 attack minutes with
  both, against 4 with rules alone.
- **The cost is noise.** 0.56% of normal minutes on this 12-computer office
  network means roughly one false "Unusual traffic" alert a minute across
  the working day. That's why the model's alerts are rated medium ("Worth
  checking"), never high.
- **The botnet goes undetected.** Its traffic looks like ordinary web
  browsing in packet headers alone.
- **Slow port scans slip through.** Port scans are 99.8% caught by
  connection, but minutes where a scanner touched fewer than 21 ports aren't.

**How these settings were chosen:** judging every packet caught the same DDoS
minutes with nearly twice the false alarms (0.96%), because a busy
connection got hundreds of chances to trip the model. Dropping the running
totals (duration, packets and bytes so far) removed false alarms on DNS but
added more on web browsing.

## Running it yourself

The dataset is free but needs registration, and each day's capture is
several GB:

```bash
# A day's capture plus that day's labelled-flow CSVs
python scripts/evaluate.py Friday-WorkingHours.pcap Friday-*.pcap_ISCX.csv
python scripts/evaluate.py Friday-WorkingHours.pcap Friday-*.pcap_ISCX.csv --train-minutes 60   # train the model on the first hour, score the rest
```

Use CIC-IDS2017's labelled-flow CSVs (the ones with `Source IP` and
`Destination IP` columns), not the machine-learning CSVs, which leave the
IPs out. The script says so if a file is missing those columns.

It reports recall for each attack label, the share of normal traffic wrongly
flagged, and precision, per labelled connection and, with a model, per host
pair per minute. It reads pcap and pcapng files directly rather than through
scapy, so a multi-GB day takes a minute or two; `--max-packets` stops early
for a quick look.

Results on other public datasets are welcome as pull requests.
