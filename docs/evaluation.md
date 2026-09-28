# Evaluating SentinelAI

## The built-in self-test

`make evaluate` replays a built-in labelled capture through the real
pipeline (packet parsing, flow tracking and the rules) and reports what was
caught and what was wrongly flagged. The capture has one of each attack,
plus normal traffic that fooled earlier versions or looks like an attack:
ordinary browsing, a fast download, a download recorded as merged oversized
frames, an FTP session, a website replying to many connections at once, a
busy DNS resolver, and an office server used by many local devices.

| Attack | Detected |
|--------|----------|
| SYN flood | Yes |
| Port scan | Yes |
| UDP flood | Yes |
| Oversized packet | Yes |
| Request flood | Yes |
| Distributed flood (80 sources) | Yes, every source |
| Network sweep (30 devices) | Yes, every target |
| **Normal traffic wrongly flagged** | **0 of 115 host pairs** |

It runs in a few seconds and is part of the test suite, so a change that
makes detection worse fails CI.

That's a sanity check, not a benchmark, so SentinelAI is also being measured
on [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), a public
dataset of real traffic with labelled attacks.

## Results on CIC-IDS2017

The full Friday capture (9,915,680 packets, 08:59–17:02), replayed with the
detection rules only. Each labelled connection is scored: detected if
SentinelAI raised an alert on any of its packets.

> **Read these numbers as optimistic.** The request-flood, distributed-flood
> and network-sweep thresholds were chosen by measuring Friday's normal
> traffic, and then scored on the same day. The false alarm rate in
> particular reflects a threshold picked to clear Friday's busiest normal
> traffic. A held-out day, with every threshold frozen, is the fair test;
> results for Wednesday will be added here when that run is done.

| Attack | Connections | Detected | Recall |
|--------|------------:|---------:|-------:|
| Port scan | 158,420 | 158,064 | **99.8%** |
| DDoS (HTTP flood) | 45,383 | 45,383 | **100%** |
| Botnet (Ares) | 1,228 | 0 | 0% |

| Normal traffic | |
|---|---|
| Normal connections | 190,541 |
| Wrongly flagged | **20 (0.01%)** |
| Precision (flagged connections that were real attacks) | 99.5% |

**What this means:**

- **Port scans are caught almost completely,** the job the port-scan rule is
  built for.
- **The HTTP flood is caught by the request-flood rule.** It's made of
  complete, normal-looking web requests, which is why the SYN and packet
  flood rules missed it (they caught 0.4%). What gives it away is volume: one
  source opening around 800 completed connections to one web server every 10
  seconds, against a peak of 251 for the busiest normal traffic that day.
- **The botnet is missed.** It talks to its controller over ordinary-looking
  web traffic, at a normal rate. Catching it needs a different signal, such
  as the regular timing of its check-ins.
- **About the false alarm count:** scored strictly against the dataset's
  labels, 933 normal connections (0.49%) were flagged. 913 of those are
  between the attacker and the victim during the DDoS, on more than 20,000
  different ports, but labelled as normal. CIC-IDS2017 has known labelling
  errors of this kind (see Engelen, Rimmer and Joosen, *Troubleshooting an
  Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE Security and
  Privacy Workshops 2021), so they're left out of the numbers above.
  `scripts/evaluate.py` prints the strict figure.
- **Not measured here:** Friday has no distributed flood (the "DDoS" came
  from a single machine) and no network sweep, so those two rules are only
  covered by the self-test. Neither raised a single false alarm across the
  day.

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
| DDoS (HTTP flood) | 25 of 34 | 22 of 34 | 25 of 34 |
| Port scan | 9 of 19 | 4 of 19 | 9 of 19 |
| Botnet (Ares) | 0 of 599 | 0 of 599 | 0 of 599 |
| **Normal minutes wrongly flagged** | 0.01% | 0.56% | 0.57% |

- **On this capture the model adds no detection.** It independently catches
  most of the HTTP flood, but the request-flood rule now catches everything
  it does. Its value is for patterns no rule describes, which a single day of
  labelled attacks can't show.
- **The cost is noise.** 0.56% of normal minutes on this 12-computer office
  network means roughly one false "Unusual traffic" alert a minute across
  the working day. That's why the model's alerts are rated medium ("Worth
  checking"), never high, and why it's optional.
- **Every minute of the HTTP flood itself (15:56–16:16) raised an alert.**
  The DDoS minutes counted as missed are elsewhere: scattered minutes hours
  earlier, each holding 1 to 8 connections labelled DDoS (56 in all,
  against about 45,000 in the flood). They come from the attacker's address
  to the victim's web server, and their pattern (connect, then reset) looks
  like probing rather than the flood; several coincide with port-scan
  minutes. So they're real attack traffic, probably filed under the wrong
  attack name, and missed: at 1 to 8 connections a minute they're far below
  anything a volume rule can catch.
- **Small scans slip through.** The port-scan minutes missed held 305 of
  about 158,900 scan connections. Each involved one attacker and one target
  host, probing 5 or fewer ports: short reconnaissance runs rather than full
  scans. That's below the port-scan rule's 20 ports, and because only one
  host was targeted, the network-sweep rule doesn't apply either.

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
