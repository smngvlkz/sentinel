# Evaluating SentinelAI

## The built-in self-test

`make evaluate` replays a built-in labelled capture through the real
pipeline (packet parsing, flow tracking and the rules) and reports what was
caught and what was wrongly flagged. The capture has one of each attack,
plus normal traffic that fooled earlier versions or looks like an attack:
ordinary browsing, a fast download, a download recorded as merged oversized
frames, an FTP session, a website replying to many connections at once, a
busy DNS resolver, an office server used by many local devices, and
software polling on a schedule (every 15 minutes, and every 8 seconds for
ten minutes).

| Attack | Detected |
|--------|----------|
| SYN flood | Yes |
| Port scan | Yes |
| UDP flood | Yes |
| Oversized packet | Yes |
| Request flood | Yes |
| Distributed flood (80 sources) | Yes, every source |
| Network sweep (30 devices) | Yes, every target |
| Botnet check-ins (every 101 s for 70 minutes) | Yes |
| **Normal traffic wrongly flagged** | **0 of 117 host pairs** |

It runs in a few seconds and is part of the test suite, so a change that
makes detection worse fails CI.

That's a sanity check, not a benchmark, so SentinelAI is also being measured
on [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), a public
dataset of real traffic with labelled attacks.

## Results on CIC-IDS2017

Five days of the dataset, each replayed in full with the detection rules:

- **Friday** (9.9 million packets): port scan, HTTP flood, botnet. Several
  thresholds were tuned on this day, so its numbers are optimistic.
- **Wednesday** (13.7 million packets): five denial-of-service attacks,
  none of which SentinelAI was tuned on. Every threshold was frozen first,
  with a checksum of the detection code and config taken before the replay.
  This is the fair test.
- **Monday** (11.6 million packets): no attacks at all, so every alert is a
  false alarm. Held out the same way, with the same frozen thresholds.
- **Tuesday** (11.5 million packets) and **Thursday** (9.2 million packets):
  untouched until 0.6.2, then used once to validate the connection-flood
  fix. It **failed** the target set before the run; see below.

The Friday, Wednesday and Monday sections were measured before 0.6.2. The
connection-flood and traffic-burst false alarms they describe are gone since
then (see "All five days with 0.6.2's rules" below); everything else in them
still applies.

**How it's scored.** Each labelled flow (one row in the dataset's CSV) counts
as detected if SentinelAI alerted on that connection *while that flow was
happening*. The time matters because the attack tools reuse source ports all
day, so the same connection can carry a port scan at 2pm and a flood at 4pm.
The dataset's timestamps are local time (UTC−3) to the minute; 99.9% of
labelled flows line up with packets in the capture, which confirms the
conversion.

> **Correction.** Earlier versions of this page matched labels to
> connections without looking at time, which mixed up attacks that reused
> the same connection. The Friday numbers below replace those. The main
> change: the HTTP flood lasted 21 minutes, not 34. The other 13 were
> port-scan traffic on ports the flood later reused, so the flood minutes
> reported as missed never existed.

### Wednesday: held out, thresholds frozen

| Attack | Flows | Detected | Minutes caught |
|--------|------:|---------:|---------------:|
| DoS Hulk (HTTP flood) | 231,073 | **96.7%** | 18 of 22 |
| DoS GoldenEye (HTTP flood) | 10,293 | 37.8% | 5 of 9 |
| DoS Slowhttptest (slow HTTP) | 5,499 | 46.2% | 7 of 20 |
| DoS Slowloris (slow HTTP) | 5,796 | **0%** | 0 of 27 |
| Heartbleed | 11 | **0%** | 0 of 21 |

| Normal traffic | |
|---|---|
| Normal flows | 432,832 |
| Wrongly flagged by the check-in rule (one server) | 1,486 (0.34%) |
| Wrongly flagged by every other rule | **20 (0.005%)** |
| Normal minutes flagged (per host pair) | 0.41% |

**Per machine, as the dashboard shows it** (the real detector and alert
manager: one alert per threat per pair per minute, check-ins at most
hourly): 46 alerts over the day.

| | Machines | Alerts |
|---|---:|---:|
| Web server under attack, flagged during Hulk, GoldenEye and Slowhttptest | 1 of 1 | 29 |
| Heartbleed victim flagged for Heartbleed | 0 of 1 | 0 |
| Normal machines with at least one false alarm | **7 of 12** | 17 |

What caused the 17 false alarms:

- **Check-in rule (8):** the same server as on Friday, flagged hourly
  (see below).
- **Connection-flood rule (6), on three workstations:** in each case
  examined, a workstation opened 10 to 24 connections to one web server
  within a fraction of a second, the way browsers load pages. The server
  answered every one, but the
  rule only looks at the burst of connection requests, not whether they
  were answered. Fixed in 0.6.2, and validated on days not used to design
  the fix: see Tuesday and Thursday below.
- **Traffic-burst rule (3), on two workstations and the domain
  controller:** bursts of DNS lookups, up to about 340 a second, from two
  workstations to the office DNS server.

**What this means:**

- **The request-flood rule carries over to an attack it wasn't tuned on.**
  Hulk is a different HTTP flood tool from Friday's, and 96.7% of its flows
  were caught.
- **GoldenEye and Slowhttptest are caught only in part,** in the minutes
  where they open connections fast enough to cross a flood threshold.
- **Slow attacks are missed completely.** Slowloris and Slowhttptest hold a
  few hundred connections open by sending data as slowly as the server
  allows. That's low volume by design, and every SentinelAI rule looks for
  volume. Catching them needs a rule for many long, nearly idle connections
  to one server, which doesn't exist yet.
- **Heartbleed is missed.** It's 11 connections of ordinary-looking
  encrypted traffic; spotting it means reading the TLS records, which
  SentinelAI doesn't do.
- **The check-in rule's false alarm repeats.** On Wednesday the same
  server (`192.168.10.51`) is flagged checking in with the same internet
  service (now at `162.213.33.48` and `.44`, neighbours of Friday's
  `.50`). It's a real weakness of judging by timing alone, and it's left
  in rather than allow-listed.
- **Everything else stays quiet:** 20 falsely flagged normal flows out of
  432,832, the same rate as Friday, whose thresholds they come from.
- **About the false alarm count:** scored strictly against the dataset's
  labels, 6,909 normal flows were flagged. 5,403 of them are between the
  attacker and the web server. The dataset labels 6,789 flows between
  those two machines as normal, and 6,788 of them fall inside the attack
  hours (9 to 11am); 5,361 of the flagged ones share their exact connection
  and time with a flow labelled as an attack. They're left out with
  `--exclude-pair` (see below).

**With the anomaly model**, trained on Wednesday's attack-free first 18
minutes (08:42–09:00): it flagged 14 of the 22 Hulk minutes, two of them
minutes the rules missed (20 of 22 together), and nothing of the other
attacks, with almost no false alarms (4 normal flows, 0.01% of normal
minutes).

### Monday: held out, no attacks

Monday in CIC-IDS2017 is ordinary office traffic with no attacks, so it
measures one thing cleanly: false alarms. It was replayed with the same
frozen thresholds as Wednesday (the detection code's checksum still
matched), and 99.9% of its 529,918 labelled flows line up with packets in
the capture.

| Normal traffic | |
|---|---|
| Normal flows | 529,442 |
| Wrongly flagged by the check-in rule | **7,877 (1.49%)** |
| Wrongly flagged by every other rule | 41 (0.008%) |

**Per machine, as the dashboard shows it:** 49 alerts over the day, on
**9 of 13** machines.

| Rule | Alerts | Machines | What it was |
|---|---:|---|---|
| Regular check-ins | 34 | 3 | Two workstations reconnecting to dozens of web services all day, and the polling server from Friday and Wednesday (below) |
| Traffic burst | 12 | 5 | 11 between workstations and the office server, which answers DNS and directory lookups (the pattern Wednesday traced to DNS bursts); 1 from a workstation to an internet service |
| Connection flood | 3 | 3 | Short bursts of new connections from a workstation to a web server |

**The check-in rule's false alarms are much wider than one polling server.**
This is the most important result on this page. Friday and Wednesday each
showed one false alarm for the check-in rule: a single server polling one
internet service all day. Monday shows that ordinary web browsing can look
the same:

- One workstation (`192.168.10.25`) opened new connections to about 70
  different internet services at once, each every 8 to 40 seconds (some
  every few minutes), for about six hours.
- Another (`192.168.10.5`) did the same with about 25 services, for one to
  seven hours.
- Most of the addresses belong to large cloud and CDN networks (Google,
  Amazon, Akamai, Fastly). That fits a browser left open on busy pages
  whose ads and analytics keep reconnecting, but it's an inference:
  SentinelAI reads packet headers only, so it can't see the pages.
- The polling server from the other days (`192.168.10.51` to
  `162.213.33.44`) was flagged again: a new connection every 61 seconds for
  nearly eight hours.

The self-test assumed normal scheduled traffic either stops after a while
or repeats every 15 minutes or more. Monday shows that assumption is wrong
for ad-heavy web pages. There is no quick fix that stays honest: ignoring
devices with many check-in series at once would also hide Friday's bots,
which were ordinary workstations that kept browsing while infected. Any
change to the rule needs testing on data it wasn't designed on.

**The other rules:** 41 falsely flagged flows, the same low rate as
Friday (22) and Wednesday (20). Per machine it's less comfortable: 5 of 7
normal machines on Friday, 7 of 12 on Wednesday and 9 of 13 on Monday had
at least one false alarm. The traffic-burst alerts between workstations and
the office server have now appeared on two held-out days, so they're a
pattern rather than chance.

**With the anomaly model**, trained on Monday's first hour and scored on
the rest: 1,306 flows (0.28%) and 0.23% of normal minutes flagged.

**What's still untested.** Monday and Wednesday have now shaped decisions,
so any fix made from here (to the check-in rule or the DNS bursts) can't be
fairly tested on them. Tuesday and Thursday were kept for validating fixes,
and have now been used (below).

### Tuesday and Thursday: validating the connection-flood fix (failed)

**The fix (0.6.2).** Every high-severity false alarm on Friday, Wednesday
and Monday came from the connection-flood rule, and every one, when the
packets were examined, was a browser opening 9 to 23 connections to one
internet web server at once. The server answered all of them, but its
answers took 77 to 290 ms to come back, and the rule decided after 0.1
seconds, before most had arrived. The rule now counts only connection
requests still unfinished after a second (`handshake_seconds`), and needs
at least 10 of them (`min_unfinished`). A flood is reported about a second
in, instead of at 0.1 s, and one that stops within a second isn't reported.

**The test, set before running it.** Tuesday and Thursday hadn't been
opened. Before either was replayed, with the code's checksums recorded, the
targets were fixed as:

1. Across both days, no normal machine gets more than 1 high-severity false
   alarm.
2. No attack type's detection rate drops by more than 0.5 percentage points
   against the previous rule.

Both days were replayed with the old and the new rule, scored against the
dataset's labels as published, with no host pairs left out.

**Result: target 2 passes, target 1 fails.**

| | Old rule | New rule |
|---|---:|---:|
| Tuesday: normal machines with a high-severity false alarm | 3 | **1** |
| Tuesday: connection-flood false alarms (flows) | 14 | **0** |
| Thursday: normal machines with a high-severity false alarm | 12 | **10** |
| Thursday: connection-flood alerts | 52 | 34 |
| …from browser bursts | 5 | **0** |
| …from the infected machine scanning the network (below) | 46 | 33 |
| …from `172.16.0.1` to `192.168.10.51`, unexplained | 1 | 1 |
| Attack detection per flow, both days | | **identical** |

Target 2 passes, but weakly: no rule catches Tuesday's labelled attacks
(FTP and SSH password guessing) or Thursday's (web attacks and the
infiltration) in either version, so there was little detection to lose.

**Why target 1 fails.** Thursday afternoon is an infiltration attack. The
dataset's description says that once the Windows Vista machine
(`192.168.10.8`) was infected, it ran a port scan and Nmap against all the
other clients. The labels mark only 36 flows of the infiltration as attacks,
so that scan is labelled normal. 33 of the 34 connection-flood alerts the new
rule raises on Thursday are that scan, between 14:33 and 15:42, from `.8` to
eight other machines. They are real attack traffic, and a rule that met
target 1 on these labels would have to stay silent during a real network
scan. Counting the scan as an attack, target 1 would pass: one machine on
each day with a single high-severity alert.

But that reading was only made after seeing the results, so it doesn't
count: **the fix failed the target it was set**. It ships in 0.6.2 anyway,
because it removed every browser-burst false alarm on all five days without
losing a detection. What the target was guarding, notifications for
high-severity alerts, stays blocked until a fix passes a validation on data
it hasn't seen.

**The lesson.** The target should have been written against the dataset's
documented attack schedule, not only its labels. Earlier days had already
shown that the labels miss attack traffic (the host pairs left out on Friday
and Wednesday), and Thursday's infiltration scan is described on the
dataset's own page. The next validation will state its targets that way
from the start.

**Infiltration caught.** The labels score Thursday's infiltration at 0%,
but SentinelAI did flag it: the infected machine scanning the network raised
55 port-scan alerts and, with the new rule, 33 connection-flood alerts, all
between 14:33 and 15:42. On the labels these count as false alarms; they're
the infiltration's second step.

**Also on these days:** traffic-burst alerts (medium severity) between
workstations and the office server, the pattern Wednesday and Monday showed,
and one request-flood alert from a workstation on Tuesday, the only
high-severity false alarm on either day outside the infiltration. The
traffic-burst alerts were fixed afterwards (next section).

The five old-rule browser-burst alerts on Thursday were checked the same
way as on the other days: every connection request was answered and
completed within 3 seconds, with round trips of 107 to 154 ms.

### All five days with 0.6.2's rules

After the validation above, two more problems turned up, both fixed in
0.6.2. **Neither fix is validated.** Both were designed after Tuesday and
Thursday had been run, and the traffic-burst threshold below was chosen
after looking at those two days' alerts as well as Wednesday's and Monday's
(most of the bursts examined were on Tuesday). So Tuesday and Thursday are
as used up for these fixes as the other three days, and the numbers below
show what changed, not a fresh test.

- **Repeated floods were missed.** The rate rules average over a flow's
  life. A flow idle past its 30-second timeout was only cleared if the
  once-a-minute cleanup happened to run during the gap, so a flood that
  repeats every minute (like `make demo`'s) was caught 2 to 4 times in 10
  minutes, depending on timing. The same averaging hid bursts on long-lived
  flows. A flow idle past the timeout now starts afresh on its next packet:
  the demo's flood is caught every minute.
- **Traffic-burst false alarms.** With bursts no longer averaged away, the
  traffic-burst rule's false alarms showed up properly, and every one on the
  five days was the same thing: a workstation and the office server
  (`192.168.10.3`) exchanging a burst of directory and DNS lookups (LDAP,
  global catalog, DNS), 120 to 220 packets in 0.10 to 0.17 seconds, answered
  by the server. Real floods last longer (Friday's lasted 1.3 s), so a
  traffic burst now has to keep its rate up for a second (`min_seconds`).
  The one-second figure was picked from these alerts, on all five days,
  after the validation runs.

**Per machine, as the dashboard shows it on the default settings** (check-in
rule off), old rules against 0.6.2's:

| | Friday | Wednesday | Monday | Tuesday | Thursday |
|---|---:|---:|---:|---:|---:|
| Normal machines with a false alarm | 6 → **0** | 6 → **0** | 7 → **0** | 5 → **1** | 13 → 12 |
| …with a high-severity one | 4 → **0** | 3 → **0** | 3 → **0** | 3 → **1** | 12 → 10 |
| All alerts on the day | 53 → 38 | 38 → 29 | 15 → **0** | 18 → 1 | 143 → 97 |

Tuesday's one is the request-flood alert above. Thursday's are the infected
machine scanning the network, labelled normal in the dataset.

**On the website, with the check-in rule on** (the basis of its published
figures): normal machines with a false alarm are 1 of 7 on Friday (the
polling server), 0 of 11 on Wednesday, 3 of 13 on Monday (the three the
check-in rule flags), 2 of 12 on Tuesday and 10 of 11 on Thursday. Every one of Thursday's ten was
scanned by the infected machine; counting that documented scan as an attack,
a reading made after seeing the result, leaves 1 of 11 (the polling server). The old
rules give 5 of 7 and 9 of 13 counted the same way, matching the published
figures. "Normal machines" leaves out every machine involved in a labelled
attack that day; on Wednesday that now includes the Heartbleed target,
`192.168.10.51`, which the earlier figure (7 of 12) counted as normal.

**Per labelled flow**, normal flows wrongly flagged by any rule except the
check-in rule: Friday 22 → 0, Wednesday 20 → 0, Monday 41 → 0, Tuesday 964
→ 937 (all from that one request-flood alert). Detection of every attack
type is identical to the flow, except one: a single UDP packet to port 123
in Friday's port scan.

**Per minute**, attack minutes caught by the rules are identical, except
Friday's port scan: 13 of 26 minutes before, 12 now. The minute lost
(15:12) is that same UDP packet: the scanner sent no connection requests
in it. The old rules flagged it only because the scanner's count from two
minutes earlier was still on the flow, which depended on when cleanup ran.

### 24 hours on a real laptop

The check-in rule was also left running for 24 hours on the author's own
laptop (macOS, capturing that machine's traffic only, not a whole home
network), with nothing else changed. Every alert was traced to the program
behind it, from the laptop's open connections and DNS, not guessed from
address ranges:

| Alerts | Rule | Cause |
|---:|---|---|
| 34 | Regular check-ins | The Cursor code editor, talking to its servers |
| 16 | Regular check-ins | The Claude desktop app and Claude Code |
| 3 | Regular check-ins | Three Amazon EC2 addresses, program not identified |
| 110 | Unusual traffic (model) | Two large downloads of this dataset, matching the times the files were written |
| 4 | Unusual traffic and traffic burst | Single alerts to Google, Cloudflare and Amazon addresses, not identified |

No real threats. 53 check-in alerts in a day from tools the owner uses all
day is the same problem Monday showed, on the kind of machine SentinelAI is
built for. **So the check-in rule is off by default** (`enabled = false`
under `[beaconing]` in `config/detection.toml`). It still caught every
infected machine on Friday, so it's there for anyone who would rather have
noisy alerts than miss a bot. All the results on this page were measured
with it switched on.

### Friday: tuned on the same day

| Attack | Flows | Detected | Minutes caught |
|--------|------:|---------:|---------------:|
| Port scan | 158,924 | **99.7%** | 13 of 26 |
| DDoS (HTTP flood) | 128,027 | **99.9%** | **21 of 21** |
| Botnet (Ares) | 1,966 | 23.9% | 387 of 592 |

| Normal traffic | |
|---|---|
| Normal flows | 380,557 |
| Wrongly flagged by the check-in rule (one server) | 1,441 (0.38%) |
| Wrongly flagged by every other rule | **22 (0.006%)** |
| Normal minutes flagged (per host pair) | 0.51% (0.01% without the check-in rule) |

> **Read these numbers as optimistic.** The request-flood, distributed-flood
> and network-sweep thresholds were chosen by measuring Friday's normal
> traffic, and then scored on the same day. The false alarm rate in
> particular reflects a threshold picked to clear Friday's busiest normal
> traffic. Wednesday above is the fair test of those.
>
> The beaconing thresholds were chosen on Friday too, and Friday is the only
> day in CIC-IDS2017 with a botnet, so there's no held-out day to test how
> well they catch bots. Monday (above) tested their false alarms, and found
> many more than Friday suggests.

**Per machine, as the dashboard shows it:** 92 alerts over the day.

| | Machines | Alerts |
|---|---:|---:|
| Infected machines flagged by the check-in rule | **5 of 5** | 32 |
| Normal machines with at least one false alarm | **5 of 7** | 16 |

The rest are the attacks on the web server (42) and two connection-flood
alerts on infected machines unrelated to the botnet. The 16 false alarms:
one server flagged hourly by the check-in rule (7), traffic-burst alerts
between the DNS server and two workstations (6), and connection-flood
alerts on two workstations (3). Flow percentages hide this: 0.006% sounds
negligible, but over a day it reaches five of the seven normal machines.

**What this means:**

- **Port scans are caught almost completely,** the job the port-scan rule is
  built for. The minutes missed held 374 of about 158,900 scan flows, each
  probing 5 or fewer ports on one machine: short reconnaissance runs, below
  the rule's 20 ports.
- **The HTTP flood is caught by the request-flood rule, every minute of
  it.** It's made of complete, normal-looking web requests, which is why
  the SYN and packet flood rules missed all of it. What gives
  it away is volume: one source opening around 800 completed connections
  to one web server every 10 seconds, against a peak of 251 for the busiest
  normal traffic that day.
- **All five infected machines are flagged by the check-in rule,** each
  about 45 minutes after it starts checking in with the controller. The bots
  talk over ordinary-looking web traffic at a normal rate, so no volume rule
  sees them; what gives them away is persistence: a new connection to the
  same server every minute or two, for hours. Flow recall looks low because
  every check-in before the first alert counts as missed, and because the
  dataset labels 973 of the bots' flows with their controller as normal,
  though they're the same traffic. All 973 were flagged; counting them,
  49% of the bot traffic was caught.
- **The 973 "normal" bot flows are verified, not assumed.** Every label row
  involving the controller (`205.174.165.73`) comes from one of the five
  infected machines, on port 8080. The label reads "Bot" from 10:00 to
  12:59 and "normal" from 1pm to 5pm, while the same machines keep talking
  to the same controller on the same port. No other machine ever contacts
  that address.
- **The check-in rule's false alarm:** one server (`192.168.10.51`)
  checking in with one internet service (`162.213.33.50`) every few minutes
  all day, most likely an update or monitoring service. Timing can't tell
  that apart from malware. It's 1,441 flows because every flow in the
  series counts once the rule fires; on the dashboard it's one alert an
  hour.
- **About the false alarm count:** scored strictly against the dataset's
  labels, 34,702 normal flows were flagged. 32,266 of them are between the
  attacker and the web server, and 28,654 of those share their exact
  connection and time with a flow labelled as an attack; 973 are the bot
  flows above. CIC-IDS2017 has known labelling errors of this kind (see
  Engelen, Rimmer and Joosen, *Troubleshooting an Intrusion Detection
  Dataset: the CICIDS2017 Case Study*, IEEE Security and Privacy Workshops
  2021), so they're left out of the numbers above.
- **Not measured on any day:** none of the three days has a distributed
  flood (the floods come from a single machine) or a network sweep, so
  those two rules are only covered by the self-test. Neither raised a single
  false alarm on any of the three days.

The first run on this data flagged normal FTP sessions and large downloads,
which led to two fixes: established TCP traffic is no longer checked for
oversized packets (capturing computers merge it into large frames), and only
ports that never answer count towards a port scan (FTP's data ports answer).

**With the anomaly model**, trained on Friday's attack-free first hour
(08:59–09:59) and scored on the rest of the day. Because it judges each
pair of hosts every 5 seconds rather than every connection, it's measured
the way the dashboard reports: **for each minute of traffic between two
hosts, was there an alert?**

| Attack minutes caught | Rules | Model | Both |
|---|---:|---:|---:|
| DDoS (HTTP flood) | 21 of 21 | 21 of 21 | 21 of 21 |
| Port scan | 13 of 26 | 5 of 26 | 13 of 26 |
| Botnet (Ares) | 387 of 592 | 0 of 592 | 387 of 592 |
| **Normal minutes wrongly flagged** | 0.51% | 0.57% | 1.07% |

- **The model adds little detection.** It independently catches most of
  the HTTP floods, but the request-flood rule already catches them; on
  Wednesday it added two Hulk minutes the rules missed, on Friday none. Its
  value is for patterns no rule describes, which two days of labelled
  attacks can't show.
- **Its cost depends on the network.** On Friday 0.57% of normal minutes
  were flagged: on this office network, roughly one false "Unusual traffic"
  alert a minute across the working day. It was 0.01% on Wednesday and
  0.23% on Monday. That's why the model's alerts are rated medium ("Worth
  checking"), never high, and why it's optional.

**How the model's settings were chosen** (on Friday): judging every packet
caught the same DDoS minutes with nearly twice the false alarms (0.96%),
because a busy connection got hundreds of chances to trip the model.
Dropping the running totals (duration, packets and bytes so far) removed
false alarms on DNS but added more on web browsing.

## Running it yourself

The dataset is free but needs registration, and each day's capture is
several GB:

```bash
# A day's capture plus that day's labelled-flow CSVs
python scripts/evaluate.py Friday-WorkingHours.pcap Friday-*.pcap_ISCX.csv
python scripts/evaluate.py Friday-WorkingHours.pcap Friday-*.pcap_ISCX.csv --train-minutes 60   # train the model on the first hour, score the rest

# Leave out normal labels between host pairs the dataset mislabels (repeatable)
python scripts/evaluate.py Wednesday-workingHours.pcap Wednesday-*.pcap_ISCX.csv --train-minutes 18 \
  --exclude-pair 172.16.0.1 192.168.10.50
```

The exclusions used above: on Wednesday `172.16.0.1 192.168.10.50`; on
Friday the same pair plus each infected machine with its controller
(`192.168.10.5`, `.8`, `.9`, `.14` and `.15` with `205.174.165.73`); Monday
has no attacks, so it needs none. Tuesday and Thursday were scored with no
exclusions (see their section for what that means on Thursday). Only
normal labels are dropped; attacks between those hosts are still scored.
Without `--exclude-pair` the script prints the strict figures.

Use CIC-IDS2017's labelled-flow CSVs (the ones with `Source IP` and
`Destination IP` columns), not the machine-learning CSVs, which leave the
IPs out. The script says so if a file is missing those columns.

It reports recall for each attack label, the share of normal traffic wrongly
flagged, and precision, per labelled flow (matched by connection and time)
and, with a model, per host pair per minute. It reads pcap and pcapng files
directly rather than through scapy, so a 10–13 GB day replays in two to
three minutes; `--max-packets` stops early for a quick look.

Results on other public datasets are welcome as pull requests.
