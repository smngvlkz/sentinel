"""
Offline evaluation: replay a labelled packet capture through the detection
pipeline and report how many attacks were caught and how much normal
traffic was wrongly flagged.

Usage:
    python scripts/evaluate.py capture.pcap labels.csv [more.csv ...] [--with-model] [--max-packets N]
    python scripts/evaluate.py --self-test

Labels are CSV rows with a source IP, destination IP and label, and
optionally source port, destination port and protocol. Headers are matched
loosely, so CIC-IDS2017's labelled-flow CSVs work as they are. BENIGN (any
case) means normal traffic; any other label is an attack.

With ports and protocol, scoring is per connection: a labelled connection
counts as detected if SentinelAI raised an alert on any of its packets.
Without them it falls back to per host pair. Either way, direction doesn't
matter, since labels and alerts may name the two ends in opposite order.
"""

from __future__ import annotations

import argparse
import csv
import os
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, UDP, Raw  # noqa: E402

from analysis_service.feature_extractor import FlowTracker  # noqa: E402
from capture_service.capture import parse_packet  # noqa: E402
from detection_engine.anomaly_model import FEATURE_KEYS  # noqa: E402
from detection_engine.config import has_rate_evidence, load_config  # noqa: E402
from detection_engine.rules import RuleEngine  # noqa: E402

BENIGN = "BENIGN"
# Every rule's alert type, read from the engine so new rules are always included.
RULE_TYPES = {name for name, _ in RuleEngine(config={}).rules}
# The analyzer drops flows idle for 30s, checking every 60s.
CLEANUP_INTERVAL = 60.0

Key = frozenset  # frozenset of IPs (pair) or of (ip, port) ends plus protocol (connection)


def pair_key(a: str, b: str) -> Key:
    return frozenset((a, b))


def conn_key(proto: str, a: str, a_port: str, b: str, b_port: str) -> Key:
    return frozenset(((a, a_port), (b, b_port), ("proto", proto)))


# ── Labels ──────────────────────────────────────────────────────────────


@dataclass
class Labels:
    by_connection: bool
    keys: dict[Key, str]


def _norm(header: str) -> str:
    return header.strip().lower().replace(" ", "_")


def load_labels(paths: list[str]) -> Labels:
    """Key -> BENIGN, or the most common attack label recorded for it."""
    attacks: dict[Key, Counter[str]] = defaultdict(Counter)
    benign: set[Key] = set()
    by_connection: bool | None = None
    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            cols = {_norm(h): h for h in reader.fieldnames or []}
            src = cols.get("source_ip") or cols.get("src_ip")
            dst = cols.get("destination_ip") or cols.get("dst_ip")
            lab = cols.get("label")
            if not (src and dst and lab):
                raise SystemExit(f"{path}: need source IP, destination IP and label columns, found {reader.fieldnames}")
            sport = cols.get("source_port") or cols.get("src_port")
            dport = cols.get("destination_port") or cols.get("dst_port")
            proto = cols.get("protocol")
            has_ports = bool(sport and dport and proto)
            if by_connection is not None and has_ports != by_connection:
                raise SystemExit("labels files disagree: some have port and protocol columns and some don't")
            by_connection = has_ports
            for row in reader:
                if not row.get(src):
                    continue
                if by_connection:
                    key = conn_key(row[proto].strip(), row[src].strip(), row[sport].strip(),
                                   row[dst].strip(), row[dport].strip())
                else:
                    key = pair_key(row[src].strip(), row[dst].strip())
                label = row[lab].strip()
                if label.upper() == BENIGN:
                    benign.add(key)
                else:
                    attacks[key][label] += 1
    keys = {k: BENIGN for k in benign}
    # A key with any attack rows is an attack, named by its most common label.
    keys.update({k: counts.most_common(1)[0][0] for k, counts in attacks.items()})
    return Labels(bool(by_connection), keys)


# ── Reading captures ────────────────────────────────────────────────────

# TCP flag letters in bit order, matching how scapy renders flags ("S", "SA", "PA").
_TCP_FLAGS = "FSRPAUECN"


def _flag_str(bits: int) -> str:
    return "".join(ch for i, ch in enumerate(_TCP_FLAGS) if bits & (1 << i))


def _parse_ethernet(data: bytes, timestamp: float, orig_len: int) -> dict[str, str] | None:
    """Pull the fields parse_packet() produces out of a raw Ethernet frame."""
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    off = 14
    while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags
        ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    if ethertype != 0x0800 or len(data) < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    entry = {
        "timestamp": str(timestamp),
        "src_ip": ".".join(map(str, data[off + 12:off + 16])),
        "dst_ip": ".".join(map(str, data[off + 16:off + 20])),
        "protocol": str(proto),
        "packet_size": str(orig_len),
    }
    l4 = off + ihl
    if proto == 6 and len(data) >= l4 + 14:
        sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
        bits = ((data[l4 + 12] & 0x01) << 8) | data[l4 + 13]
        entry.update(src_port=str(sport), dst_port=str(dport), flags=_flag_str(bits), transport="TCP")
    elif proto == 17 and len(data) >= l4 + 4:
        sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
        entry.update(src_port=str(sport), dst_port=str(dport), flags="", transport="UDP")
    else:
        entry.update(src_port="0", dst_port="0", flags="", transport="OTHER")
    return entry


def _read_classic(f, header: bytes, path: str) -> Iterator[dict[str, str]]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    endian, frac = formats[header[:4]]
    header += f.read(24 - len(header))
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    if linktype != 1:
        raise SystemExit(f"{path}: only Ethernet captures are supported (link type {linktype})")
    rec = struct.Struct(endian + "IIII")
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = rec.unpack(rh)
        data = f.read(incl_len)
        if len(data) < incl_len:  # truncated, e.g. a capture still downloading
            return
        entry = _parse_ethernet(data, ts_sec + ts_frac * frac, orig_len)
        if entry:
            yield entry


def _read_pcapng(f, path: str) -> Iterator[dict[str, str]]:
    """Section header, interface description and (enhanced/simple) packet blocks."""
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (link type, seconds per timestamp unit)
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            # Section header: the byte-order magic that follows sets endianness.
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", head[4:8])[0]
            body = f.read(length - 12)
            if len(body) < length - 12:
                return
            interfaces = []
            continue
        btype, length = struct.unpack(endian + "II", head)
        body = f.read(length - 8)
        if len(body) < length - 8:  # truncated
            return
        if btype == 1:  # interface description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            resolution = 1e-6
            opts = body[8:-4]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = opts[i + 4]
                    resolution = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + olen + (-olen % 4)
            interfaces.append((linktype, resolution))
        elif btype == 6:  # enhanced packet
            iface, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, resolution = interfaces[iface] if iface < len(interfaces) else (1, 1e-6)
            if linktype != 1:
                continue
            entry = _parse_ethernet(body[20:20 + cap_len], ((ts_hi << 32) | ts_lo) * resolution, orig_len)
            if entry:
                yield entry


def read_pcap(path: str) -> Iterator[dict[str, str]]:
    """
    Stream packets from a pcap or pcapng file as the same dicts parse_packet()
    produces, reading only the headers needed. Much faster than decoding
    every packet with scapy, which matters for multi-GB captures. A capture
    that's still being written is read up to its last complete packet.
    """
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            yield from _read_pcapng(f, path)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _read_classic(f, magic, path)
        else:
            raise SystemExit(f"{path}: not a pcap or pcapng file")


# ── Replay ──────────────────────────────────────────────────────────────


@dataclass
class Replay:
    packets: int = 0
    by_pair: dict[Key, set[str]] = field(default_factory=lambda: defaultdict(set))
    by_connection: dict[Key, set[str]] = field(default_factory=lambda: defaultdict(set))
    # Everything that appeared in the capture, so labels for traffic that
    # isn't in it (a partial capture, or a label/capture mismatch) aren't
    # counted as misses.
    seen_pairs: set[Key] = field(default_factory=set)
    seen_connections: set[Key] = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None
    # Per host pair per minute, matching how the dashboard reports (one alert
    # per pair per minute). Filled when labels are passed to replay().
    minute_label: dict[tuple[Key, int], str] = field(default_factory=dict)
    minute_alerts: dict[tuple[Key, int], set[str]] = field(default_factory=lambda: defaultdict(set))


# Model predictions are made in batches: exactly the same answers as the
# analyzer's one-packet-at-a-time scoring, far faster.
MODEL_BATCH = 50_000


def load_train_model():
    """ml-models/train_model.py, for its sampler and model settings (the folder name isn't importable)."""
    import importlib.util

    path = os.path.join(os.path.dirname(__file__), "..", "ml-models", "train_model.py")
    spec = importlib.util.spec_from_file_location("train_model", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def train_on_first(entries: Iterator[dict[str, str]], minutes: float):
    """
    Fit the anomaly model on a capture's first `minutes`, sampled exactly as
    `make train-collect` samples live traffic. Returns (model, samples, cutoff).
    """
    train_model = load_train_model()
    sampler = train_model.BaselineSampler()
    samples: list[list[float]] = []
    cutoff = None
    for entry in entries:
        now = float(entry["timestamp"])
        if cutoff is None:
            cutoff = now + minutes * 60
        if now >= cutoff:
            break
        sample = sampler.add(entry)
        if sample is not None:
            samples.append(sample)
    if not samples:
        raise SystemExit("no usable training samples in that window")
    return train_model.fit_model(samples), len(samples), cutoff


def replay(
    entries: Iterable[dict[str, str]],
    with_model: bool = False,
    model=None,
    score_after: float | None = None,
    model_interval: float | None = None,
    labels: Labels | None = None,
    max_packets: int | None = None,
    progress: bool = False,
) -> Replay:
    """
    Run packets through the same flow -> detect path as the live analyzer.

    `model` is a fitted anomaly model (or `with_model` loads the saved one).
    With `score_after`, earlier packets still build up flow state but aren't
    scored, e.g. when they were used for training. `model_interval` defaults
    to the analyzer's judge interval from config; 0 judges every packet.
    """
    config = load_config()
    if model_interval is None:
        model_interval = float(config["anomaly"]["judge_interval_seconds"])
    rules = RuleEngine(config)
    if with_model:
        from detection_engine.anomaly_model import AnomalyDetector

        model = AnomalyDetector().model
        if model is None:
            raise SystemExit("--with-model: no trained model at ml-models/saved/anomaly_model.pkl")

    tracker = FlowTracker()
    result = Replay()
    last_cleanup = None
    started = time.time()
    pending: list[tuple[Key, Key, tuple[Key, int], list[float]]] = []
    # With model_interval, the model judges each flow at most that often.
    last_judged: dict[tuple[str, str], float] = {}

    def flush() -> None:
        if not pending:
            return
        import numpy as np

        predictions = model.predict(np.array([v for _, _, _, v in pending]))
        for (pair, conn, minute, _), p in zip(pending, predictions):
            if p == -1:
                result.by_pair[pair].add("ANOMALY")
                result.by_connection[conn].add("ANOMALY")
                result.minute_alerts[minute].add("ANOMALY")
        pending.clear()

    for entry in entries:
        result.packets += 1
        now = float(entry["timestamp"])
        if last_cleanup is None:
            last_cleanup = now
        elif now - last_cleanup > CLEANUP_INTERVAL:
            tracker.cleanup_stale(now)
            last_cleanup = now

        features = tracker.update(entry)
        if score_after is not None and now < score_after:
            continue

        pair = pair_key(entry["src_ip"], entry["dst_ip"])
        conn = conn_key(entry["protocol"], entry["src_ip"], entry["src_port"], entry["dst_ip"], entry["dst_port"])
        result.seen_pairs.add(pair)
        result.seen_connections.add(conn)
        if result.first_ts is None:
            result.first_ts = now
        result.last_ts = now

        minute = (pair, int(now // 60))
        if labels is not None:
            label = labels.keys.get(conn if labels.by_connection else pair)
            if label is not None and result.minute_label.get(minute, BENIGN) == BENIGN:
                result.minute_label[minute] = label

        found = rules.evaluate(features)
        if found:
            result.by_pair[pair].update(found)
            result.by_connection[conn].update(found)
            result.minute_alerts[minute].update(found)
        flow = (entry["src_ip"], entry["dst_ip"])
        due = model_interval <= 0 or now - last_judged.get(flow, float("-inf")) >= model_interval
        if model is not None and due and has_rate_evidence(features, config):
            last_judged[flow] = now
            pending.append((pair, conn, minute, [features[k] for k in FEATURE_KEYS]))
            if len(pending) >= MODEL_BATCH:
                flush()

        if progress and result.packets % 1_000_000 == 0:
            rate = result.packets / (time.time() - started)
            print(f"  {result.packets:,} packets ({rate:,.0f}/s)", file=sys.stderr, flush=True)
        if max_packets and result.packets >= max_packets:
            break
    if model is not None:
        flush()
    return result


# ── Scoring ─────────────────────────────────────────────────────────────


@dataclass
class Report:
    unit: str
    by_label: dict[str, tuple[int, int]]  # label -> (labelled, detected)
    benign: int
    false_positives: int
    fp_alert_types: Counter[str]
    unlabelled_alerts: int
    not_in_capture: int

    @property
    def attacks(self) -> int:
        return sum(n for n, _ in self.by_label.values())

    @property
    def detected(self) -> int:
        return sum(d for _, d in self.by_label.values())

    @property
    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    @property
    def precision(self) -> float:
        flagged = self.detected + self.false_positives
        return self.detected / flagged if flagged else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0


def score(labels: Labels, result: Replay, types: set[str] | None = None) -> Report:
    """Score alerts against labels. `types` limits which alert types count."""
    alerts = result.by_connection if labels.by_connection else result.by_pair
    if types is not None:
        alerts = {k: v & types for k, v in alerts.items() if v & types}
    seen = result.seen_connections if labels.by_connection else result.seen_pairs
    by_label: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    benign = fps = missing = 0
    fp_types: Counter[str] = Counter()
    for key, label in labels.keys.items():
        if key not in seen:
            missing += 1
            continue
        flagged = key in alerts
        if label == BENIGN:
            benign += 1
            if flagged:
                fps += 1
                fp_types.update(alerts[key])
        else:
            by_label[label][0] += 1
            by_label[label][1] += flagged
    unlabelled = sum(1 for key in alerts if key not in labels.keys)
    unit = "connections" if labels.by_connection else "host pairs"
    return Report(unit, {k: (v[0], v[1]) for k, v in by_label.items()}, benign, fps, fp_types, unlabelled, missing)


def score_minutes(result: Replay, types: set[str] | None = None) -> Report:
    """
    Score per host pair per minute: an attack minute counts as detected if
    any alert (of `types`) was raised between that pair in that minute.
    Needs replay(..., labels=...). Minutes with no labelled traffic aren't scored.
    """
    by_label: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    benign = fps = 0
    fp_types: Counter[str] = Counter()
    for minute, label in result.minute_label.items():
        alerts = result.minute_alerts.get(minute, set())
        if types is not None:
            alerts = alerts & types
        if label == BENIGN:
            benign += 1
            if alerts:
                fps += 1
                fp_types.update(alerts)
        else:
            by_label[label][0] += 1
            by_label[label][1] += bool(alerts)
    return Report("pair-minutes", {k: (v[0], v[1]) for k, v in by_label.items()}, benign, fps, fp_types, 0, 0)


def print_report(report: Report, packets: int, title: str | None = None) -> None:
    if title:
        print(f"\n── {title} " + "─" * max(0, 60 - len(title)))
    print(f"\nReplayed {packets:,} packets. Scored per {report.unit[:-1]}.\n")
    print(f"{'Attack':<28}{report.unit.capitalize():>14}{'Detected':>12}{'Recall':>9}")
    for label, (n, d) in sorted(report.by_label.items()):
        print(f"{label:<28}{n:>14,}{d:>12,}{d / n:>9.1%}")
    print(f"{'All attacks':<28}{report.attacks:>14,}{report.detected:>12,}{report.recall:>9.1%}")
    print(f"\nNormal {report.unit}: {report.benign:,}, wrongly flagged: {report.false_positives:,} "
          f"({report.false_positive_rate:.2%})")
    if report.fp_alert_types:
        print("False alarms by alert type: " + ", ".join(f"{t} {n:,}" for t, n in report.fp_alert_types.most_common()))
    print(f"Precision (flagged {report.unit} that were real attacks): {report.precision:.1%}")
    if report.unlabelled_alerts:
        print(f"Alerted {report.unit} with no label (not scored): {report.unlabelled_alerts:,}")
    if report.not_in_capture:
        print(f"Labelled {report.unit} not in the capture (not scored): {report.not_in_capture:,}")


# ── Self-test ───────────────────────────────────────────────────────────

VICTIM = "192.168.1.10"


def synthetic_capture() -> tuple[list, Labels]:
    """
    A small labelled capture: one of each attack plus normal traffic that
    has fooled earlier versions (fast downloads, merged download frames,
    FTP passive mode, server replies to many client ports, ordinary
    browsing). Labelled per host pair.
    """
    pkts: list = []
    keys: dict[Key, str] = {}

    def add(t, pkt):
        pkt.time = 1_000.0 + t
        pkts.append(pkt)

    # Normal browsing: 10 devices, a request/response every half second.
    for dev in range(20, 30):
        host, server = f"192.168.1.{dev}", f"192.0.2.{dev}"
        keys[pair_key(host, server)] = BENIGN
        for i in range(120):
            add(i * 0.5, IP(src=host, dst=server) / TCP(sport=50000 + dev, dport=443, flags="PA") / Raw(b"x" * 200))
            add(i * 0.5 + 0.02, IP(src=server, dst=host) / TCP(sport=443, dport=50000 + dev, flags="A") / Raw(b"x" * 900))

    # Fast download: 3000 full-size packets/s in, a stream of small ACKs out.
    dl_host, dl_server = "192.168.1.40", "192.0.2.40"
    keys[pair_key(dl_host, dl_server)] = BENIGN
    for i in range(6000):
        add(10 + i / 3000, IP(src=dl_server, dst=dl_host) / TCP(sport=443, dport=51000, flags="A") / Raw(b"x" * 1400))
        if i % 2 == 0:
            add(10 + i / 3000 + 0.0001, IP(src=dl_host, dst=dl_server) / TCP(sport=51000, dport=443, flags="A"))

    # A download as a capturing computer records it: merged 15 KB frames
    # (receive offload), which never existed on the wire.
    gro_host, gro_server = "192.168.1.42", "192.0.2.42"
    keys[pair_key(gro_host, gro_server)] = BENIGN
    for i in range(40):
        add(15 + i * 0.01, IP(src=gro_server, dst=gro_host) / TCP(sport=80, dport=50273, flags="A") / Raw(b"x" * 15000))

    # FTP in passive mode: a control connection, then a data connection on a
    # new high port for every file, each answered by the server.
    ftp_client, ftp_server = "192.168.1.43", "192.0.2.43"
    keys[pair_key(ftp_client, ftp_server)] = BENIGN
    add(22, IP(src=ftp_client, dst=ftp_server) / TCP(sport=40000, dport=21, flags="S"))
    add(22.01, IP(src=ftp_server, dst=ftp_client) / TCP(sport=21, dport=40000, flags="SA"))
    for i in range(30):
        port = 20000 + i * 137
        add(22.1 + i * 0.2, IP(src=ftp_client, dst=ftp_server) / TCP(sport=40001 + i, dport=port, flags="S"))
        add(22.11 + i * 0.2, IP(src=ftp_server, dst=ftp_client) / TCP(sport=port, dport=40001 + i, flags="SA"))

    # A busy website replying to 60 of the client's connections at once.
    web_host, web_server = "192.168.1.41", "192.0.2.41"
    keys[pair_key(web_host, web_server)] = BENIGN
    for i in range(60):
        add(20 + i * 0.02, IP(src=web_server, dst=web_host) / TCP(sport=443, dport=52000 + i, flags="PA") / Raw(b"x" * 1200))

    # SYN flood: 400 connection requests/s for 5s.
    keys[pair_key("203.0.113.66", VICTIM)] = "SYN flood"
    for i in range(2000):
        add(30 + i / 400, IP(src="203.0.113.66", dst=VICTIM) / TCP(sport=1024 + i % 60000, dport=80, flags="S"))

    # Port scan: SYNs to 100 ports.
    keys[pair_key("198.51.100.23", VICTIM)] = "Port scan"
    for port in range(1, 101):
        add(40 + port * 0.01, IP(src="198.51.100.23", dst=VICTIM) / TCP(sport=40000, dport=port, flags="S"))

    # UDP flood: 1500 small packets/s for 3s.
    keys[pair_key("198.51.100.77", VICTIM)] = "UDP flood"
    for i in range(4500):
        add(50 + i / 1500, IP(src="198.51.100.77", dst=VICTIM) / UDP(sport=5555, dport=53) / Raw(b"x" * 100))

    # One oversized UDP packet (a real jumbo, not merged TCP segments).
    keys[pair_key("203.0.113.140", VICTIM)] = "Oversized packet"
    add(60, IP(src="203.0.113.140", dst=VICTIM) / UDP(sport=1234, dport=9999) / Raw(b"x" * 15000))

    # Request flood (HTTP flood shape): 60 completed connections a second.
    flood_src = "198.51.100.44"
    keys[pair_key(flood_src, VICTIM)] = "Request flood"
    for i in range(600):
        t, sport = 70 + i / 60, 20000 + i
        add(t, IP(src=flood_src, dst=VICTIM) / TCP(sport=sport, dport=80, flags="S"))
        add(t + 0.001, IP(src=VICTIM, dst=flood_src) / TCP(sport=80, dport=sport, flags="SA"))
        add(t + 0.002, IP(src=flood_src, dst=VICTIM) / TCP(sport=sport, dport=80, flags="A"))

    # A busy DNS resolver: hundreds of lookups a second is normal, and it's UDP.
    resolver, upstream = "192.168.1.3", "192.0.2.53"
    keys[pair_key(resolver, upstream)] = BENIGN
    for i in range(1500):
        add(70 + i / 150, IP(src=resolver, dst=upstream) / UDP(sport=30000 + i, dport=53) / Raw(b"q" * 40))

    # Distributed flood: 80 internet hosts, each retrying once (as TCP does).
    for i in range(80):
        src = f"198.51.100.{150 + i}"
        keys[pair_key(src, VICTIM)] = "Distributed flood"
        for retry in (0, 3):
            add(90 + i * 0.02 + retry, IP(src=src, dst=VICTIM) / TCP(sport=41000 + i, dport=443, flags="S"))

    # An office file server used by 40 local devices: many sources, all local.
    office_server = "192.168.1.5"
    for i in range(40):
        client = f"192.168.1.{150 + i}"
        keys[pair_key(client, office_server)] = BENIGN
        add(100 + i * 0.05, IP(src=client, dst=office_server) / TCP(sport=45000 + i, dport=445, flags="S"))

    # Network sweep: a local device trying port 445 on 30 others, twice.
    sweeper = "192.168.1.66"
    for i in range(30):
        target = f"192.168.1.{200 + i}"
        keys[pair_key(sweeper, target)] = "Network sweep"
        for retry in (0, 3):
            add(110 + i * 0.05 + retry, IP(src=sweeper, dst=target) / TCP(sport=46000 + i, dport=445, flags="S"))

    # A resolver asking 60 internet DNS servers: many hosts, but not local.
    for i in range(60):
        server = f"192.0.2.{100 + i}"
        keys[pair_key(resolver, server)] = BENIGN
        add(120 + i * 0.05, IP(src=resolver, dst=server) / UDP(sport=33000 + i, dport=53) / Raw(b"q" * 40))

    pkts.sort(key=lambda p: p.time)
    return pkts, Labels(by_connection=False, keys=keys)


def self_test() -> Report:
    pkts, labels = synthetic_capture()
    result = replay(e for e in map(parse_packet, pkts) if e is not None)
    report = score(labels, result)
    print_report(report, result.packets)
    return report


def print_minutes(result: Replay) -> None:
    """Compact per pair-minute table: did each minute of an attack raise an alert?"""
    layers = [("Rules", RULE_TYPES), ("Model", {"ANOMALY"}), ("Both", None)]
    reports = [(name, score_minutes(result, types)) for name, types in layers]
    labels = sorted({label for _, r in reports for label in r.by_label})
    print("\n── Per host pair per minute (how the dashboard reports) " + "─" * 5)
    print(f"\n{'Attack minutes caught':<24}" + "".join(f"{name:>16}" for name, _ in reports))
    for label in labels:
        cells = []
        for _, r in reports:
            n, d = r.by_label.get(label, (0, 0))
            cells.append(f"{d:,}/{n:,}")
        print(f"{label:<24}" + "".join(f"{c:>16}" for c in cells))
    print(f"{'Normal minutes flagged':<24}" + "".join(f"{r.false_positive_rate:>16.2%}" for _, r in reports))


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SentinelAI detection on a labelled capture")
    parser.add_argument("pcap", nargs="?", help="packet capture (classic .pcap, Ethernet)")
    parser.add_argument("labels", nargs="*", help="one or more labels CSVs")
    parser.add_argument("--with-model", action="store_true", help="include the saved anomaly model")
    parser.add_argument(
        "--train-minutes", type=float, metavar="N",
        help="train a fresh anomaly model on the capture's first N minutes (which must be attack-free) "
             "and score only what comes after",
    )
    parser.add_argument("--max-packets", type=int, help="stop after this many packets")
    parser.add_argument("--self-test", action="store_true", help="run on a built-in synthetic capture")
    args = parser.parse_args()

    if args.self_test:
        report = self_test()
        sys.exit(0 if report.recall == 1.0 and report.false_positives == 0 else 1)
    if not (args.pcap and args.labels):
        parser.error("give a pcap and at least one labels CSV, or --self-test")

    labels = load_labels(args.labels)
    attacked = sum(v != BENIGN for v in labels.keys.values())
    unit = "connections" if labels.by_connection else "host pairs"
    print(f"Loaded labels for {len(labels.keys):,} {unit} ({attacked:,} attacks).", flush=True)
    started = time.time()
    model = cutoff = None
    if args.train_minutes:
        model, n_samples, cutoff = train_on_first(read_pcap(args.pcap), args.train_minutes)
        print(f"Trained the anomaly model on the first {args.train_minutes:g} minutes "
              f"({n_samples:,} samples) in {time.time() - started:,.0f}s. Scoring what follows.", flush=True)
    result = replay(read_pcap(args.pcap), with_model=args.with_model, model=model, score_after=cutoff,
                    labels=labels, max_packets=args.max_packets, progress=True)
    print(f"Replay took {time.time() - started:,.0f}s.")
    if result.first_ts is not None:
        span = time.strftime("%Y-%m-%d %H:%M", time.gmtime(result.first_ts)), time.strftime("%H:%M UTC", time.gmtime(result.last_ts))
        print(f"Capture covers {span[0]} to {span[1]}.")
    if model is not None or args.with_model:
        print_report(score(labels, result, RULE_TYPES), result.packets, "Rules only")
        print_report(score(labels, result, {"ANOMALY"}), result.packets, "Anomaly model only")
        print_report(score(labels, result), result.packets, "Rules and model together")
        print_minutes(result)
    else:
        print_report(score(labels, result), result.packets)


if __name__ == "__main__":
    main()
