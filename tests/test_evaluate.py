"""Tests for scripts/evaluate.py: detection quality, label loading and pcap reading."""

import sys
import os

import pytest
from scapy.all import ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, wrpcap
from scapy.utils import PcapNgWriter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import evaluate
from capture_service.capture import parse_packet


def test_self_test_catches_every_attack_without_false_alarms():
    """
    Replays one of each attack plus normal traffic that fooled earlier
    versions (fast downloads, server replies to many ports) through the
    real parse -> flow -> detect pipeline.
    """
    pkts, labels = evaluate.synthetic_capture()
    result = evaluate.replay(e for e in map(parse_packet, pkts) if e is not None)
    report = evaluate.score(labels, result)
    assert report.recall == 1.0, report.by_label
    assert report.false_positives == 0, report.fp_alert_types


CIC_HEADER = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Label\n"


def test_load_labels_reads_cic_ids2017_connections(tmp_path):
    """CIC-IDS2017 headers have leading spaces; rows are per connection."""
    path = tmp_path / "labels.csv"
    path.write_text(
        CIC_HEADER
        + "x,10.0.0.1,5000,10.0.0.2,80,6,BENIGN\n"
        + "x,172.16.0.1,40000,192.168.10.50,22,6,PortScan\n"
        + "x,172.16.0.1,40001,192.168.10.50,80,6,DDoS\n"
    )
    labels = evaluate.load_labels([str(path)])
    assert labels.by_connection
    assert labels.keys[evaluate.conn_key("6", "10.0.0.1", "5000", "10.0.0.2", "80")] == "BENIGN"
    # Same hosts, different connections, different attacks: kept apart.
    assert labels.keys[evaluate.conn_key("6", "192.168.10.50", "22", "172.16.0.1", "40000")] == "PortScan"
    assert labels.keys[evaluate.conn_key("6", "172.16.0.1", "40001", "192.168.10.50", "80")] == "DDoS"


def test_load_labels_attack_wins_over_benign(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(CIC_HEADER + "x,1.1.1.1,1,2.2.2.2,2,6,BENIGN\nx,2.2.2.2,2,1.1.1.1,1,6,Bot\n")
    labels = evaluate.load_labels([str(path)])
    assert labels.keys[evaluate.conn_key("6", "1.1.1.1", "1", "2.2.2.2", "2")] == "Bot"


def test_load_labels_without_ports_scores_pairs(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text("src_ip,dst_ip,label\n1.1.1.1,2.2.2.2,BENIGN\n")
    labels = evaluate.load_labels([str(path)])
    assert not labels.by_connection
    assert labels.keys == {evaluate.pair_key("1.1.1.1", "2.2.2.2"): "BENIGN"}


def test_load_labels_refuses_mixed_files(tmp_path):
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    a.write_text(CIC_HEADER + "x,1.1.1.1,1,2.2.2.2,2,6,BENIGN\n")
    b.write_text("src_ip,dst_ip,label\n1.1.1.1,2.2.2.2,BENIGN\n")
    with pytest.raises(SystemExit):
        evaluate.load_labels([str(a), str(b)])


# Fixed MACs so scapy doesn't try to resolve addresses on the real network.
def Eth():
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def test_fast_pcap_reader_matches_capture_parser(tmp_path):
    """read_pcap must produce the same fields as the live capture code."""
    frames = [
        Eth() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags="S"),
        Eth() / IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=80, dport=1234, flags="SA"),
        Eth() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags="PA") / Raw(b"x" * 500),
        Eth() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags="FA"),
        Eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53) / Raw(b"q" * 40),
        Eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Eth() / Dot1Q(vlan=10) / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=1, dport=2, flags="A"),
        Eth() / ARP(),
    ]
    for i, f in enumerate(frames):
        f.time = 1_000_000.0 + i * 0.25
    path = tmp_path / "t.pcap"
    wrpcap(str(path), frames)

    ng = tmp_path / "t.pcapng"
    with PcapNgWriter(str(ng)) as w:
        for f in frames:
            w.write(f)

    slow = [e for e in map(parse_packet, frames) if e is not None]
    assert len(slow) == 7  # ARP has no IP layer and is skipped
    for path in (path, ng):
        fast = list(evaluate.read_pcap(str(path)))
        assert len(fast) == len(slow), path
        for a, b in zip(fast, slow):
            a, b = dict(a), dict(b)
            assert float(a.pop("timestamp")) == pytest.approx(float(b.pop("timestamp"))), path
            assert a == b, path


def test_reader_stops_cleanly_on_truncated_capture(tmp_path):
    """A capture still downloading ends mid-packet; read what's complete."""
    frames = [Eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags="S") for _ in range(5)]
    for i, f in enumerate(frames):
        f.time = 1000.0 + i
    for name, write in (("t.pcap", lambda p: wrpcap(p, frames)), ("t.pcapng", None)):
        path = tmp_path / name
        if write:
            write(str(path))
        else:
            with PcapNgWriter(str(path)) as w:
                for f in frames:
                    w.write(f)
        data = path.read_bytes()
        path.write_bytes(data[:-10])  # cut the last packet short
        assert len(list(evaluate.read_pcap(str(path)))) == 4, name


def test_unseen_labels_are_not_counted_as_misses():
    labels = evaluate.Labels(False, {
        evaluate.pair_key("1.1.1.1", "2.2.2.2"): "PortScan",
        evaluate.pair_key("3.3.3.3", "4.4.4.4"): "DDoS",  # not in the capture
    })
    result = evaluate.Replay()
    result.seen_pairs.add(evaluate.pair_key("1.1.1.1", "2.2.2.2"))
    result.by_pair[evaluate.pair_key("1.1.1.1", "2.2.2.2")].add("PORT_SCAN")
    report = evaluate.score(labels, result)
    assert report.by_label == {"PortScan": (1, 1)}
    assert report.not_in_capture == 1


def test_train_on_first_minutes_then_score_the_rest():
    """The model trains on the attack-free start and only later traffic is scored."""
    pkts, labels = evaluate.synthetic_capture()
    entries = [e for e in map(parse_packet, pkts) if e is not None]
    # Attacks start 30s in; train on the first 25s of normal traffic.
    model, n_samples, cutoff = evaluate.train_on_first(iter(entries), minutes=25 / 60)
    assert n_samples > 0 and cutoff == float(entries[0]["timestamp"]) + 25
    result = evaluate.replay(entries, model=model, score_after=cutoff)
    assert result.first_ts >= cutoff

    rules_only = evaluate.score(labels, result, evaluate.RULE_TYPES)
    assert rules_only.recall == 1.0  # every attack is after the cutoff
    model_only = evaluate.score(labels, result, {"ANOMALY"})
    combined = evaluate.score(labels, result)
    assert combined.detected >= max(rules_only.detected, model_only.detected)


def test_score_can_limit_alert_types():
    labels = evaluate.Labels(False, {evaluate.pair_key("1.1.1.1", "2.2.2.2"): "PortScan"})
    result = evaluate.Replay()
    key = evaluate.pair_key("1.1.1.1", "2.2.2.2")
    result.seen_pairs.add(key)
    result.by_pair[key].update({"PORT_SCAN"})
    assert evaluate.score(labels, result, {"PORT_SCAN"}).detected == 1
    assert evaluate.score(labels, result, {"ANOMALY"}).detected == 0


def test_cic_timestamps_are_afternoon_below_8_and_utc_minus_3():
    # 5 July 2017, 3:30 on CIC's 12-hour clock is 15:30 local, 18:30 UTC.
    assert evaluate.parse_cic_time("5/7/2017 3:30", -3) == evaluate.calendar.timegm((2017, 7, 5, 18, 30, 0))
    assert evaluate.parse_cic_time("5/7/2017 9:05", -3) == evaluate.calendar.timegm((2017, 7, 5, 12, 5, 0))


TIMED_HEADER = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Label\n"


def test_reused_connection_keys_are_scored_by_time(tmp_path):
    """
    Flood tools reuse source ports, so one connection key can carry two
    attacks hours apart. An alert during the first must not count for the second.
    """
    path = tmp_path / "labels.csv"
    path.write_text(
        TIMED_HEADER
        + "x,172.16.0.1,40000,192.168.10.50,80,6,5/7/2017 9:50,1000000,Slowloris\n"
        + "x,172.16.0.1,40000,192.168.10.50,80,6,5/7/2017 10:30,1000000,Hulk\n"
    )
    labels = evaluate.load_labels([str(path)])
    key = evaluate.conn_key("6", "172.16.0.1", "40000", "192.168.10.50", "80")
    assert labels.flows is not None and len(labels.flows[key]) == 2
    slowloris = int(evaluate.parse_cic_time("5/7/2017 9:50", -3) // 60)
    hulk = int(evaluate.parse_cic_time("5/7/2017 10:30", -3) // 60)
    assert evaluate.label_at(labels, key, hulk * 60 + 10) == "Hulk"

    result = evaluate.Replay()
    result.conn_seen_minutes[key].update({slowloris, hulk})
    result.conn_alert_minutes[key][hulk].add("REQUEST_FLOOD")
    report = evaluate.score(labels, result)
    assert report.unit == "flows"
    assert report.by_label == {"Hulk": (1, 1), "Slowloris": (1, 0)}


def test_timed_labels_not_in_capture_are_not_misses(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(TIMED_HEADER + "x,1.1.1.1,1,2.2.2.2,2,6,5/7/2017 9:50,5,DDoS\n")
    report = evaluate.score(evaluate.load_labels([str(path)]), evaluate.Replay())
    assert report.by_label == {} and report.not_in_capture == 1


def test_excluded_pairs_drop_only_normal_labels(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(
        TIMED_HEADER
        + "x,172.16.0.1,40000,192.168.10.50,80,6,5/7/2017 9:50,5,DDoS\n"
        + "x,172.16.0.1,40001,192.168.10.50,80,6,5/7/2017 9:50,5,BENIGN\n"
        + "x,192.168.10.3,53,192.168.10.9,5000,17,5/7/2017 9:50,5,BENIGN\n"
    )
    labels = evaluate.load_labels([str(path)])
    assert evaluate.drop_normal_labels(labels, {evaluate.pair_key("192.168.10.50", "172.16.0.1")}) == 2
    assert set(labels.keys.values()) == {"DDoS", "BENIGN"}
    assert sorted(f[2] for flows in labels.flows.values() for f in flows) == ["BENIGN", "DDoS"]
