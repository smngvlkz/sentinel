"""Tests for how ml-models/train_model.py turns traffic into training samples."""

import importlib.util
import os
import sys

_spec = importlib.util.spec_from_file_location(
    "train_model", os.path.join(os.path.dirname(__file__), "..", "ml-models", "train_model.py")
)
train_model = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = train_model
_spec.loader.exec_module(train_model)


def pkt(t, src, dst, size=1400, flags="A"):
    return {"timestamp": str(t), "src_ip": src, "dst_ip": dst, "protocol": "6", "packet_size": str(size),
            "src_port": "443", "dst_port": "50000", "flags": flags, "transport": "TCP"}


def test_busy_connection_does_not_dominate_the_baseline():
    """A 60s download at 3000 packets/s next to browsing at 2 packets/s."""
    sampler = train_model.BaselineSampler(interval=5.0)
    counts = {"download": 0, "browsing": 0}
    for i in range(60 * 3000):
        t = 1000.0 + i / 3000
        if sampler.add(pkt(t, "203.0.113.5", "192.168.1.20")):
            counts["download"] += 1
        if i % 1500 == 0 and sampler.add(pkt(t, "198.51.100.9", "192.168.1.21", size=600)):
            counts["browsing"] += 1
    # Roughly one sample per flow every 5s, whatever the packet rate.
    assert 10 <= counts["download"] <= 13
    assert 9 <= counts["browsing"] <= 13


def test_young_flows_are_not_sampled():
    """Flows need the same history the analyzer requires before scoring."""
    sampler = train_model.BaselineSampler()
    assert all(sampler.add(pkt(1000.0 + i * 0.001, "10.0.0.1", "10.0.0.2")) is None for i in range(9))


def test_samples_use_the_model_feature_order():
    sampler = train_model.BaselineSampler(interval=1.0)
    samples = [s for i in range(50) if (s := sampler.add(pkt(1000.0 + i * 0.1, "10.0.0.1", "10.0.0.2")))]
    assert samples and all(len(s) == len(train_model.FEATURE_KEYS) for s in samples)
