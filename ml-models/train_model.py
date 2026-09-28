"""
Train the anomaly detection model.

Step 1: Capture normal baseline traffic.
Step 2: Train an Isolation Forest on the collected features.

Usage:
    python train_model.py --collect 3600   # collect 1 hour of normal traffic
    python train_model.py --train          # train the model
"""

import os
import sys
import time
import json
import argparse
import logging

import numpy as np
import joblib
import redis
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.anomaly_model import FEATURE_KEYS
from detection_engine.config import has_rate_evidence, load_config

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [train] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SAVED_DIR = os.path.join(os.path.dirname(__file__), "saved")
TRAINING_FILE = os.path.join(DATA_DIR, "normal_traffic.json")
MODEL_FILE = os.path.join(SAVED_DIR, "anomaly_model.pkl")

# Recordings take one sample per connection this often (in packet time).
SAMPLE_INTERVAL = 5.0
SAMPLING = f"per_flow_{SAMPLE_INTERVAL:g}s"
# Mirrors the analyzer: forget flows idle this long, checked every minute.
CLEANUP_INTERVAL = 60.0


class BaselineSampler:
    """
    Turns a packet stream into training samples: at most one per flow every
    SAMPLE_INTERVAL seconds, and only once the flow has enough history for
    its rates to mean anything (the same subset the analyzer scores).

    Sampling every packet let a single busy connection, like a large
    download, make up nearly all of the baseline, so the model learned that
    one download as "normal" and little else.
    """

    def __init__(self, interval: float = SAMPLE_INTERVAL) -> None:
        self.interval = interval
        self.config = load_config()
        self.tracker = FlowTracker()
        self.last_sampled: dict[tuple[str, str], float] = {}
        self.last_cleanup: float | None = None
        self.packets = 0

    def add(self, packet: dict[str, str]) -> list[float] | None:
        self.packets += 1
        now = float(packet["timestamp"])
        if self.last_cleanup is None:
            self.last_cleanup = now
        elif now - self.last_cleanup > CLEANUP_INTERVAL:
            self.tracker.cleanup_stale(now)
            self.last_sampled = {k: t for k, t in self.last_sampled.items() if k in self.tracker.flows}
            self.last_cleanup = now

        features = self.tracker.update(packet)
        if not has_rate_evidence(features, self.config):
            return None
        key = (packet["src_ip"], packet["dst_ip"])
        last = self.last_sampled.get(key)
        if last is not None and now - last < self.interval:
            return None
        self.last_sampled[key] = now
        return [features[k] for k in FEATURE_KEYS]


def fit_model(samples):
    """The anomaly model, fitted on baseline samples. Shared with scripts/evaluate.py."""
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=200,
        # Share of baseline traffic treated as outliers. The analyzer scores
        # many packets per flow, so even a few percent here floods the
        # dashboard with alerts on normal traffic; 0.5% keeps only rare flows.
        contamination=0.005,
        max_samples="auto",
        random_state=42,
    )
    return model.fit(np.asarray(samples))


def collect(duration):
    os.makedirs(DATA_DIR, exist_ok=True)

    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )

    sampler = BaselineSampler()
    samples = []
    start = time.time()
    last_id = "$"

    log.info("collecting baseline traffic for %ds (Ctrl+C to stop early and keep what's collected)...", duration)

    try:
        while time.time() - start < duration:
            results = r.xread({"packet_stream": last_id}, count=100, block=1000)
            for _, entries in results:
                for msg_id, packet in entries:
                    sample = sampler.add(packet)
                    if sample is not None:
                        samples.append(sample)
                    last_id = msg_id
    except KeyboardInterrupt:
        log.info("stopped early after %ds", time.time() - start)

    if not samples:
        log.warning("no usable traffic collected; is capture running? Keeping the previous %s", TRAINING_FILE)
        return

    with open(TRAINING_FILE, "w") as f:
        json.dump({"feature_keys": FEATURE_KEYS, "sampling": SAMPLING, "samples": samples}, f)

    log.info("collected %d samples from %d packets -> %s", len(samples), sampler.packets, TRAINING_FILE)


def train():
    os.makedirs(SAVED_DIR, exist_ok=True)

    with open(TRAINING_FILE) as f:
        data = json.load(f)

    # Train only on flows the analyzer will actually score: ones with enough
    # history for their rates to be meaningful. Recordings made before this
    # filter existed contain every packet, so filter here rather than at
    # collection time.
    if data.get("sampling") != SAMPLING:
        log.warning(
            "this recording samples every packet, so busy connections dominate it; "
            "re-record with make train-collect for a balanced baseline"
        )
    config = load_config()
    keys = data["feature_keys"]
    samples = [s for s in data["samples"] if has_rate_evidence(dict(zip(keys, s)), config)]
    log.info("using %d of %d recorded samples (flows with enough history)", len(samples), len(data["samples"]))
    if len(samples) < 1000:
        log.warning("only %d usable samples; record for longer for a reliable model", len(samples))
    if not samples:
        return

    X = np.array(samples)
    log.info("training on %d samples (%d features)", X.shape[0], X.shape[1])

    model = fit_model(X)
    joblib.dump(model, MODEL_FILE)

    scores = model.score_samples(X)
    log.info("saved -> %s", MODEL_FILE)
    log.info("scores: mean=%.4f std=%.4f min=%.4f", scores.mean(), scores.std(), scores.min())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SentinelAI anomaly model")
    parser.add_argument("--collect", type=int, metavar="SECONDS", help="collect baseline traffic")
    parser.add_argument("--train", action="store_true", help="train model on collected data")
    args = parser.parse_args()

    if args.collect:
        collect(args.collect)
    elif args.train:
        train()
    else:
        parser.print_help()
