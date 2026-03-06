"""Train the Isolation Forest anomaly detection model.

Usage:
    # Collect normal traffic first, then train:
    python train_model.py --collect 3600    # collect features for 1 hour
    python train_model.py --train           # train on collected data
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

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRAIN] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SAVED_DIR = os.path.join(os.path.dirname(__file__), "saved")
TRAINING_DATA_FILE = os.path.join(DATA_DIR, "normal_traffic.json")
MODEL_FILE = os.path.join(SAVED_DIR, "anomaly_model.pkl")


def collect_features(duration_seconds):
    """Collect feature vectors from live traffic for training."""
    os.makedirs(DATA_DIR, exist_ok=True)

    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )

    tracker = FlowTracker()
    samples = []
    start = time.time()

    logger.info("Collecting training data for %d seconds...", duration_seconds)

    last_id = "$"
    while time.time() - start < duration_seconds:
        results = r.xread({"packet_stream": last_id}, count=100, block=1000)
        for stream, entries in results:
            for msg_id, packet in entries:
                features = tracker.update(packet)
                vector = [features[k] for k in FEATURE_KEYS]
                samples.append(vector)
                last_id = msg_id

    with open(TRAINING_DATA_FILE, "w") as f:
        json.dump({"feature_keys": FEATURE_KEYS, "samples": samples}, f)

    logger.info("Collected %d samples. Saved to %s", len(samples), TRAINING_DATA_FILE)


def train():
    """Train Isolation Forest on collected normal traffic."""
    os.makedirs(SAVED_DIR, exist_ok=True)

    with open(TRAINING_DATA_FILE) as f:
        data = json.load(f)

    samples = np.array(data["samples"])
    logger.info("Training on %d samples with %d features", samples.shape[0], samples.shape[1])

    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
    )
    model.fit(samples)

    joblib.dump(model, MODEL_FILE)
    logger.info("Model saved to %s", MODEL_FILE)

    scores = model.score_samples(samples)
    logger.info("Score stats - mean: %.4f, std: %.4f, min: %.4f", scores.mean(), scores.std(), scores.min())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--collect", type=int, help="Collect normal traffic for N seconds")
    parser.add_argument("--train", action="store_true", help="Train model on collected data")
    args = parser.parse_args()

    if args.collect:
        collect_features(args.collect)
    elif args.train:
        train()
    else:
        parser.print_help()
