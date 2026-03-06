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


def collect(duration):
    os.makedirs(DATA_DIR, exist_ok=True)

    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )

    tracker = FlowTracker()
    samples = []
    start = time.time()
    last_id = "$"

    log.info("collecting baseline traffic for %ds...", duration)

    while time.time() - start < duration:
        results = r.xread({"packet_stream": last_id}, count=100, block=1000)
        for _, entries in results:
            for msg_id, packet in entries:
                features = tracker.update(packet)
                samples.append([features[k] for k in FEATURE_KEYS])
                last_id = msg_id

    with open(TRAINING_FILE, "w") as f:
        json.dump({"feature_keys": FEATURE_KEYS, "samples": samples}, f)

    log.info("collected %d samples -> %s", len(samples), TRAINING_FILE)


def train():
    os.makedirs(SAVED_DIR, exist_ok=True)

    with open(TRAINING_FILE) as f:
        data = json.load(f)

    X = np.array(data["samples"])
    log.info("training on %d samples (%d features)", X.shape[0], X.shape[1])

    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
    )
    model.fit(X)
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
