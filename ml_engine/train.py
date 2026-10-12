"""
Isolation Forest ML Training Pipeline.
Trains anomaly detection model on benign DNS telemetry and saves model artifacts.
"""

import os
import json
import time
import logging
import joblib
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from ml_engine.features import MLFeatureProcessor, FEATURE_COLUMNS
from dns_simulator.synthetic_data import BENIGN_DOMAINS, BENIGN_SUBDOMAINS

logger = logging.getLogger("DNSShield.MLTrain")

DEFAULT_MODEL_DIR = os.path.join("ml_engine", "models")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "isolation_forest.joblib")
DEFAULT_META_PATH = os.path.join(DEFAULT_MODEL_DIR, "model_metadata.json")

def generate_benign_training_samples(count: int = 1000) -> List[Dict[str, Any]]:
    """Generates synthetic benign DNS feature samples for initial model baseline training."""
    from packet_monitor.feature_extractor import FeatureExtractor
    import random

    samples = []
    for _ in range(count):
        d = random.choice(BENIGN_DOMAINS)
        sub = random.choice(BENIGN_SUBDOMAINS) if random.random() > 0.4 else ""
        qname = f"{sub}.{d}" if sub else d
        labels = qname.split(".")
        
        parsed = {
            "qname": qname,
            "subdomain": sub,
            "labels": labels,
            "qtype": "A" if random.random() > 0.1 else "TXT",
            "packet_size": random.randint(54, 120),
            "rcode": 0
        }
        hist = {
            "query_frequency": round(random.uniform(0.1, 2.0), 2),
            "unique_subdomain_rate": round(random.uniform(0.05, 0.3), 2),
            "txt_request_rate": 0.1 if parsed["qtype"] == "TXT" else 0.0,
            "nxdomain_rate": 0.0,
            "average_packet_size": float(parsed["packet_size"])
        }
        feat = FeatureExtractor.extract_features(parsed, historical_stats=hist)
        samples.append(feat)
    return samples

def train_model(
    training_data: Optional[List[Dict[str, Any]]] = None,
    contamination: float = 0.05,
    model_path: str = DEFAULT_MODEL_PATH,
    meta_path: str = DEFAULT_META_PATH
) -> Dict[str, Any]:
    """Trains IsolationForest model and persists artifact & metadata."""
    if not training_data:
        logger.info("No custom training data provided. Generating synthetic benign baseline dataset...")
        training_data = generate_benign_training_samples(count=1200)

    X = MLFeatureProcessor.feature_dicts_to_matrix(training_data)
    
    logger.info(f"Training IsolationForest on {X.shape[0]} samples with {X.shape[1]} features...")
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)

    metadata = {
        "model_type": "IsolationForest",
        "n_estimators": 100,
        "contamination": contamination,
        "sample_count": X.shape[0],
        "feature_columns": FEATURE_COLUMNS,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model_path": model_path,
        "status": "LOADED"
    }

    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Model saved to '{model_path}'. Metadata saved to '{meta_path}'.")
    return metadata

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_model()
