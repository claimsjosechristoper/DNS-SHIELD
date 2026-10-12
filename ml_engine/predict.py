"""
ML Inference Module.
Loads persisted Isolation Forest model and computes anomaly prediction scores.
"""

import os
import json
import logging
import joblib
import numpy as np
from typing import Dict, Any, Tuple, Optional
from ml_engine.features import MLFeatureProcessor
from ml_engine.train import DEFAULT_MODEL_PATH, DEFAULT_META_PATH, train_model

logger = logging.getLogger("DNSShield.MLPredict")

class MLAnomalyDetector:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, meta_path: str = DEFAULT_META_PATH):
        self.model_path = model_path
        self.meta_path = meta_path
        self.model = None
        self.metadata = {}
        self.load_model()

    def load_model(self):
        """Loads model from disk, training a default baseline if absent."""
        if not os.path.exists(self.model_path):
            logger.info("Model file not found. Auto-training baseline model...")
            train_model(model_path=self.model_path, meta_path=self.meta_path)

        try:
            self.model = joblib.load(self.model_path)
            if os.path.exists(self.meta_path):
                with open(self.meta_path, "r") as f:
                    self.metadata = json.load(f)
            self.metadata["status"] = "LOADED"
            logger.info("Isolation Forest model successfully loaded.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None
            self.metadata = {"status": "ERROR", "error": str(e)}

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predicts whether feature vector is anomalous.
        Returns prediction: -1 (anomalous) or 1 (normal), and anomaly score (0.0 to 1.0).
        """
        if self.model is None:
            self.load_model()
            if self.model is None:
                return {
                    "is_anomalous": False,
                    "anomaly_score": 0.0,
                    "prediction": 1,
                    "model_status": "UNAVAILABLE"
                }

        X = MLFeatureProcessor.feature_dict_to_vector(features)
        X_mat = np.array([X], dtype=np.float64)

        # IsolationForest predict returns -1 for outlier/anomaly, 1 for inlier
        pred = int(self.model.predict(X_mat)[0])
        # Decision function returns negative values for anomalies, positive for normal
        raw_score = float(self.model.decision_function(X_mat)[0])

        # Normalize score into a 0.0 (normal) to 1.0 (anomalous) anomaly index
        # Typical raw scores range from -0.3 (highly anomalous) to +0.3 (normal)
        anomaly_score = max(0.0, min(1.0, (0.2 - raw_score) / 0.5))
        is_anomalous = (pred == -1) or (anomaly_score > 0.6)

        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": round(anomaly_score, 4),
            "raw_decision_score": round(raw_score, 4),
            "prediction": pred,
            "prediction_label": "ANOMALOUS" if is_anomalous else "NORMAL",
            "model_status": self.metadata.get("status", "LOADED")
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns model status and metadata."""
        return {
            "status": self.metadata.get("status", "NOT_LOADED"),
            "model_path": self.model_path,
            "sample_count": self.metadata.get("sample_count", 0),
            "trained_at": self.metadata.get("trained_at", "N/A"),
            "feature_columns": self.metadata.get("feature_columns", [])
        }
