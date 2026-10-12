"""
ML Feature Processing Module.
Extracts vector features from raw feature dictionaries for scikit-learn model input.
"""

import numpy as np
from typing import Dict, Any, List

FEATURE_COLUMNS = [
    "shannon_entropy",
    "domain_length",
    "subdomain_length",
    "label_count",
    "query_frequency",
    "unique_subdomain_rate",
    "TXT_request_rate",
    "NXDOMAIN_rate",
    "average_packet_size"
]

class MLFeatureProcessor:
    @staticmethod
    def feature_dict_to_vector(features: Dict[str, Any]) -> List[float]:
        """Converts a feature dictionary to an ordered numerical feature vector."""
        return [
            float(features.get("shannon_entropy", 0.0)),
            float(features.get("domain_length", 0)),
            float(features.get("subdomain_length", 0)),
            float(features.get("label_count", 0)),
            float(features.get("query_frequency", 0.0)),
            float(features.get("unique_subdomain_rate", 0.0)),
            float(features.get("TXT_request_rate", 0.0)),
            float(features.get("NXDOMAIN_rate", 0.0)),
            float(features.get("average_packet_size", 64.0))
        ]

    @classmethod
    def feature_dicts_to_matrix(cls, feature_list: List[Dict[str, Any]]) -> np.ndarray:
        """Converts a list of feature dictionaries to a 2D numpy matrix."""
        vectors = [cls.feature_dict_to_vector(f) for f in feature_list]
        return np.array(vectors, dtype=np.float64)
