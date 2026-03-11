"""
QScan — Anomaly Detection

Detects unusual or suspicious cryptographic configurations
that may indicate misconfiguration or compromise.

Uses Isolation Forest to flag outlier TLS/crypto setups
that both rule-based and ML scoring might miss.
"""

import os
import joblib
import numpy as np
from typing import Dict, List, Optional

from ai_ml.feature_engineering import FeatureExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


class CryptoAnomalyDetector:
    """Detects anomalous cryptographic configurations using Isolation Forest."""

    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path or os.path.join(DEFAULT_MODEL_DIR, "anomaly_model.joblib")
        self.is_fitted = False
        self.feature_extractor = FeatureExtractor()

        # Try to load a pre-fitted model
        if os.path.exists(self.model_path):
            self.load_model(self.model_path)
        else:
            logger.info("CryptoAnomalyDetector initialized (not yet fitted)")

    def fit(self, scan_results: list, contamination: float = 0.1):
        """
        Fit the Isolation Forest on a set of crypto configurations.

        Args:
            scan_results: List of classified scan result dicts
            contamination: Expected fraction of anomalies in training data
        """
        from sklearn.ensemble import IsolationForest

        feature_dicts = self.feature_extractor.extract_batch(scan_results)
        X = self.feature_extractor.to_numpy(feature_dicts)

        if X.shape[0] < 10:
            logger.warning(f"Too few samples ({X.shape[0]}) to fit anomaly detector, need at least 10")
            return

        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            max_features=1.0,
            random_state=42,
            n_jobs=-1,
        )

        self.model.fit(X)
        self.is_fitted = True
        logger.info(f"Anomaly detector fitted on {X.shape[0]} samples (contamination={contamination})")

    def detect(self, scan_result: dict) -> dict:
        """
        Check if a crypto configuration is anomalous.

        Returns:
            dict with keys:
                - is_anomaly (bool): True if the config is flagged
                - anomaly_score (float): Raw anomaly score (lower = more anomalous)
                - confidence (str): LOW / MEDIUM / HIGH
                - reasons (list): Human-readable reasons (heuristic)
        """
        result = {
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "confidence": "LOW",
            "reasons": [],
        }

        # ── ML-based detection ──
        if self.is_fitted and self.model is not None:
            features = self.feature_extractor.extract(scan_result)
            X = self.feature_extractor.to_numpy([features])
            raw_score = float(self.model.decision_function(X)[0])
            prediction = int(self.model.predict(X)[0])

            result["anomaly_score"] = round(raw_score, 4)
            result["is_anomaly"] = prediction == -1

            if prediction == -1:
                if raw_score < -0.3:
                    result["confidence"] = "HIGH"
                elif raw_score < -0.1:
                    result["confidence"] = "MEDIUM"
                else:
                    result["confidence"] = "LOW"

        # ── Heuristic checks (always run) ──
        heuristic_flags = self._heuristic_checks(scan_result)
        result["reasons"].extend(heuristic_flags)

        # If heuristics find issues but ML didn't flag it, still mark as anomaly
        if heuristic_flags and not result["is_anomaly"]:
            result["is_anomaly"] = True
            result["confidence"] = "MEDIUM"

        return result

    def detect_batch(self, scan_results: list) -> list:
        """Detect anomalies in multiple scan results."""
        return [self.detect(r) for r in scan_results]

    def _heuristic_checks(self, scan_result: dict) -> list:
        """
        Rule-based heuristic checks for obviously suspicious configurations.
        These catch things that statistical models might miss due to limited training data.
        """
        flags = []
        ca = scan_result.get("cipher_analysis", {})
        tls_version = scan_result.get("tls_version", "")

        # 1. NULL or extremely weak encryption
        enc = ca.get("encryption") or {}
        enc_alg = enc.get("algorithm", "")
        if enc_alg in ("NULL", "DES", "RC4"):
            flags.append(f"Dangerously weak encryption: {enc_alg}")

        # 2. TLS 1.3 cipher with non-ephemeral key exchange (impossible in valid config)
        kex = ca.get("key_exchange") or {}
        if tls_version == "TLSv1.3" and kex.get("algorithm") == "RSA":
            flags.append("Invalid config: TLS 1.3 with RSA key exchange (should be ephemeral only)")

        # 3. Very old protocols still supported alongside new ones
        supported = scan_result.get("supported_protocols", [])
        has_modern = any(p in ("TLSv1.2", "TLSv1.3") for p in supported)
        has_ancient = any(p in ("SSLv2", "SSLv3") for p in supported)
        if has_modern and has_ancient:
            flags.append("Suspicious: supports both modern TLS and deprecated SSL protocols simultaneously")

        # 4. Extremely small key sizes
        for cert in scan_result.get("chain_analysis", []):
            key_bits = cert.get("key_bits", 0) or 0
            key_type = cert.get("key_type", "").upper()
            if key_type == "RSA" and 0 < key_bits < 1024:
                flags.append(f"Critically weak RSA key: {key_bits} bits")
            elif key_type in ("EC", "ECDSA", "ECC") and 0 < key_bits < 224:
                flags.append(f"Critically weak ECC key: {key_bits} bits")

        # 5. Missing forward secrecy with sensitive protocols
        if not ca.get("forward_secrecy", False) and tls_version in ("TLSv1.2", "TLSv1.3"):
            flags.append("No forward secrecy on modern TLS — increased HNDL risk")

        return flags

    def save_model(self, path: str = None):
        """Save fitted model to disk."""
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump({"model": self.model}, save_path)
        logger.info(f"Anomaly model saved to {save_path}")

    def load_model(self, path: str = None):
        """Load a pre-fitted model from disk."""
        load_path = path or self.model_path
        if not os.path.exists(load_path):
            logger.warning(f"Anomaly model not found: {load_path}")
            return
        try:
            payload = joblib.load(load_path)
            self.model = payload["model"]
            self.is_fitted = True
            logger.info(f"Loaded anomaly model from {load_path}")
        except Exception as e:
            logger.error(f"Failed to load anomaly model: {e}")
            self.is_fitted = False
