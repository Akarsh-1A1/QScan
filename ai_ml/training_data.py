"""
QScan — Training Data Generator

Generates labeled training data from scan results for ML model training.
Uses realistic cipher suite ecosystems, sampling from known safe, legacy,
and weak cipher strings, rather than generating random independent components.
"""

import random
import csv
import json
import os
import numpy as np
from typing import List, Dict, Optional

from ai_ml.feature_engineering import FeatureExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

# ─── Realistic Cipher Suite Ecosystems ────────────────────

SAFE_CIPHERS = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
]

LEGACY_CIPHERS = [
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
]

WEAK_CIPHERS = [
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_NULL_WITH_NULL_NULL",
]

# ─── Certificate Properties ───────────────────────────────

SIG_ALGS = [
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "sha1WithRSAEncryption",
    "md5WithRSAEncryption",
]

DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


class TrainingDataGenerator:
    """Generates and manages training datasets."""

    def __init__(self):
        self.dataset: List[Dict] = []
        self.labels: List[float] = []
        self.feature_extractor = FeatureExtractor()
        logger.info("TrainingDataGenerator initialized (Realistic Ecosystem Mode)")

    def from_scan_results(self, scan_results: list, labels: list = None):
        """Build training data from real scan results."""
        features = self.feature_extractor.extract_batch(scan_results)
        if labels is None:
            labels = [r.get("quantum_risk_score", 50.0) for r in scan_results]
        self.dataset.extend(features)
        self.labels.extend(labels)
        logger.info(f"Added {len(features)} real samples (total: {len(self.dataset)})")

    def generate_synthetic(self, num_samples: int = 1500):
        """Generate synthetic crypto configs using realistic distributions."""
        from crypto.pqc_classifier import PQCClassifier
        from crypto.cipher_parser import CipherParser

        classifier = PQCClassifier()
        cipher_parser = CipherParser()
        generated = 0

        for _ in range(num_samples):
            # 1. Choose a cipher category
            category = random.choices(
                ["safe", "legacy", "weak"],
                weights=[0.70, 0.20, 0.10], k=1
            )[0]

            if category == "safe":
                cipher_str = random.choice(SAFE_CIPHERS)
            elif category == "legacy":
                cipher_str = random.choice(LEGACY_CIPHERS)
            else:
                cipher_str = random.choice(WEAK_CIPHERS)

            # 2. Assign a matching TLS version
            if not cipher_str.startswith("TLS_AES") and not cipher_str.startswith("TLS_CHACHA20"):
                tls_version = random.choices(
                    ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"],
                    weights=[0.85, 0.05, 0.05, 0.03, 0.02], k=1
                )[0]
            else:
                tls_version = "TLSv1.3"

            # Older protocols shouldn't have modern ciphers
            if tls_version in ("SSLv2", "SSLv3") and category == "safe":
                tls_version = "TLSv1.2"

            # 3. Simulate multiple protocol support (e.g. server hasn't disabled old TLS)
            supported = [tls_version]
            if random.random() < 0.20:
                supported.extend(random.sample(DEPRECATED_PROTOCOLS, k=random.randint(1, 2)))
            
            # 4. Generate realistic certificates
            if "ECDSA" in cipher_str:
                cert_key_type = "EC"
                cert_key_bits = random.choices([256, 384, 521], weights=[0.80, 0.15, 0.05], k=1)[0]
                sig_alg = random.choices(["ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA1"], weights=[0.85, 0.10, 0.05], k=1)[0]
            else:
                cert_key_type = "RSA"
                cert_key_bits = random.choices([1024, 2048, 3072, 4096], weights=[0.05, 0.75, 0.10, 0.10], k=1)[0]
                sig_alg = random.choices(
                    ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha1WithRSAEncryption", "md5WithRSAEncryption"],
                    weights=[0.75, 0.15, 0.08, 0.02], k=1
                )[0]

            # Parse string through the standard pipeline
            raw_scan = {
                "host": "synthetic.ssl.com",
                "port": 443,
                "cipher_suite": cipher_str,
                "tls_version": tls_version,
                "supported_protocols": list(set(supported)),
                "certificate_chain": [{
                    "position": 0,
                    "key_type": cert_key_type,
                    "key_bits": cert_key_bits,
                    "signature_algorithm": sig_alg,
                }]
            }

            parsed = cipher_parser.parse(raw_scan)
            classified = classifier.classify(parsed)

            features = self.feature_extractor.extract(classified)
            risk_score = classified.get("quantum_risk_score", 50.0)

            self.dataset.append(features)
            self.labels.append(risk_score)
            generated += 1

        logger.info(f"Generated {generated} realistic synthetic samples (total: {len(self.dataset)})")

    def get_numpy_data(self):
        X = self.feature_extractor.to_numpy(self.dataset)
        y = np.array(self.labels, dtype=np.float64)
        return X, y

    def export(self, path: str, format: str = "csv"):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        if format == "csv":
            fieldnames = self.feature_extractor.get_feature_names() + ["risk_score"]
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for features, label in zip(self.dataset, self.labels):
                    row = features.copy()
                    row["risk_score"] = label
                    writer.writerow(row)
        logger.info(f"Exported {len(self.dataset)} samples to {path}")
