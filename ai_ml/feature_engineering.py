"""
QScan — Feature Engineering

Extracts and transforms cryptographic scan data into ML-ready features.
Handles encoding of categorical crypto attributes and normalization.
"""

import numpy as np
from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


# ─── Encoding Maps ──────────────────────────────────────────────────

TLS_VERSION_MAP = {
    "SSLv2": 0, "SSLv3": 1,
    "TLSv1.0": 2, "TLSv1.1": 3,
    "TLSv1.2": 4, "TLSv1.3": 5,
}

KEX_ALGORITHM_MAP = {
    "RSA": 0, "DH": 1, "DHE": 2,
    "ECDH": 3, "ECDHE": 4, "ECDHE/DHE": 4,
    "PSK": 5, "UNKNOWN": -1,
}

AUTH_ALGORITHM_MAP = {
    "RSA": 0, "DSA": 1, "ECDSA": 2,
    "PSK": 3, "Anonymous": 4, "UNKNOWN": -1,
}

ENC_ALGORITHM_MAP = {
    "NULL": 0, "DES": 1, "3DES": 2, "RC4": 3,
    "AES-128-CBC": 4, "AES-256-CBC": 5,
    "AES-128-GCM": 6, "AES-256-GCM": 7,
    "AES-128-CCM": 8,
    "ChaCha20-Poly1305": 9, "UNKNOWN": -1,
}

CERT_KEY_TYPE_MAP = {
    "RSA": 0, "EC": 1, "ECDSA": 1, "ECC": 1,
    "DSA": 2, "Ed25519": 3, "UNKNOWN": -1,
}

# Ordered feature names for model interpretability (Expanded to 24)
FEATURE_NAMES = [
    "tls_version",
    "kex_algorithm",
    "kex_quantum_safe",
    "auth_algorithm",
    "auth_quantum_safe",
    "enc_algorithm",
    "enc_bits",
    "enc_quantum_safe",
    "forward_secrecy",
    "num_quantum_vulnerable",
    "num_quantum_safe",
    "cert_key_type",
    "cert_key_bits",
    "num_deprecated_protocols",
    "num_chain_vulnerabilities",
    "has_weak_signature",
    # New realistic features
    "is_aead_cipher",
    "uses_sha1",
    "uses_md5",
    "is_cbc_cipher",
    "is_export_cipher",
    "is_null_cipher",
    "cipher_strength_bits",
    "protocol_deprecated",
]


class FeatureExtractor:
    """Extracts ML features from scan results."""

    def __init__(self):
        self.feature_names = FEATURE_NAMES.copy()
        logger.info("FeatureExtractor initialized")

    def extract(self, scan_result: dict) -> dict:
        """
        Extract features from a single scan result.
        Returns a dict of {feature_name: numeric_value}.
        """
        ca = scan_result.get("cipher_analysis", {})
        kex = ca.get("key_exchange") or {}
        auth = ca.get("authentication") or {}
        enc = ca.get("encryption") or {}
        mac = ca.get("mac") or {}

        # ── TLS version ──
        tls_ver_str = scan_result.get("tls_version", "")
        tls_version = TLS_VERSION_MAP.get(tls_ver_str, -1)
        protocol_deprecated = int(tls_ver_str in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"])

        # ── Key exchange ──
        kex_alg_str = kex.get("algorithm", "UNKNOWN")
        kex_algorithm = KEX_ALGORITHM_MAP.get(kex_alg_str, -1)
        kex_quantum_safe = int(kex.get("quantum_safe", False))

        # ── Authentication ──
        auth_alg_str = auth.get("algorithm", "UNKNOWN")
        auth_algorithm = AUTH_ALGORITHM_MAP.get(auth_alg_str, -1)
        auth_quantum_safe = int(auth.get("quantum_safe", False))

        # ── Encryption / Cipher properties ──
        enc_alg_str = enc.get("algorithm", "UNKNOWN")
        enc_algorithm = ENC_ALGORITHM_MAP.get(enc_alg_str, -1)
        enc_bits = enc.get("bits", 0) or 0
        enc_quantum_safe = int(enc.get("quantum_safe", False))
        cipher_suite_name = scan_result.get("cipher_suite", "").upper()

        is_aead_cipher = int("GCM" in cipher_suite_name or "POLY1305" in cipher_suite_name or "CCM" in cipher_suite_name)
        is_cbc_cipher = int("CBC" in cipher_suite_name)
        is_export_cipher = int("EXPORT" in cipher_suite_name)
        is_null_cipher = int(enc_alg_str == "NULL")
        cipher_strength_bits = enc_bits

        # ── Forward secrecy ──
        forward_secrecy = int(ca.get("forward_secrecy", False))

        # ── Quantum component counts ──
        num_quantum_vulnerable = len(ca.get("quantum_vulnerable_components", []))
        num_quantum_safe = len(ca.get("quantum_safe_components", []))

        # ── Certificate info (from first cert in chain) ──
        chain = scan_result.get("chain_analysis", [])
        uses_sha1 = int(mac.get("algorithm") == "SHA-1" or "SHA1" in cipher_suite_name)
        uses_md5 = int(mac.get("algorithm") == "MD5" or "MD5" in cipher_suite_name)
        
        if chain:
            first_cert = chain[0]
            cert_key_type = CERT_KEY_TYPE_MAP.get(first_cert.get("key_type", "UNKNOWN").upper(), -1)
            cert_key_bits = first_cert.get("key_bits", 0) or 0
            num_chain_vulns = sum(len(c.get("vulnerabilities", [])) for c in chain)
            
            sig_alg = str(first_cert.get("signature_algorithm", "")).lower()
            if "sha1" in sig_alg: uses_sha1 = 1
            if "md5" in sig_alg: uses_md5 = 1

            has_weak_sig = int(any("weak" in str(c.get("signature_algorithm", "")).lower() for c in chain) or uses_sha1 or uses_md5)
        else:
            cert_key_type = -1
            cert_key_bits = 0
            num_chain_vulns = 0
            has_weak_sig = 0

        # ── Deprecated protocols ──
        deprecated = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
        supported = scan_result.get("supported_protocols", [])
        num_deprecated = sum(1 for p in supported if p in deprecated)

        return {
            "tls_version": tls_version,
            "kex_algorithm": kex_algorithm,
            "kex_quantum_safe": kex_quantum_safe,
            "auth_algorithm": auth_algorithm,
            "auth_quantum_safe": auth_quantum_safe,
            "enc_algorithm": enc_algorithm,
            "enc_bits": enc_bits,
            "enc_quantum_safe": enc_quantum_safe,
            "forward_secrecy": forward_secrecy,
            "num_quantum_vulnerable": num_quantum_vulnerable,
            "num_quantum_safe": num_quantum_safe,
            "cert_key_type": cert_key_type,
            "cert_key_bits": cert_key_bits,
            "num_deprecated_protocols": num_deprecated,
            "num_chain_vulnerabilities": num_chain_vulns,
            "has_weak_signature": has_weak_sig,
            "is_aead_cipher": is_aead_cipher,
            "uses_sha1": uses_sha1,
            "uses_md5": uses_md5,
            "is_cbc_cipher": is_cbc_cipher,
            "is_export_cipher": is_export_cipher,
            "is_null_cipher": is_null_cipher,
            "cipher_strength_bits": cipher_strength_bits,
            "protocol_deprecated": protocol_deprecated,
        }

    def extract_batch(self, scan_results: list) -> list:
        features = []
        for result in scan_results:
            try:
                feat = self.extract(result)
                features.append(feat)
            except Exception as e:
                logger.warning(f"Feature extraction failed for one result: {e}")
        return features

    def to_numpy(self, feature_dicts: list) -> np.ndarray:
        matrix = []
        for fd in feature_dicts:
            row = [fd.get(name, 0) for name in self.feature_names]
            matrix.append(row)
        return np.array(matrix, dtype=np.float64)

    def get_feature_names(self) -> list:
        return self.feature_names
