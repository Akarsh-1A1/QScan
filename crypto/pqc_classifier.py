"""
QScan - PQC Classifier Module
Classifies crypto configs for post-quantum readiness.
"""

from typing import Dict, List
from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


class PQCClassifier:
    """Classifies assets for quantum readiness and recommends PQC migration."""

    def __init__(self):
        self.settings = Settings()

        self.weights = {
            "key_exchange": 35,
            "authentication": 20,
            "encryption": 15,
            "tls_version": 15,
            "certificate": 10,
            "forward_secrecy": 5,
        }

        self.pqc_replacements = {
            "RSA": {"replacement": "ML-KEM-768 (Kyber)", "nist": "FIPS 203", "priority": "HIGH", "hybrid": "X25519+ML-KEM-768"},
            "ECDHE": {"replacement": "ML-KEM-768 (Kyber)", "nist": "FIPS 203", "priority": "MEDIUM", "hybrid": "X25519+ML-KEM-768"},
            "DHE": {"replacement": "ML-KEM-1024 (Kyber)", "nist": "FIPS 203", "priority": "HIGH", "hybrid": "FFDHE+ML-KEM-1024"},
            "ECDH": {"replacement": "ML-KEM-768 (Kyber)", "nist": "FIPS 203", "priority": "MEDIUM", "hybrid": "ECDH+ML-KEM-768"},
            "DH": {"replacement": "ML-KEM-1024 (Kyber)", "nist": "FIPS 203", "priority": "HIGH", "hybrid": "DH+ML-KEM-1024"},
            "ECDSA": {"replacement": "ML-DSA-65 (Dilithium)", "nist": "FIPS 204", "priority": "MEDIUM", "hybrid": "ECDSA+ML-DSA-65"},
            "DSA": {"replacement": "ML-DSA-87 (Dilithium)", "nist": "FIPS 204", "priority": "HIGH", "hybrid": "N/A"},
            "Ed25519": {"replacement": "ML-DSA-44 (Dilithium)", "nist": "FIPS 204", "priority": "MEDIUM", "hybrid": "Ed25519+ML-DSA-44"},
        }

    def classify(self, parsed_result: Dict) -> Dict:

        result = parsed_result.copy()

        risk_score = self._compute_risk_score(result)

        result["quantum_risk_score"] = risk_score
        result["quantum_risk_level"] = self._risk_level(risk_score)

        result["pqc_status"] = self._determine_pqc_status(result)

        result["pqc_recommendations"] = self._generate_recommendations(result)

        result["quantum_threat_assessment"] = self._assess_threat_timeline(result)

        return result

    def _compute_risk_score(self, result: Dict) -> float:

        score = 0.0

        ca = result.get("cipher_analysis") or {}

        kex = ca.get("key_exchange") or {}

        if kex and not kex.get("quantum_safe", True):

            alg = kex.get("algorithm") or ""

            score += self.weights["key_exchange"] * (1.0 if alg in ("RSA", "DH") else 0.85)

        auth = ca.get("authentication") or {}

        if auth and not auth.get("quantum_safe", True):

            score += self.weights["authentication"] * (1.0 if auth.get("algorithm") == "RSA" else 0.9)

        enc = ca.get("encryption") or {}

        bits = enc.get("bits") or 0

        if bits >= 256:
            score += self.weights["encryption"] * 0.1
        elif bits >= 128:
            score += self.weights["encryption"] * 0.3
        else:
            score += self.weights["encryption"]

        tls = result.get("tls_version") or ""

        tls_risk = self.settings.tls_risk_levels.get(tls, "HIGH")

        tls_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.4, "LOW": 0.1}

        score += self.weights["tls_version"] * tls_map.get(tls_risk, 0.5)

        protocols = result.get("supported_protocols") or []

        if "TLSv1.3" in protocols:
            score -= 8

        chain = result.get("chain_analysis") or []

        for cert in chain:

            bits = cert.get("key_bits") or 0

            key_type = (cert.get("key_type") or "").upper()

            if key_type == "RSA":

                if bits < 2048:
                    score += 10
                elif bits < 3072:
                    score += 5
                else:
                    score += 2

            if key_type in ("EC", "ECDSA"):
                score += 4

        if not ca.get("forward_secrecy", False):
            score += self.weights["forward_secrecy"]

        deprecated = [p for p in protocols if p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]

        score += len(deprecated) * 2

        if "TLSv1.3" not in protocols and "TLSv1.2" in protocols:
            score += 3

        if len(protocols) > 3:
            score += 2

        all_ciphers = result.get("all_cipher_analysis") or []

        weak_cipher_count = 0

        for cipher in all_ciphers:

            enc = cipher.get("encryption") or {}

            if enc and not enc.get("quantum_safe", True):
                weak_cipher_count += 1

        score += min(weak_cipher_count * 1.5, 10)

        cipher_count = len(all_ciphers)

        if cipher_count > 20:
            score += 8
        elif cipher_count > 15:
            score += 5
        elif cipher_count > 10:
            score += 3

        return round(min(score, 100.0), 1)

    def _risk_level(self, score: float) -> str:

        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"

        return "SAFE"

    def _determine_pqc_status(self, result: Dict) -> str:

        risk = result.get("quantum_risk_score", 100)

        cipher_name = (result.get("cipher_suite") or "").upper()

        pqc_indicators = ["KYBER", "ML_KEM", "DILITHIUM", "ML_DSA", "SPHINCS", "FALCON"]

        has_pqc = any(i in cipher_name for i in pqc_indicators)

        vuln = result.get("cipher_analysis", {}).get("quantum_vulnerable_components", [])

        if has_pqc and not vuln:
            return "PQC_READY"

        if has_pqc:
            return "HYBRID_PQC"

        if risk >= 80:
            return "CRITICAL"

        return "MIGRATION_NEEDED"

    def _generate_recommendations(self, result: Dict) -> List[Dict]:

        recs = []

        ca = result.get("cipher_analysis") or {}

        for component, key in [("Key Exchange", "key_exchange"), ("Authentication", "authentication")]:

            info = ca.get(key) or {}

            if info and not info.get("quantum_safe", True):

                alg = info.get("algorithm") or ""

                rep = self.pqc_replacements.get(alg)

                if rep:

                    recs.append({
                        "component": component,
                        "current": alg,
                        "recommended": rep["replacement"],
                        "nist_standard": rep["nist"],
                        "priority": rep["priority"],
                        "hybrid_option": rep["hybrid"],
                        "rationale": f"{alg} is vulnerable to Shor's algorithm. Migrate to {rep['replacement']} ({rep['nist']})."
                    })

        tls = result.get("tls_version") or ""

        if tls in ("TLSv1.0", "TLSv1.1"):

            recs.append({
                "component": "TLS Protocol",
                "current": tls,
                "recommended": "TLS 1.3",
                "priority": "CRITICAL",
                "rationale": "Deprecated TLS version detected."
            })

        elif tls == "TLSv1.2":

            recs.append({
                "component": "TLS Protocol",
                "current": "TLS 1.2",
                "recommended": "TLS 1.3",
                "priority": "HIGH",
                "rationale": "TLS 1.3 provides improved cryptographic agility and PQC readiness."
            })

        return recs

    def _assess_threat_timeline(self, result: Dict) -> Dict:

        risk = result.get("quantum_risk_score", 50)

        fs = result.get("cipher_analysis", {}).get("forward_secrecy", False)

        kex = result.get("cipher_analysis", {}).get("key_exchange", {}).get("algorithm", "")

        if kex in ("RSA", "DH"):
            threat = "2028-2032"
        elif kex in ("ECDHE", "ECDH"):
            threat = "2030-2035"
        else:
            threat = "2035+"

        return {
            "hndl_risk": "MEDIUM" if fs else "HIGH",
            "hndl_explanation": "Forward secrecy provides partial HNDL protection but key exchange remains quantum-vulnerable." if fs else "Without forward secrecy, recorded traffic can be decrypted once quantum computers break the private key.",
            "estimated_quantum_threat": threat,
            "migration_deadline": "2026" if risk >= 80 else "2027" if risk >= 60 else "2028" if risk >= 40 else "2030",
            "urgency": "IMMEDIATE" if risk >= 80 else "NEAR-TERM" if risk >= 60 else "PLANNED" if risk >= 40 else "MONITOR",
        }