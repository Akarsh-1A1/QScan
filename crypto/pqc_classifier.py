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
            "key_exchange": 35, "authentication": 20, "encryption": 15,
            "tls_version": 15, "certificate": 10, "forward_secrecy": 5,
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
        ca = result.get("cipher_analysis", {})

        kex = ca.get("key_exchange", {})
        if kex and not kex.get("quantum_safe", True):
            alg = kex.get("algorithm", "")
            score += self.weights["key_exchange"] * (1.0 if alg in ("RSA","DH") else 0.85)

        auth = ca.get("authentication", {})
        if auth and not auth.get("quantum_safe", True):
            score += self.weights["authentication"] * (1.0 if auth.get("algorithm")=="RSA" else 0.9)

        enc = ca.get("encryption", {})
        if enc:
            if not enc.get("quantum_safe", True):
                score += self.weights["encryption"]
            elif enc.get("bits", 0) and enc["bits"] < 256:
                score += self.weights["encryption"] * 0.2

        tls = result.get("tls_version", "")
        tls_risk = self.settings.tls_risk_levels.get(tls, "HIGH")
        tls_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.4, "LOW": 0.1}
        score += self.weights["tls_version"] * tls_map.get(tls_risk, 0.5)

        chain = result.get("chain_analysis", [])
        if chain:
            vulns = sum(len(c.get("vulnerabilities", [])) for c in chain)
            score += min(vulns * 3, self.weights["certificate"])
        else:
            score += self.weights["certificate"] * 0.5

        if not ca.get("forward_secrecy", False):
            score += self.weights["forward_secrecy"]

        deprecated = [p for p in result.get("supported_protocols", []) if p in ("SSLv2","SSLv3","TLSv1.0","TLSv1.1")]
        score += len(deprecated) * 2

        return round(min(score, 100.0), 1)

    def _risk_level(self, score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "SAFE"

    def _determine_pqc_status(self, result: Dict) -> str:
        risk = result.get("quantum_risk_score", 100)
        cipher_name = result.get("cipher_suite", "").upper()
        pqc_indicators = ["KYBER","ML_KEM","DILITHIUM","ML_DSA","SPHINCS","FALCON"]
        has_pqc = any(i in cipher_name for i in pqc_indicators)
        vuln = result.get("cipher_analysis", {}).get("quantum_vulnerable_components", [])
        if has_pqc and not vuln: return "PQC_READY"
        if has_pqc: return "HYBRID_PQC"
        if risk >= 80: return "CRITICAL"
        return "MIGRATION_NEEDED"

    def _generate_recommendations(self, result: Dict) -> List[Dict]:
        recs = []
        ca = result.get("cipher_analysis", {})

        for component, key in [("Key Exchange","key_exchange"), ("Authentication","authentication")]:
            info = ca.get(key, {})
            if info and not info.get("quantum_safe", True):
                alg = info.get("algorithm", "")
                rep = self.pqc_replacements.get(alg)
                if rep:
                    recs.append({
                        "component": component, "current": alg,
                        "recommended": rep["replacement"], "nist_standard": rep["nist"],
                        "priority": rep["priority"], "hybrid_option": rep["hybrid"],
                        "rationale": f"{alg} is vulnerable to Shor's algorithm. Migrate to {rep['replacement']} ({rep['nist']})."
                    })

        for cert in result.get("chain_analysis", []):
            for r in cert.get("recommendations", []):
                recs.append({"component": f"Certificate (pos {cert.get('position','?')})", "current": cert.get("key_type"), "recommended": r, "priority": "HIGH"})

        tls = result.get("tls_version", "")
        if tls in ("TLSv1.0","TLSv1.1"):
            recs.append({"component": "TLS Protocol", "current": tls, "recommended": "TLS 1.3", "priority": "CRITICAL"})

        return recs

    def _assess_threat_timeline(self, result: Dict) -> Dict:
        risk = result.get("quantum_risk_score", 50)
        fs = result.get("cipher_analysis", {}).get("forward_secrecy", False)
        return {
            "hndl_risk": "MEDIUM" if fs else "HIGH",
            "hndl_explanation": "Forward secrecy provides partial HNDL protection but key exchange remains quantum-vulnerable." if fs else "Without forward secrecy, recorded traffic can be decrypted once quantum computers break the private key.",
            "estimated_quantum_threat": "2030-2035",
            "migration_deadline": "2026" if risk>=80 else "2027" if risk>=60 else "2028" if risk>=40 else "2030",
            "urgency": "IMMEDIATE" if risk>=80 else "NEAR-TERM" if risk>=60 else "PLANNED" if risk>=40 else "MONITOR",
        }
