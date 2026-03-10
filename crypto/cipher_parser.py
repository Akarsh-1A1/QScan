"""
QScan — Cipher Suite Parser Module

Parses TLS cipher suite names and classifies their cryptographic components:
  - Key exchange algorithm
  - Authentication algorithm
  - Bulk encryption algorithm
  - Message authentication (MAC)
  - Quantum vulnerability assessment
"""

import re
from typing import Dict, List, Optional

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


class CipherParser:
    """Parses and classifies cipher suites from TLS scan results."""

    def __init__(self):
        self.settings = Settings()

        # ─── Cipher Suite Component Patterns (IANA naming) ───
        self.kex_patterns = {
            "ECDHE": {"algorithm": "ECDHE", "quantum_safe": False, "family": "ECC"},
            "DHE": {"algorithm": "DHE", "quantum_safe": False, "family": "DH"},
            "ECDH": {"algorithm": "ECDH", "quantum_safe": False, "family": "ECC"},
            "DH": {"algorithm": "DH", "quantum_safe": False, "family": "DH"},
            "RSA": {"algorithm": "RSA", "quantum_safe": False, "family": "RSA"},
            "PSK": {"algorithm": "PSK", "quantum_safe": True, "family": "Symmetric"},
        }

        self.enc_patterns = {
            "AES_256_GCM": {"algorithm": "AES-256-GCM", "bits": 256, "quantum_safe": True},
            "AES_128_GCM": {"algorithm": "AES-128-GCM", "bits": 128, "quantum_safe": True},
            "AES_256_CBC": {"algorithm": "AES-256-CBC", "bits": 256, "quantum_safe": True},
            "AES_128_CBC": {"algorithm": "AES-128-CBC", "bits": 128, "quantum_safe": True},
            "CHACHA20_POLY1305": {"algorithm": "ChaCha20-Poly1305", "bits": 256, "quantum_safe": True},
            "3DES_EDE_CBC": {"algorithm": "3DES", "bits": 168, "quantum_safe": False},
            "RC4": {"algorithm": "RC4", "bits": 128, "quantum_safe": False},
            "DES_CBC": {"algorithm": "DES", "bits": 56, "quantum_safe": False},
            "NULL": {"algorithm": "NULL", "bits": 0, "quantum_safe": False},
        }

        self.auth_patterns = {
            "ECDSA": {"algorithm": "ECDSA", "quantum_safe": False},
            "RSA": {"algorithm": "RSA", "quantum_safe": False},
            "DSA": {"algorithm": "DSA", "quantum_safe": False},
            "PSK": {"algorithm": "PSK", "quantum_safe": True},
            "anon": {"algorithm": "Anonymous", "quantum_safe": False},
        }

        self.mac_patterns = {
            "SHA384": {"algorithm": "SHA-384", "bits": 384},
            "SHA256": {"algorithm": "SHA-256", "bits": 256},
            "SHA": {"algorithm": "SHA-1", "bits": 160},
            "MD5": {"algorithm": "MD5", "bits": 128},
            "AEAD": {"algorithm": "AEAD", "bits": None},
        }

    def parse(self, scan_result: Dict) -> Dict:
        """
        Parse a TLS scan result and add cryptographic classification.

        Args:
            scan_result: Raw output from TLS scanner

        Returns:
            Enriched scan result with parsed cipher suite details
        """
        result = scan_result.copy()

        # Parse the negotiated cipher suite
        cipher_name = result.get("cipher_suite", "")
        if cipher_name:
            result["cipher_analysis"] = self._analyze_cipher(cipher_name)

        # Parse all enumerated cipher suites
        all_ciphers = result.get("all_cipher_suites", [])
        result["all_cipher_analysis"] = []
        for cipher_info in all_ciphers:
            name = cipher_info.get("name", "")
            analysis = self._analyze_cipher(name)
            analysis["bits"] = cipher_info.get("bits")
            analysis["protocol"] = cipher_info.get("protocol")
            result["all_cipher_analysis"].append(analysis)

        # Parse certificate chain crypto
        chain = result.get("certificate_chain", [])
        result["chain_analysis"] = []
        for cert in chain:
            cert_analysis = self._analyze_certificate_crypto(cert)
            result["chain_analysis"].append(cert_analysis)

        # Overall cryptographic summary
        result["crypto_summary"] = self._generate_summary(result)

        return result

    def _analyze_cipher(self, cipher_name: str) -> Dict:
        """Break down a cipher suite name into its cryptographic components."""
        analysis = {
            "cipher_suite": cipher_name,
            "key_exchange": None,
            "authentication": None,
            "encryption": None,
            "mac": None,
            "forward_secrecy": False,
            "quantum_vulnerable_components": [],
            "quantum_safe_components": [],
        }

        if not cipher_name:
            return analysis

        # Determine if TLS 1.3 cipher (different naming convention)
        is_tls13 = cipher_name.startswith("TLS_") and "WITH" not in cipher_name

        if is_tls13:
            analysis = self._parse_tls13_cipher(cipher_name, analysis)
        else:
            analysis = self._parse_tls12_cipher(cipher_name, analysis)

        return analysis

    def _parse_tls13_cipher(self, cipher_name: str, analysis: Dict) -> Dict:
        """
        Parse TLS 1.3 cipher suite.
        TLS 1.3 ciphers use the format: TLS_<AEAD>_<HASH>
        Key exchange is always ECDHE or DHE (not in cipher name).
        """
        analysis["key_exchange"] = {
            "algorithm": "ECDHE/DHE",
            "quantum_safe": False,
            "note": "TLS 1.3 uses ephemeral key exchange (not in cipher name)",
        }
        analysis["forward_secrecy"] = True
        analysis["quantum_vulnerable_components"].append("Key Exchange (ECDHE/DHE)")

        # Parse encryption + MAC (AEAD in TLS 1.3)
        if "AES_256_GCM" in cipher_name:
            analysis["encryption"] = self.enc_patterns["AES_256_GCM"]
            analysis["quantum_safe_components"].append("AES-256-GCM")
        elif "AES_128_GCM" in cipher_name:
            analysis["encryption"] = self.enc_patterns["AES_128_GCM"]
            analysis["quantum_safe_components"].append("AES-128-GCM")
        elif "CHACHA20_POLY1305" in cipher_name:
            analysis["encryption"] = self.enc_patterns["CHACHA20_POLY1305"]
            analysis["quantum_safe_components"].append("ChaCha20-Poly1305")
        elif "AES_128_CCM" in cipher_name:
            analysis["encryption"] = {"algorithm": "AES-128-CCM", "bits": 128, "quantum_safe": True}
            analysis["quantum_safe_components"].append("AES-128-CCM")

        # Hash
        if "SHA384" in cipher_name:
            analysis["mac"] = self.mac_patterns["SHA384"]
        elif "SHA256" in cipher_name:
            analysis["mac"] = self.mac_patterns["SHA256"]

        analysis["mac"] = analysis.get("mac") or {"algorithm": "AEAD", "bits": None}

        return analysis

    def _parse_tls12_cipher(self, cipher_name: str, analysis: Dict) -> Dict:
        """
        Parse TLS 1.2 and earlier cipher suites.
        Format: TLS_<KEX>_WITH_<ENC>_<MAC> or ECDHE-RSA-AES256-GCM-SHA384 (OpenSSL)
        """
        # Normalize separators
        normalized = cipher_name.replace("-", "_").upper()

        # Key exchange
        for pattern, info in self.kex_patterns.items():
            if pattern in normalized:
                analysis["key_exchange"] = info.copy()
                if pattern in ("ECDHE", "DHE"):
                    analysis["forward_secrecy"] = True
                if not info["quantum_safe"]:
                    analysis["quantum_vulnerable_components"].append(
                        f"Key Exchange ({info['algorithm']})"
                    )
                else:
                    analysis["quantum_safe_components"].append(
                        f"Key Exchange ({info['algorithm']})"
                    )
                break

        # Encryption
        for pattern, info in self.enc_patterns.items():
            if pattern in normalized:
                analysis["encryption"] = info.copy()
                if info["quantum_safe"]:
                    analysis["quantum_safe_components"].append(info["algorithm"])
                else:
                    analysis["quantum_vulnerable_components"].append(info["algorithm"])
                break

        # Authentication (after KEX, check for auth-specific patterns)
        for pattern, info in self.auth_patterns.items():
            auth_check = f"_{pattern}_" in normalized or normalized.endswith(f"_{pattern}")
            if auth_check and pattern != analysis.get("key_exchange", {}).get("algorithm"):
                analysis["authentication"] = info.copy()
                if not info["quantum_safe"]:
                    analysis["quantum_vulnerable_components"].append(
                        f"Authentication ({info['algorithm']})"
                    )
                break

        # MAC
        for pattern, info in self.mac_patterns.items():
            if normalized.endswith(pattern) or f"_{pattern}_" in normalized:
                analysis["mac"] = info.copy()
                break

        return analysis

    def _analyze_certificate_crypto(self, cert: Dict) -> Dict:
        """Analyze the cryptographic properties of a certificate."""
        analysis = {
            "position": cert.get("position"),
            "key_type": cert.get("key_type", "UNKNOWN"),
            "key_bits": cert.get("key_bits", 0),
            "signature_algorithm": cert.get("signature_algorithm", "UNKNOWN"),
            "quantum_safe": False,
            "vulnerabilities": [],
            "recommendations": [],
        }

        # Key type assessment
        key_type = analysis["key_type"].upper()
        key_bits = analysis["key_bits"]

        if key_type == "RSA":
            analysis["quantum_safe"] = False
            analysis["vulnerabilities"].append(
                f"RSA-{key_bits} key exchange vulnerable to Shor's algorithm"
            )
            analysis["recommendations"].append(
                "Migrate to ML-KEM (Kyber) for key encapsulation"
            )
            if key_bits < 2048:
                analysis["vulnerabilities"].append(
                    f"RSA key size {key_bits} is below recommended minimum (2048)"
                )

        elif key_type in ("EC", "ECDSA", "ECC"):
            analysis["quantum_safe"] = False
            analysis["vulnerabilities"].append(
                f"ECC-{key_bits} vulnerable to quantum factoring"
            )
            analysis["recommendations"].append(
                "Migrate to ML-DSA (Dilithium) for digital signatures"
            )

        elif key_type == "DSA":
            analysis["quantum_safe"] = False
            analysis["vulnerabilities"].append("DSA vulnerable to Shor's algorithm")
            analysis["recommendations"].append(
                "Migrate to SLH-DSA (SPHINCS+) or ML-DSA (Dilithium)"
            )

        # Signature algorithm assessment
        sig_alg = analysis["signature_algorithm"].lower()
        if "sha1" in sig_alg or "md5" in sig_alg:
            analysis["vulnerabilities"].append(
                f"Weak signature algorithm: {analysis['signature_algorithm']}"
            )

        return analysis

    def _generate_summary(self, result: Dict) -> Dict:
        """Generate an overall cryptographic posture summary."""
        summary = {
            "total_quantum_vulnerable": 0,
            "total_quantum_safe": 0,
            "forward_secrecy": False,
            "deprecated_protocols": [],
            "weak_ciphers": [],
            "strong_ciphers": [],
        }

        # From cipher analysis
        cipher_analysis = result.get("cipher_analysis", {})
        if cipher_analysis:
            summary["total_quantum_vulnerable"] = len(
                cipher_analysis.get("quantum_vulnerable_components", [])
            )
            summary["total_quantum_safe"] = len(
                cipher_analysis.get("quantum_safe_components", [])
            )
            summary["forward_secrecy"] = cipher_analysis.get("forward_secrecy", False)

        # Check supported protocols
        for proto in result.get("supported_protocols", []):
            if proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                summary["deprecated_protocols"].append(proto)

        return summary
