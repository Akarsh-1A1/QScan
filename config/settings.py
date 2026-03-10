"""
QScan Configuration Settings
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    """Global configuration for QScan."""

    # ─── Network Settings ────────────────────────────────────
    timeout: int = 10
    max_threads: int = 10
    max_retries: int = 3
    retry_delay: float = 1.0

    # ─── Target Ports ────────────────────────────────────────
    target_ports: List[int] = field(default_factory=lambda: [
        443,    # HTTPS
        8443,   # HTTPS (alternate)
        8080,   # HTTP proxy / alt HTTPS
        993,    # IMAPS
        995,    # POP3S
        465,    # SMTPS
        587,    # SMTP (STARTTLS)
        636,    # LDAPS
        989,    # FTPS data
        990,    # FTPS control
        5061,   # SIP over TLS
    ])

    # ─── Asset Discovery ─────────────────────────────────────
    dns_resolvers: List[str] = field(default_factory=lambda: [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
    ])

    # Common subdomain prefixes for banking infrastructure
    subdomain_wordlist: List[str] = field(default_factory=lambda: [
        "www", "mail", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "smtp", "secure", "vpn", "api",
        "dev", "staging", "test", "portal", "admin",
        "gateway", "payment", "pay", "mobile", "app",
        "banking", "online", "ibank", "ebank", "netbanking",
        "services", "auth", "login", "sso", "ib",
        "corporate", "treasury", "fx", "trade",
        "cdn", "static", "assets", "media",
        "mx", "mx1", "mx2", "pop", "imap",
    ])

    # ─── Cryptographic Classification ────────────────────────

    # Algorithms considered quantum-vulnerable
    quantum_vulnerable_algorithms: List[str] = field(default_factory=lambda: [
        "RSA", "DSA", "ECDSA", "ECDH", "ECDHE",
        "DH", "DHE", "EdDSA", "Ed25519", "Ed448",
        "X25519", "X448",
    ])

    # NIST-approved Post-Quantum Algorithms
    pqc_algorithms: List[str] = field(default_factory=lambda: [
        "ML-KEM",          # Kyber (Key Encapsulation)
        "ML-DSA",          # Dilithium (Digital Signatures)
        "SLH-DSA",         # SPHINCS+ (Hash-based Signatures)
        "FN-DSA",          # Falcon (Digital Signatures)
        "BIKE",            # Alternate KEM
        "HQC",             # Alternate KEM
        "Classic McEliece", # Code-based KEM
    ])

    # Algorithms considered quantum-safe (symmetric)
    quantum_safe_symmetric: List[str] = field(default_factory=lambda: [
        "AES-256", "AES-192",
        "ChaCha20", "ChaCha20-Poly1305",
    ])

    # Algorithms partially safe (need larger key sizes)
    quantum_partial_safe: List[str] = field(default_factory=lambda: [
        "AES-128",  # Safe with Grover's, but reduced margin
    ])

    # ─── TLS Version Classification ─────────────────────────
    tls_risk_levels: dict = field(default_factory=lambda: {
        "TLSv1.3": "LOW",
        "TLSv1.2": "MEDIUM",
        "TLSv1.1": "HIGH",
        "TLSv1.0": "CRITICAL",
        "SSLv3":   "CRITICAL",
        "SSLv2":   "CRITICAL",
    })

    # ─── Output Settings ────────────────────────────────────
    cbom_version: str = "1.0"
    output_format: str = "json"
