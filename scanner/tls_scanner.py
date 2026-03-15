"""
QScan — TLS Scanner Module

Performs TLS handshakes to extract:
  - TLS protocol version
  - Cipher suite details
  - Certificate information
  - Key exchange parameters
  - Certificate chain
"""

import socket
import ssl
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict

from OpenSSL import SSL, crypto

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


class TLSScanner:
    """Performs TLS analysis on target hosts."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def scan(self, host: str, port: int = 443) -> Optional[Dict]:
        """
        Perform a TLS handshake and extract cryptographic details.

        Returns a dictionary with TLS configuration info, or None on failure.
        """
        result = {
            "host": host,
            "port": port,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_version": None,
            "cipher_suite": None,
            "cipher_bits": None,
            "key_exchange": None,
            "certificate": None,
            "certificate_chain": [],
            "supported_protocols": [],
            "all_cipher_suites": [],
            "discovered_san_assets": [],
            "error": None,
        }

        try:
            # ─── Primary TLS Handshake (stdlib ssl) ─────────────
            primary_info = self._stdlib_scan(host, port)
            result.update(primary_info)

            # ─── Extract SAN domains (NEW FEATURE) ──────────────
            certificate = result.get("certificate")
            if certificate:
                result["discovered_san_assets"] = self._extract_san_domains(certificate)

            # ─── Extended Scan (pyOpenSSL) ──────────────────────
            extended_info = self._openssl_scan(host, port)
            result.update(extended_info)

            # ─── Protocol Support Enumeration ───────────────────
            supported = self._enumerate_protocols(host, port)
            result["supported_protocols"] = supported

            # ─── Cipher Suite Enumeration ───────────────────────
            all_ciphers = self._enumerate_ciphers(host, port)
            result["all_cipher_suites"] = all_ciphers

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"TLS scan failed for {host}:{port} — {e}")

        return result

    def _stdlib_scan(self, host: str, port: int) -> Dict:
        """Use Python's ssl module for basic TLS handshake info."""
        info = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection(
                (host, port), timeout=self.settings.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:

                    info["tls_version"] = tls_sock.version()

                    cipher = tls_sock.cipher()
                    if cipher:
                        info["cipher_suite"] = cipher[0]
                        info["cipher_protocol"] = cipher[1]
                        info["cipher_bits"] = cipher[2]

                    cert = tls_sock.getpeercert()
                    if cert:
                        info["certificate"] = self._parse_certificate(cert, host)

                    der_cert = tls_sock.getpeercert(binary_form=True)
                    if der_cert:
                        info.setdefault("certificate", {})
                        info["certificate"]["sha256_fingerprint"] = hashlib.sha256(
                            der_cert
                        ).hexdigest()

        except ssl.SSLCertVerificationError as e:
            logger.warning(f"  Certificate verification failed for {host}:{port}: {e}")
            info.update(self._insecure_scan(host, port))

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.warning(f"  Connection failed to {host}:{port}: {e}")

        return info

    def _insecure_scan(self, host: str, port: int) -> Dict:
        """Scan without certificate verification."""
        info = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (host, port), timeout=self.settings.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:

                    info["tls_version"] = tls_sock.version()

                    cipher = tls_sock.cipher()
                    if cipher:
                        info["cipher_suite"] = cipher[0]
                        info["cipher_protocol"] = cipher[1]
                        info["cipher_bits"] = cipher[2]

                    info["certificate_verified"] = False

        except Exception:
            pass

        return info

    def _openssl_scan(self, host: str, port: int) -> Dict:
        """Use pyOpenSSL for extended certificate and chain analysis."""
        info = {"certificate_chain": []}

        try:
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

            sock = socket.create_connection((host, port), timeout=self.settings.timeout)
            conn = SSL.Connection(ctx, sock)
            conn.set_tlsext_host_name(host.encode())
            conn.set_connect_state()
            conn.do_handshake()

            chain = conn.get_peer_cert_chain()

            if chain:
                for i, cert in enumerate(chain):

                    chain_cert = {
                        "position": i,
                        "subject": self._x509_name_to_dict(cert.get_subject()),
                        "issuer": self._x509_name_to_dict(cert.get_issuer()),
                        "serial_number": str(cert.get_serial_number()),
                        "signature_algorithm": cert.get_signature_algorithm().decode(
                            "utf-8", errors="ignore"
                        ),
                        "not_before": self._parse_asn1_time(cert.get_notBefore()),
                        "not_after": self._parse_asn1_time(cert.get_notAfter()),
                        "version": cert.get_version(),
                        "key_type": self._get_key_type(cert),
                        "key_bits": cert.get_pubkey().bits(),
                    }

                    info["certificate_chain"].append(chain_cert)

            cipher_name = conn.get_cipher_name()
            if cipher_name:
                info["key_exchange"] = self._extract_key_exchange(cipher_name)

            conn.shutdown()
            conn.close()
            sock.close()

        except Exception as e:
            logger.debug(f"  OpenSSL extended scan note for {host}:{port}: {e}")

        return info

    def _enumerate_protocols(self, host: str, port: int) -> List[str]:
        """Test which TLS protocol versions are supported."""
        supported = []

        protocols = {
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.0": ssl.TLSVersion.TLSv1,
        }

        for name, version in protocols.items():

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection(
                    (host, port), timeout=self.settings.timeout
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls_sock:

                        negotiated = tls_sock.version()

                        if negotiated:
                            supported.append(name)

            except Exception:
                pass

        return supported

    def _enumerate_ciphers(self, host: str, port: int) -> List[Dict]:
        """Enumerate all cipher suites accepted by the server."""
        accepted = []

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            all_ciphers = context.get_ciphers()

            for cipher_info in all_ciphers:

                cipher_name = cipher_info.get("name", "")

                try:
                    test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    test_ctx.check_hostname = False
                    test_ctx.verify_mode = ssl.CERT_NONE
                    test_ctx.set_ciphers(cipher_name)

                    with socket.create_connection((host, port), timeout=3) as sock:
                        with test_ctx.wrap_socket(sock, server_hostname=host) as tls_sock:

                            negotiated = tls_sock.cipher()

                            if negotiated:
                                accepted.append(
                                    {
                                        "name": negotiated[0],
                                        "protocol": negotiated[1],
                                        "bits": negotiated[2],
                                    }
                                )

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"  Cipher enumeration note: {e}")

        logger.debug(f"  {host}:{port} accepted {len(accepted)} cipher suites")

        return accepted

    def _extract_san_domains(self, certificate: Dict) -> List[str]:
        """Extract DNS SAN domains from certificate."""
        domains = []

        san_entries = certificate.get("san", [])

        for entry in san_entries:
            if entry.get("type") == "DNS":

                value = entry.get("value")

                if value and re.match(r"^[a-zA-Z0-9.-]+$", value):
                    domains.append(value.lower())

        return list(set(domains))

    def _parse_certificate(self, cert: Dict, host: str) -> Dict:
        """Parse stdlib certificate dict into structured format."""

        parsed = {
            "subject": {},
            "issuer": {},
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [],
            "hostname_match": False,
        }

        subject = cert.get("subject", ())

        for rdn in subject:
            for attr_type, attr_value in rdn:
                parsed["subject"][attr_type] = attr_value

        issuer = cert.get("issuer", ())

        for rdn in issuer:
            for attr_type, attr_value in rdn:
                parsed["issuer"][attr_type] = attr_value

        san = cert.get("subjectAltName", ())

        parsed["san"] = [
            {"type": san_type, "value": san_value} for san_type, san_value in san
        ]

        san_values = [v for _, v in san]

        cn = parsed["subject"].get("commonName", "")

        if host in san_values or host == cn:
            parsed["hostname_match"] = True

        try:
            not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")

            parsed["days_until_expiry"] = (not_after - datetime.utcnow()).days
            parsed["is_expired"] = parsed["days_until_expiry"] < 0

        except (ValueError, TypeError):
            pass

        return parsed

    def _x509_name_to_dict(self, x509_name) -> Dict:
        """Convert pyOpenSSL X509Name to dict."""
        result = {}

        for key, value in x509_name.get_components():
            result[key.decode("utf-8")] = value.decode("utf-8")

        return result

    def _get_key_type(self, cert) -> str:
        """Get the public key type from pyOpenSSL cert."""
        key = cert.get_pubkey()
        key_type = key.type()

        type_map = {
            crypto.TYPE_RSA: "RSA",
            crypto.TYPE_DSA: "DSA",
        }

        return type_map.get(key_type, f"UNKNOWN({key_type})")

    def _extract_key_exchange(self, cipher_name: str) -> str:
        """Extract key exchange algorithm from cipher suite name."""

        kex_map = {
            "ECDHE": "ECDHE",
            "DHE": "DHE",
            "ECDH": "ECDH",
            "DH": "DH",
            "RSA": "RSA",
            "PSK": "PSK",
        }

        for prefix, kex in kex_map.items():
            if cipher_name.startswith(prefix) or f"_{prefix}_" in cipher_name:
                return kex

        return "UNKNOWN"

    def _parse_asn1_time(self, asn1_bytes) -> Optional[str]:
        """Parse ASN1 time bytes to ISO format string."""
        try:
            if isinstance(asn1_bytes, bytes):
                time_str = asn1_bytes.decode("utf-8")
                dt = datetime.strptime(time_str, "%Y%m%d%H%M%SZ")
                return dt.isoformat() + "Z"
        except (ValueError, AttributeError):
            pass

        return None