"""
QScan — VPN Scanner Module

Detects and analyses TLS-based VPN endpoints exposed on the public internet:
  - IKEv2 / IPsec  (UDP 500, 4500)
  - OpenVPN         (UDP 1194, TCP 1194 / 443)
  - SSL VPN         (TCP 443, 8443, 4433, 10443)
  - WireGuard       (UDP 51820)

For each detected VPN endpoint the scanner reports:
  - VPN protocol type
  - Port / transport
  - Cryptographic parameters (ciphers, key-exchange, integrity, DH group)
  - PQC readiness assessment
  - Recommendations for migration to quantum-safe algorithms
"""

import socket
import ssl
import struct
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# PQC reference data
# ---------------------------------------------------------------------------

# IKEv2 transform-type 1 — Encryption Algorithm
IKE_ENCR = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES",
    5: "3IDEA",
    6: "CAST",
    7: "BLOWFISH",
    8: "3IDEA-v2",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    23: "CAMELLIA-CBC",
    24: "CAMELLIA-CTR",
    25: "CAMELLIA-CCM-8",
    26: "CAMELLIA-CCM-12",
    27: "CAMELLIA-CCM-16",
    28: "CHACHA20-POLY1305",
}

# IKEv2 transform-type 2 — PRF Algorithm
IKE_PRF = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "HMAC-TIGER",
    5: "AES128-XCBC",
    6: "HMAC-SHA2-256",
    7: "HMAC-SHA2-384",
    8: "HMAC-SHA2-512",
    9: "AES128-CMAC",
}

# IKEv2 transform-type 3 — Integrity Algorithm
IKE_INTEG = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-96",
    6: "HMAC-MD5-128",
    7: "HMAC-SHA1-160",
    8: "AES-CMAC-96",
    9: "AES-128-GMAC",
    10: "AES-192-GMAC",
    11: "AES-256-GMAC",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

# IKEv2 transform-type 4 — Diffie-Hellman Group
IKE_DH = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-192",
    20: "ECP-224",
    21: "ECP-256",
    22: "ECP-384",
    23: "ECP-521",
    24: "MODP-1024+160",
    25: "MODP-2048+224",
    26: "MODP-2048+256",
    27: "ECP-192",
    28: "ECP-256",
    29: "ECP-384",
    30: "ECP-521",
    31: "CURVE25519",
    32: "CURVE448",
    33: "GOST-R-34-10",
    34: "ML-KEM-768 (Kyber)",   # Draft hybrid/PQC
    35: "ML-KEM-1024 (Kyber)",
}

# DH groups that are quantum-safe or PQC hybrid
PQC_SAFE_DH_GROUPS = {31, 32, 34, 35}

# Encryption algorithms quantum-safe (symmetric ≥ 256-bit counts as safe against Grover)
QUANTUM_SAFE_ENCR = {
    20: True,   # AES-GCM-16 (256-bit key)
    28: True,   # CHACHA20-POLY1305
}

# Well-known PQC cipher strings (TLS)
PQC_TLS_INDICATORS = [
    "kyber", "ml_kem", "ml-kem", "dilithium", "ml_dsa", "ml-dsa",
    "sphincs", "falcon", "x25519kyber768", "p256kyber512",
]


def _is_pqc_tls_cipher(cipher_name: str) -> bool:
    lower = cipher_name.lower()
    return any(ind in lower for ind in PQC_TLS_INDICATORS)


# ---------------------------------------------------------------------------
# VPN Scanner
# ---------------------------------------------------------------------------

class VPNScanner:
    """
    Probes well-known VPN ports to detect and characterise TLS-based VPNs
    and IKEv2/IPsec endpoints, then assesses post-quantum readiness.
    """

    # Ports to probe per protocol
    IKE_PORTS = [500, 4500]
    OPENVPN_UDP_PORTS = [1194]
    OPENVPN_TCP_PORTS = [1194, 443]
    SSL_VPN_PORTS = [443, 8443, 4433, 10443]
    WIREGUARD_PORTS = [51820]

    def __init__(self, settings: Settings):
        self.settings = settings
        self.timeout = min(settings.timeout, 5)  # be fast for UDP probes

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def scan(self, host: str) -> List[Dict]:
        """
        Scan *host* for all supported VPN protocol types.

        Returns a list of VPN endpoint dicts (one per detected endpoint).
        """
        results: List[Dict] = []

        # IKEv2 / IPsec
        for port in self.IKE_PORTS:
            res = self._scan_ike(host, port)
            if res:
                results.append(res)

        # SSL VPN (TLS-based)
        for port in self.SSL_VPN_PORTS:
            res = self._scan_ssl_vpn(host, port)
            if res:
                results.append(res)

        # OpenVPN over UDP
        for port in self.OPENVPN_UDP_PORTS:
            res = self._scan_openvpn_udp(host, port)
            if res:
                results.append(res)

        # OpenVPN over TCP (TLS-based)
        for port in self.OPENVPN_TCP_PORTS:
            res = self._scan_openvpn_tcp(host, port)
            if res:
                results.append(res)

        # WireGuard handshake probe
        for port in self.WIREGUARD_PORTS:
            res = self._scan_wireguard(host, port)
            if res:
                results.append(res)

        # deduplicate by (port, protocol)
        seen = set()
        unique = []
        for r in results:
            key = (r.get("port"), r.get("vpn_protocol"))
            if key not in seen:
                seen.add(key)
                unique.append(r)

        logger.info(f"  VPN scan {host}: {len(unique)} endpoint(s) detected")
        return unique

    # -----------------------------------------------------------------------
    # IKEv2 / IPsec scanner
    # -----------------------------------------------------------------------

    def _scan_ike(self, host: str, port: int) -> Optional[Dict]:
        """
        Send an IKEv2 SA_INIT packet and parse the responder's proposal.
        """
        try:
            packet = self._build_ikev2_sa_init()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(4096)
            sock.close()

            if len(data) < 28:
                return None

            return self._parse_ikev2_response(host, port, data)

        except (socket.timeout, OSError, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"  IKE scan {host}:{port} — {e}")
            return None

    def _build_ikev2_sa_init(self) -> bytes:
        """
        Build a minimal IKE_SA_INIT request with a single proposal that lists
        common transform types so the responder echoes back its preferences.
        """
        # Initiator SPI (8 random bytes)
        spi_i = os.urandom(8)
        spi_r = b"\x00" * 8

        # Transforms: ENCR=AES-CBC(id=12) key=256, PRF=HMAC-SHA2-256(id=6),
        #             INTEG=HMAC-SHA2-256-128(id=12), DH=ECP-256(id=19)
        def make_transform(t_type: int, t_id: int, attr: bytes = b"") -> bytes:
            payload = struct.pack(">BBH", t_type, 0, t_id) + attr
            # last transform flag = 3, non-last = 0
            return payload

        transforms = [
            make_transform(1, 12, struct.pack(">HH", 0x800E, 256)),  # ENCR AES-CBC 256
            make_transform(2, 6),   # PRF HMAC-SHA2-256
            make_transform(3, 12),  # INTEG HMAC-SHA2-256-128
            make_transform(4, 19),  # DH ECP-256
        ]

        # Pack transforms with proper last/more flags
        raw_transforms = b""
        for i, t in enumerate(transforms):
            last = (i == len(transforms) - 1)
            t_type = t[0:1]
            t_rest = t[1:]
            transform_length = 8 + len(t_rest)  # header(4) + type(1) + res(1) + id(2) = 8
            # transform: last(1) res(1) length(2) type(1) res(1) id(2) [attributes]
            t_id_bytes = struct.unpack(">H", t[2:4])[0] if len(t) >= 4 else 0
            attr = t[4:] if len(t) > 4 else b""
            length = 8 + len(attr)
            raw_transforms += struct.pack(">BBH BB H", 0 if not last else 0, 0, length,
                                          t[0], 0, struct.unpack(">H", t[2:4])[0] if len(t) >= 4 else 0) + attr

        # Build SA proposal
        # proposal: last(1) res(1) length(2) num(1) proto_id(1) spi_size(1) num_transforms(1) [transforms]
        num_transforms = len(transforms)
        proposal_header = struct.pack(">BBHBBBB", 0, 0, 0, 1, 1, 0, num_transforms)

        # Rebuild transforms properly
        raw_t = b""
        for i, (t_type, t_id) in enumerate([
            (1, 12), (2, 6), (3, 12), (4, 19)
        ]):
            last_flag = 0 if i < len(transforms) - 1 else 0
            attr = struct.pack(">HH", 0x800E, 256) if t_type == 1 else b""
            t_len = 8 + len(attr)
            raw_t += struct.pack(">BBH BB H", last_flag, 0, t_len, t_type, 0, t_id) + attr

        proposal_len = 8 + len(raw_t)
        proposal = struct.pack(">BBHBBBB", 0, 0, proposal_len, 1, 1, 0, len(transforms)) + raw_t

        # SA payload: next(1) crit(1) length(2) proposal
        sa_len = 4 + len(proposal)
        sa_payload = struct.pack(">BBH", 0x21, 0, sa_len) + proposal  # next=0x21 (Nonce)

        # Nonce payload
        nonce = os.urandom(32)
        nonce_payload = struct.pack(">BBH", 0, 0, 4 + len(nonce)) + nonce  # next=0 (no next)

        # Chain: SA -> Nonce
        sa_payload = struct.pack(">BBH", 0x28, 0, sa_len) + proposal  # next=0x28 (40=Nonce)
        nonce_payload = struct.pack(">BBH", 0, 0, 4 + len(nonce)) + nonce

        payloads = sa_payload + nonce_payload

        # IKEv2 header: spi_i(8) spi_r(8) next_payload(1) ver(1) exchange_type(1)
        #                flags(1) message_id(4) length(4)
        header_len = 28
        total_len = header_len + len(payloads)
        # next payload = SA (33 = 0x21)
        header = (spi_i + spi_r
                  + struct.pack(">B", 0x21)   # next payload = SA
                  + struct.pack(">B", 0x20)   # version 2.0
                  + struct.pack(">B", 0x22)   # IKE_SA_INIT = 34 = 0x22
                  + struct.pack(">B", 0x08)   # flags: Initiator
                  + struct.pack(">I", 0)      # message ID
                  + struct.pack(">I", total_len))
        return header + payloads

    def _parse_ikev2_response(self, host: str, port: int, data: bytes) -> Optional[Dict]:
        """
        Parse an IKEv2 SA_INIT response and extract offered transforms.
        """
        if len(data) < 28:
            return None

        # Check IKEv2 header
        version = data[17]
        exchange_type = data[18]

        if (version & 0xF0) != 0x20:  # Must be IKEv2 (major=2)
            return None

        if exchange_type not in (0x22, 0x23):  # SA_INIT or SA_AUTH
            # Might still be IKE response; proceed cautiously
            pass

        encr_algos: List[str] = []
        prf_algos: List[str] = []
        integ_algos: List[str] = []
        dh_groups: List[str] = []
        dh_ids: List[int] = []

        next_payload = data[16]
        offset = 28

        while offset < len(data) and next_payload != 0:
            if offset + 4 > len(data):
                break

            current_payload = next_payload
            next_payload = data[offset]
            payload_len = struct.unpack(">H", data[offset + 2: offset + 4])[0]

            if payload_len < 4 or offset + payload_len > len(data):
                break

            payload_data = data[offset + 4: offset + payload_len]

            # SA payload (type 33 = 0x21)
            if current_payload == 0x21:
                self._parse_sa_payload(payload_data, encr_algos, prf_algos, integ_algos, dh_groups, dh_ids)

            offset += payload_len

        if not encr_algos and not dh_groups:
            # Got a response but couldn't parse — still report as detected
            return self._vpn_result(host, port, "IKEv2/IPsec", "UDP",
                                    encr_algos, prf_algos, integ_algos, dh_groups, dh_ids)

        return self._vpn_result(host, port, "IKEv2/IPsec", "UDP",
                                encr_algos, prf_algos, integ_algos, dh_groups, dh_ids)

    def _parse_sa_payload(self, data: bytes, encr: list, prf: list,
                           integ: list, dh: list, dh_ids: list):
        """Parse SA payload proposals and extract transform IDs."""
        offset = 0
        while offset < len(data):
            if offset + 8 > len(data):
                break
            last_prop = data[offset]
            prop_len = struct.unpack(">H", data[offset + 2: offset + 4])[0]
            if prop_len < 8:
                break
            num_transforms = data[offset + 7]
            t_offset = offset + 8
            for _ in range(num_transforms):
                if t_offset + 8 > len(data):
                    break
                t_last = data[t_offset]
                t_len = struct.unpack(">H", data[t_offset + 2: t_offset + 4])[0]
                if t_len < 8:
                    break
                t_type = data[t_offset + 4]
                t_id = struct.unpack(">H", data[t_offset + 6: t_offset + 8])[0]

                if t_type == 1:
                    name = IKE_ENCR.get(t_id, f"ENCR-{t_id}")
                    if name not in encr:
                        encr.append(name)
                elif t_type == 2:
                    name = IKE_PRF.get(t_id, f"PRF-{t_id}")
                    if name not in prf:
                        prf.append(name)
                elif t_type == 3:
                    name = IKE_INTEG.get(t_id, f"INTEG-{t_id}")
                    if name not in integ:
                        integ.append(name)
                elif t_type == 4:
                    name = IKE_DH.get(t_id, f"DH-{t_id}")
                    if name not in dh:
                        dh.append(name)
                        dh_ids.append(t_id)

                t_offset += t_len
            if last_prop == 0:
                break
            offset += prop_len

    # -----------------------------------------------------------------------
    # SSL VPN scanner (TLS-based)
    # -----------------------------------------------------------------------

    def _scan_ssl_vpn(self, host: str, port: int) -> Optional[Dict]:
        """
        Attempt a TLS handshake on SSL VPN ports and characterise the cipher.
        Detect SSL VPN by checking for common vendor-specific HTTP headers.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls_ver = tls.version()
                    cipher = tls.cipher()
                    cipher_name = cipher[0] if cipher else "UNKNOWN"
                    cipher_bits = cipher[2] if cipher else 0

                    # Probe for SSL VPN indicators via HTTP
                    is_ssl_vpn, vpn_product = self._detect_ssl_vpn_banner(tls, host, port)
                    if not is_ssl_vpn and port not in (443, 8443):
                        return None

            return self._tls_vpn_result(
                host=host,
                port=port,
                vpn_protocol="SSL-VPN" if is_ssl_vpn else "HTTPS",
                vpn_product=vpn_product,
                tls_version=tls_ver,
                cipher_name=cipher_name,
                cipher_bits=cipher_bits,
            )

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        except ssl.SSLError:
            return None
        except Exception as e:
            logger.debug(f"  SSL VPN probe {host}:{port} — {e}")
            return None

    def _detect_ssl_vpn_banner(self, tls_sock, host: str, port: int):
        """
        Send an HTTP GET and look for SSL VPN product banners.
        Returns (is_vpn: bool, product: str).
        """
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: QScan/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            tls_sock.sendall(request)
            response = tls_sock.recv(4096).decode("utf-8", errors="ignore")

            vpn_signatures = {
                "Pulse Secure": ["pulse", "pulse-secure", "pulseui"],
                "Fortinet SSL VPN": ["forticlient", "fortinet", "sslvpn"],
                "Cisco AnyConnect": ["anyconnect", "cisco", "webvpn", "svc"],
                "Palo Alto GlobalProtect": ["globalprotect", "pan-gp", "PaloAlto"],
                "Citrix NetScaler": ["citrix", "netscaler", "nsvpn"],
                "F5 BIG-IP": ["bigip", "f5-icontrol", "/my.logon.php"],
                "SonicWall SSL VPN": ["sonicwall", "sslvpn", "NetExtender"],
                "Check Point VPN": ["checkpoint", "cp-vpn"],
                "OpenVPN AS": ["openvpn", "OpenVPN Access Server"],
                "WireGuard": ["WireGuard"],
            }

            lower_resp = response.lower()
            for product, sigs in vpn_signatures.items():
                if any(s.lower() in lower_resp for s in sigs):
                    return True, product

            # Check for common VPN-specific paths
            vpn_paths = ["/dana-na/", "/remote/login", "/vpn/index.html",
                         "/global-protect/", "/dana/home", "/my.logon.php",
                         "/cgi-bin/sslvpn", "/ssl-vpn/", "/smb/"]
            if any(p in response for p in vpn_paths):
                return True, "Unknown SSL VPN"

        except Exception:
            pass

        return False, ""

    # -----------------------------------------------------------------------
    # OpenVPN UDP scanner
    # -----------------------------------------------------------------------

    def _scan_openvpn_udp(self, host: str, port: int) -> Optional[Dict]:
        """
        Send an OpenVPN client reset packet and check for a response.
        OpenVPN UDP handshake starts with a P_CONTROL_HARD_RESET_CLIENT_V2.
        """
        try:
            # OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2
            # opcode (3-bits) | key_id (5-bits) = 0x38 (7<<3|0)
            session_id = os.urandom(8)
            packet = bytes([0x38]) + session_id + b"\x00" + struct.pack(">I", 0) + b"\x00"

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if not data:
                return None

            # If we get any non-ICMP response it's likely OpenVPN
            opcode = (data[0] >> 3) & 0x1F if data else 0

            return {
                "host": host,
                "port": port,
                "transport": "UDP",
                "vpn_protocol": "OpenVPN",
                "vpn_product": "OpenVPN",
                "detected": True,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "tls_version": None,
                "cipher_suite": None,
                "cipher_bits": None,
                "encryption_algorithms": [],
                "prf_algorithms": [],
                "integrity_algorithms": [],
                "dh_groups": [],
                "pqc_status": "MIGRATION_NEEDED",
                "quantum_risk_level": "HIGH",
                "quantum_risk_score": 65.0,
                "notes": "OpenVPN UDP detected. TLS cipher details require TCP probe.",
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "ECDHE / DH (OpenVPN default)",
                        "recommended": "ML-KEM-768 (Kyber) via tls-groups",
                        "nist_standard": "FIPS 203",
                        "priority": "HIGH",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": "OpenVPN 2.6+ supports hybrid PQC key exchange via --tls-groups.",
                    }
                ],
            }

        except (socket.timeout, OSError, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"  OpenVPN UDP probe {host}:{port} — {e}")
            return None

    # -----------------------------------------------------------------------
    # OpenVPN TCP scanner (TLS-based)
    # -----------------------------------------------------------------------

    def _scan_openvpn_tcp(self, host: str, port: int) -> Optional[Dict]:
        """
        Probe OpenVPN TCP mode: OpenVPN wraps TLS inside its own framing.
        We try a TCP connect followed by OpenVPN reset; if that fails we fall
        back to treating a plain TLS response as potential OpenVPN/SSL-VPN.
        """
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)

            # OpenVPN TCP: 2-byte length prefix then P_CONTROL_HARD_RESET
            session_id = os.urandom(8)
            inner = bytes([0x38]) + session_id + b"\x00" + struct.pack(">I", 0) + b"\x00"
            packet = struct.pack(">H", len(inner)) + inner
            sock.sendall(packet)
            sock.settimeout(self.timeout)
            data = sock.recv(1024)
            sock.close()

            if not data:
                return None

            return {
                "host": host,
                "port": port,
                "transport": "TCP",
                "vpn_protocol": "OpenVPN",
                "vpn_product": "OpenVPN",
                "detected": True,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "tls_version": None,
                "cipher_suite": None,
                "cipher_bits": None,
                "encryption_algorithms": [],
                "prf_algorithms": [],
                "integrity_algorithms": [],
                "dh_groups": [],
                "pqc_status": "MIGRATION_NEEDED",
                "quantum_risk_level": "HIGH",
                "quantum_risk_score": 65.0,
                "notes": "OpenVPN TCP detected.",
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "ECDHE / DH (OpenVPN default)",
                        "recommended": "ML-KEM-768 (Kyber) via tls-groups",
                        "nist_standard": "FIPS 203",
                        "priority": "HIGH",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": "OpenVPN 2.6+ supports hybrid PQC via --tls-groups.",
                    }
                ],
            }

        except (socket.timeout, OSError, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"  OpenVPN TCP probe {host}:{port} — {e}")
            return None

    # -----------------------------------------------------------------------
    # WireGuard scanner
    # -----------------------------------------------------------------------

    def _scan_wireguard(self, host: str, port: int) -> Optional[Dict]:
        """
        Send a WireGuard handshake initiation message and listen for a response.
        WireGuard uses Curve25519 + ChaCha20-Poly1305 — quantum-safe symmetric
        but key exchange is not PQC-safe.
        """
        try:
            # WireGuard Handshake Initiation: type(4) reserved(3) sender(4)
            #   ephemeral(32) encrypted_static(48) encrypted_timestamp(28) mac1(16) mac2(16)
            # We send a minimal (zeros) initiation; any response indicates WireGuard.
            wg_msg = struct.pack(">I", 1) + b"\x00" * 3  # type=1, reserved
            wg_msg += os.urandom(4)                        # sender index
            wg_msg += b"\x00" * (32 + 48 + 28 + 16 + 16) # rest of fields

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(wg_msg, (host, port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if not data:
                return None

            # Check for WireGuard handshake response (type=2)
            if len(data) >= 4 and struct.unpack(">I", data[:4])[0] == 2:
                detected = True
            else:
                detected = True  # Any response to WG port is likely WG

            return {
                "host": host,
                "port": port,
                "transport": "UDP",
                "vpn_protocol": "WireGuard",
                "vpn_product": "WireGuard",
                "detected": detected,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "tls_version": "N/A",
                "cipher_suite": "ChaCha20-Poly1305",
                "cipher_bits": 256,
                "encryption_algorithms": ["ChaCha20-Poly1305"],
                "prf_algorithms": ["BLAKE2s"],
                "integrity_algorithms": ["Poly1305"],
                "dh_groups": ["Curve25519"],
                "pqc_status": "MIGRATION_NEEDED",
                "quantum_risk_level": "MEDIUM",
                "quantum_risk_score": 50.0,
                "notes": (
                    "WireGuard uses ChaCha20-Poly1305 (256-bit, Grover-resistant) "
                    "and Curve25519 for key exchange. Symmetric layer is quantum-safe; "
                    "key exchange (Curve25519) is vulnerable to Shor's algorithm."
                ),
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "Curve25519 (X25519)",
                        "recommended": "ML-KEM-768 (Kyber) hybrid",
                        "nist_standard": "FIPS 203",
                        "priority": "MEDIUM",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": (
                            "WireGuard post-quantum extensions (e.g. wireguard-pq) "
                            "add ML-KEM hybrid key encapsulation. "
                            "Symmetric ciphers (ChaCha20-Poly1305) are already quantum-safe."
                        ),
                    }
                ],
            }

        except (socket.timeout, OSError, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"  WireGuard probe {host}:{port} — {e}")
            return None

    # -----------------------------------------------------------------------
    # Result builders
    # -----------------------------------------------------------------------

    def _vpn_result(
        self,
        host: str,
        port: int,
        vpn_protocol: str,
        transport: str,
        encr_algos: List[str],
        prf_algos: List[str],
        integ_algos: List[str],
        dh_groups: List[str],
        dh_ids: List[int],
    ) -> Dict:
        """Build a structured VPN result dict for IKE-style endpoints."""

        pqc_status, risk_score, risk_level, recommendations = self._assess_ike_pqc(
            encr_algos, dh_groups, dh_ids
        )

        return {
            "host": host,
            "port": port,
            "transport": transport,
            "vpn_protocol": vpn_protocol,
            "vpn_product": vpn_protocol,
            "detected": True,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_version": None,
            "cipher_suite": encr_algos[0] if encr_algos else None,
            "cipher_bits": None,
            "encryption_algorithms": encr_algos,
            "prf_algorithms": prf_algos,
            "integrity_algorithms": integ_algos,
            "dh_groups": dh_groups,
            "pqc_status": pqc_status,
            "quantum_risk_level": risk_level,
            "quantum_risk_score": risk_score,
            "notes": self._ike_notes(encr_algos, dh_groups),
            "recommendations": recommendations,
        }

    def _tls_vpn_result(
        self,
        host: str,
        port: int,
        vpn_protocol: str,
        vpn_product: str,
        tls_version: Optional[str],
        cipher_name: str,
        cipher_bits: Optional[int],
    ) -> Dict:
        """Build a structured VPN result dict for TLS-based VPN endpoints."""

        pqc_status, risk_score, risk_level, recommendations = self._assess_tls_vpn_pqc(
            tls_version, cipher_name, cipher_bits
        )

        return {
            "host": host,
            "port": port,
            "transport": "TCP",
            "vpn_protocol": vpn_protocol,
            "vpn_product": vpn_product,
            "detected": True,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
            "cipher_bits": cipher_bits,
            "encryption_algorithms": [cipher_name] if cipher_name else [],
            "prf_algorithms": [],
            "integrity_algorithms": [],
            "dh_groups": [],
            "pqc_status": pqc_status,
            "quantum_risk_level": risk_level,
            "quantum_risk_score": risk_score,
            "notes": self._tls_notes(tls_version, cipher_name),
            "recommendations": recommendations,
        }

    # -----------------------------------------------------------------------
    # PQC assessment helpers
    # -----------------------------------------------------------------------

    def _assess_ike_pqc(
        self,
        encr_algos: List[str],
        dh_groups: List[str],
        dh_ids: List[int],
    ):
        """
        Score IKEv2/IPsec configuration against PQC criteria.
        Returns (pqc_status, risk_score, risk_level, recommendations).
        """
        score = 0.0
        recommendations = []

        # Key exchange risk (highest weight)
        has_pqc_dh = any(did in PQC_SAFE_DH_GROUPS for did in dh_ids)
        has_weak_dh = any(
            g in dh_groups for g in ("MODP-768", "MODP-1024", "MODP-1536")
        )
        if not has_pqc_dh:
            score += 40
            recommendations.append({
                "component": "IKE Key Exchange",
                "current": ", ".join(dh_groups) if dh_groups else "MODP/ECP (classic)",
                "recommended": "ML-KEM-768 (Kyber) hybrid with RFC 9370",
                "nist_standard": "FIPS 203",
                "priority": "HIGH",
                "hybrid_option": "ECDH+ML-KEM-768",
                "rationale": (
                    "IKEv2 Diffie-Hellman groups based on MODP or ECDH are vulnerable "
                    "to Shor's algorithm. RFC 9370 defines PQC hybrid KEM for IKEv2."
                ),
            })
        if has_weak_dh:
            score += 20
            recommendations.append({
                "component": "IKE DH Group",
                "current": next(
                    g for g in dh_groups if g in ("MODP-768", "MODP-1024", "MODP-1536")
                ),
                "recommended": "ECP-256 minimum (short-term) / ML-KEM (long-term)",
                "nist_standard": "NIST SP 800-77r1",
                "priority": "CRITICAL",
                "hybrid_option": "ECDH+ML-KEM-768",
                "rationale": "Weak MODP groups (≤1536-bit) are exploitable even classically.",
            })

        # Encryption
        has_quantum_safe_encr = any(
            a in ("AES-GCM-16", "CHACHA20-POLY1305", "AES-GCM-8", "AES-GCM-12")
            for a in encr_algos
        )
        if not has_quantum_safe_encr and encr_algos:
            score += 20
            recommendations.append({
                "component": "IKE Encryption",
                "current": ", ".join(encr_algos),
                "recommended": "AES-256-GCM or ChaCha20-Poly1305 (256-bit)",
                "nist_standard": "NIST SP 800-38D",
                "priority": "MEDIUM",
                "hybrid_option": "AES-256-GCM",
                "rationale": "256-bit symmetric ciphers provide Grover-resistant security.",
            })
        elif not encr_algos:
            score += 15

        # Deprecated 3DES / DES
        has_legacy = any(a in ("DES", "3DES", "DES-IV64") for a in encr_algos)
        if has_legacy:
            score += 20
            recommendations.append({
                "component": "IKE Encryption",
                "current": "DES/3DES",
                "recommended": "AES-256-GCM",
                "nist_standard": "NIST SP 800-57",
                "priority": "CRITICAL",
                "hybrid_option": "AES-256-GCM",
                "rationale": "DES and 3DES are deprecated and should be removed immediately.",
            })

        score = min(score, 100.0)

        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 60:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        elif score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        if has_pqc_dh and not has_legacy:
            pqc_status = "PQC_READY"
        elif has_pqc_dh:
            pqc_status = "HYBRID_PQC"
        elif score >= 80:
            pqc_status = "CRITICAL"
        else:
            pqc_status = "MIGRATION_NEEDED"

        return pqc_status, round(score, 1), risk_level, recommendations

    def _assess_tls_vpn_pqc(
        self,
        tls_version: Optional[str],
        cipher_name: str,
        cipher_bits: Optional[int],
    ):
        """
        Score a TLS-based VPN endpoint against PQC criteria.
        Returns (pqc_status, risk_score, risk_level, recommendations).
        """
        score = 0.0
        recommendations = []
        has_pqc = _is_pqc_tls_cipher(cipher_name)

        # TLS version risk
        tls_risk = {
            "TLSv1.3": 0,
            "TLSv1.2": 15,
            "TLSv1.1": 40,
            "TLSv1.0": 50,
            "SSLv3": 70,
        }
        score += tls_risk.get(tls_version or "", 20)

        if tls_version in ("TLSv1.0", "TLSv1.1", "SSLv3"):
            recommendations.append({
                "component": "TLS Protocol",
                "current": tls_version,
                "recommended": "TLS 1.3",
                "nist_standard": "NIST SP 800-52r2",
                "priority": "CRITICAL",
                "hybrid_option": "TLS 1.3",
                "rationale": f"{tls_version} is deprecated and insecure.",
            })
        elif tls_version == "TLSv1.2":
            recommendations.append({
                "component": "TLS Protocol",
                "current": "TLS 1.2",
                "recommended": "TLS 1.3",
                "nist_standard": "NIST SP 800-52r2",
                "priority": "HIGH",
                "hybrid_option": "TLS 1.3",
                "rationale": "TLS 1.3 is required for PQC hybrid key exchange.",
            })

        # Key exchange (inferred from cipher)
        if not has_pqc:
            score += 35
            recommendations.append({
                "component": "Key Exchange",
                "current": "ECDHE (classical)",
                "recommended": "ML-KEM-768 (Kyber) hybrid",
                "nist_standard": "FIPS 203",
                "priority": "HIGH",
                "hybrid_option": "X25519+ML-KEM-768",
                "rationale": (
                    "ECDHE is vulnerable to Shor's algorithm. "
                    "Upgrade VPN gateway to support TLS hybrid PQC key exchange."
                ),
            })

        # Cipher strength
        if cipher_bits and cipher_bits < 256:
            score += 10

        score = min(score, 100.0)

        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 60:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        elif score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        if has_pqc and score < 20:
            pqc_status = "PQC_READY"
        elif has_pqc:
            pqc_status = "HYBRID_PQC"
        elif score >= 80:
            pqc_status = "CRITICAL"
        else:
            pqc_status = "MIGRATION_NEEDED"

        return pqc_status, round(score, 1), risk_level, recommendations

    # -----------------------------------------------------------------------
    # Narrative helpers
    # -----------------------------------------------------------------------

    def _ike_notes(self, encr_algos: List[str], dh_groups: List[str]) -> str:
        parts = []
        if encr_algos:
            parts.append(f"Encryption: {', '.join(encr_algos)}")
        if dh_groups:
            parts.append(f"DH Groups: {', '.join(dh_groups)}")
        return ". ".join(parts) if parts else "IKEv2 endpoint detected (no SA detail parsed)."

    def _tls_notes(self, tls_version: Optional[str], cipher_name: str) -> str:
        return f"TLS {tls_version or 'UNKNOWN'} — {cipher_name}"
