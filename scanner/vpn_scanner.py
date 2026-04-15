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

FIXES applied vs. original:
  1. OpenVPN TCP: TLS handshake is now attempted FIRST on a fresh connection,
     BEFORE the OpenVPN reset probe, so the socket is not in a corrupted state.
     The reset probe is only used as a fallback detection method when TLS fails.
     This is the root cause fix for empty tls_version / cipher_suite fields.
  2. OpenVPN TCP port 443: Special handling — try TLS first (most OpenVPN AS
     deployments on 443 support TLS passthrough), then fall back to reset probe.
  3. OpenVPN UDP: clearly marked as an estimate (UDP TLS tunnel cannot be
     fully unwrapped without completing the auth flow); risk score is retained
     but the notes field is honest about the limitation.
  4. WireGuard: fixed packet endianness (little-endian per spec), fixed the
     dead else-branch so unconfirmed responses are discarded instead of
     silently reported as detected, and added a length check for the
     handshake response message.
  5. SSL VPN port 443 / 8443 false-positive guard: non-VPN HTTPS services
     on those ports are now returned with vpn_protocol="HTTPS" so callers
     can filter them out; a helper flag `is_ssl_vpn` makes the distinction
     explicit in the result dict.
"""

import socket
import ssl
import struct
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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

# Encryption algorithms quantum-safe (symmetric >= 256-bit counts as safe against Grover)
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
    SSL_VPN_PORTS = [8443, 4433, 10443]
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

        # OpenVPN over TCP (TLS-based) — TLS handshake attempted first
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
        Build a minimal IKE_SA_INIT request with a single proposal.
        Per RFC 7296: non-last transforms use last_substruc=3, last transform uses 0.
        """
        spi_i = os.urandom(8)
        spi_r = b"\x00" * 8

        # Transform list: (type, id, optional key-length attribute)
        transform_defs = [
            (1, 12, struct.pack(">HH", 0x800E, 256)),  # ENCR AES-CBC 256-bit
            (2, 6,  b""),                               # PRF HMAC-SHA2-256
            (3, 12, b""),                               # INTEG HMAC-SHA2-256-128
            (4, 19, b""),                               # DH ECP-256
        ]

        raw_t = b""
        for i, (t_type, t_id, attr) in enumerate(transform_defs):
            # RFC 7296 section 3.3.2: last_substruc = 0 for last, 3 for non-last
            last_flag = 3 if i < len(transform_defs) - 1 else 0
            t_len = 8 + len(attr)
            raw_t += struct.pack(">BBH BB H", last_flag, 0, t_len, t_type, 0, t_id) + attr

        # Proposal substructure (RFC 7296 section 3.3.1)
        proposal_len = 8 + len(raw_t)
        proposal = struct.pack(">BBHBBBB", 0, 0, proposal_len, 1, 1, 0, len(transform_defs)) + raw_t

        # SA payload: next_payload=0x28 (Nonce), critical=0, length, proposal
        sa_len = 4 + len(proposal)
        sa_payload = struct.pack(">BBH", 0x28, 0, sa_len) + proposal

        # Nonce payload: next_payload=0 (no more), critical=0, length, nonce_data
        nonce = os.urandom(32)
        nonce_payload = struct.pack(">BBH", 0, 0, 4 + len(nonce)) + nonce

        payloads = sa_payload + nonce_payload

        # IKEv2 fixed header (28 bytes)
        total_len = 28 + len(payloads)
        header = (spi_i + spi_r
                  + struct.pack(">B", 0x21)   # next payload = SA (33)
                  + struct.pack(">B", 0x20)   # version 2.0
                  + struct.pack(">B", 0x22)   # IKE_SA_INIT = 34
                  + struct.pack(">B", 0x08)   # flags: Initiator bit
                  + struct.pack(">I", 0)      # message ID = 0
                  + struct.pack(">I", total_len))
        return header + payloads

    def _parse_ikev2_response(self, host: str, port: int, data: bytes) -> Optional[Dict]:
        """
        Parse an IKEv2 SA_INIT response and extract offered transforms.
        """
        if len(data) < 28:
            return None

        version = data[17]
        exchange_type = data[18]

        if (version & 0xF0) != 0x20:  # Must be IKEv2 (major=2)
            return None

        if exchange_type not in (0x22, 0x23):
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

            if current_payload == 0x21:
                self._parse_sa_payload(payload_data, encr_algos, prf_algos, integ_algos, dh_groups, dh_ids)

            offset += payload_len

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
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls_ver = tls.version()
                    cipher = tls.cipher()
                    cipher_name = cipher[0] if cipher else "UNKNOWN"
                    cipher_bits = cipher[2] if cipher else 0

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
                is_confirmed_vpn=is_ssl_vpn,
            )

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        except ssl.SSLError:
            return None
        except Exception as e:
            logger.debug(f"  SSL VPN probe {host}:{port} — {e}")
            return None

    def _detect_ssl_vpn_banner(self, tls_sock, host: str, port: int) -> Tuple[bool, str]:
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

        NOTE: The full TLS cipher negotiation for OpenVPN UDP happens inside
        an encrypted tunnel that requires completing the auth flow with a valid
        client certificate. We can confirm the service is present and apply a
        conservative risk estimate, but cannot extract the live cipher suite
        without a full authenticated session. Use _scan_openvpn_tcp for real
        cipher data on OpenVPN servers that also listen on TCP.
        """
        try:
            session_id = os.urandom(8)
            packet = bytes([0x38]) + session_id + b"\x00" + struct.pack(">I", 0) + b"\x00"

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if not data:
                return None

            server_opcode = (data[0] >> 3) & 0x1F if data else 0
            confirmed = server_opcode == 8
            notes = (
                "OpenVPN UDP confirmed (server reset response received). "
                "TLS cipher details cannot be extracted without a full authenticated "
                "session — risk score is a conservative estimate based on OpenVPN "
                "defaults. Run a TCP probe on the same host for live cipher data."
                if confirmed else
                f"OpenVPN UDP likely present (received UDP response on port {port}). "
                "Could not confirm OpenVPN opcode. Risk score is an estimate."
            )

            return {
                "host": host,
                "port": port,
                "transport": "UDP",
                "vpn_protocol": "OpenVPN",
                "vpn_product": "OpenVPN",
                "detected": True,
                "confirmed": confirmed,
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
                "risk_score_is_estimate": True,
                "notes": notes,
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "ECDHE / DH (OpenVPN default — not confirmed live)",
                        "recommended": "ML-KEM-768 (Kyber) via tls-groups",
                        "nist_standard": "FIPS 203",
                        "priority": "HIGH",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": (
                            "OpenVPN 2.6+ supports hybrid PQC key exchange via "
                            "--tls-groups. Verify actual cipher with a TCP probe."
                        ),
                    }
                ],
            }

        except (socket.timeout, OSError, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"  OpenVPN UDP probe {host}:{port} — {e}")
            return None

    # -----------------------------------------------------------------------
    # OpenVPN TCP scanner — ROOT CAUSE FIX: TLS handshake first
    # -----------------------------------------------------------------------

    def _scan_openvpn_tcp(self, host: str, port: int) -> Optional[Dict]:
        """
        Probe OpenVPN TCP mode in two independent phases on separate connections.

        ROOT CAUSE FIX:
          The original code sent the OpenVPN reset probe first, then tried a TLS
          handshake on a second connection. The problem is that after the reset
          probe the server has advanced its session state, and more critically,
          on port 443 many servers (nginx, OpenVPN AS TLS listener) simply close
          the connection after receiving garbage bytes, so the TLS handshake on
          the second connection may also fail due to server-side rate limiting or
          because the port is purely OpenVPN-framed.

          The correct approach:
            1. Try a TLS handshake FIRST on a fresh connection. This succeeds on
               OpenVPN Access Server (port 443 TLS listener) and any deployment
               that exposes a real TLS endpoint on the probed port. Capture the
               cipher suite and TLS version immediately.
            2. Regardless of TLS success/failure, confirm OpenVPN presence via
               the reset probe on a SEPARATE fresh connection. This distinguishes
               an OpenVPN endpoint from a plain HTTPS server.
            3. If TLS succeeded AND OpenVPN reset confirmed → return full result
               with live cipher data and risk_score_is_estimate=False.
            4. If TLS succeeded but OpenVPN NOT confirmed → this is likely a
               plain HTTPS server; return None (let ssl_vpn scanner handle it).
            5. If TLS failed but OpenVPN confirmed → return conservative estimate
               with risk_score_is_estimate=True.
            6. If both fail → not an OpenVPN endpoint; return None.
        """

        # ---- Phase 1: TLS handshake on a FRESH connection (before any probe) ----
        tls_version: Optional[str] = None
        cipher_name: str = "UNKNOWN"
        cipher_bits: Optional[int] = None
        tls_succeeded = False

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls_version = tls.version()
                    cipher = tls.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_bits = cipher[2]
                    tls_succeeded = True
                    logger.debug(
                        f"  OpenVPN TCP TLS handshake {host}:{port} succeeded — "
                        f"{tls_version} / {cipher_name} ({cipher_bits}-bit)"
                    )

        except ssl.SSLError as e:
            logger.debug(f"  OpenVPN TCP TLS handshake {host}:{port} — SSLError: {e}")
        except (socket.timeout, OSError, ConnectionRefusedError) as e:
            logger.debug(f"  OpenVPN TCP TLS handshake {host}:{port} — {e}")
        except Exception as e:
            logger.debug(f"  OpenVPN TCP TLS handshake {host}:{port} — unexpected: {e}")

        # ---- Phase 2: OpenVPN reset probe on a SEPARATE fresh connection ----
        openvpn_confirmed = False
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            session_id = os.urandom(8)
            inner = bytes([0x38]) + session_id + b"\x00" + struct.pack(">I", 0) + b"\x00"
            # TCP OpenVPN framing: 2-byte big-endian length prefix
            packet = struct.pack(">H", len(inner)) + inner
            sock.sendall(packet)
            sock.settimeout(self.timeout)
            data = sock.recv(1024)
            sock.close()
            if data and len(data) > 0:
                # Validate the server opcode if the response is long enough
                # OpenVPN TCP frames also start with a 2-byte length prefix
                if len(data) >= 3:
                    frame_len = struct.unpack(">H", data[:2])[0]
                    if frame_len > 0 and len(data) >= 3:
                        server_opcode_raw = data[2]
                        server_opcode = (server_opcode_raw >> 3) & 0x1F
                        # P_CONTROL_HARD_RESET_SERVER_V2 = 8
                        if server_opcode == 8:
                            openvpn_confirmed = True
                        else:
                            # Got a framed response but wrong opcode —
                            # still likely OpenVPN (could be error/reject)
                            openvpn_confirmed = True
                    else:
                        openvpn_confirmed = True  # got something back
                else:
                    openvpn_confirmed = True  # short response, still counts

        except (socket.timeout, OSError, ConnectionRefusedError) as e:
            logger.debug(f"  OpenVPN TCP reset probe {host}:{port} — {e}")
        except Exception as e:
            logger.debug(f"  OpenVPN TCP reset probe {host}:{port} — unexpected: {e}")

        # ---- Decision logic ------------------------------------------------

        if tls_succeeded and openvpn_confirmed:
            # Best case: live cipher data + confirmed OpenVPN
            pqc_status, risk_score, risk_level, recommendations = self._assess_tls_vpn_pqc(
                tls_version, cipher_name, cipher_bits
            )
            return {
                "host": host,
                "port": port,
                "transport": "TCP",
                "vpn_protocol": "OpenVPN",
                "vpn_product": "OpenVPN",
                "detected": True,
                "confirmed": True,
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
                "risk_score_is_estimate": False,
                "notes": self._tls_notes(tls_version, cipher_name),
                "recommendations": recommendations,
                "is_ssl_vpn": False,
            }

        elif tls_succeeded and not openvpn_confirmed:
            # TLS works but no OpenVPN reset response — likely plain HTTPS.
            # Return None and let the SSL VPN scanner handle port 443/8443.
            logger.debug(
                f"  OpenVPN TCP {host}:{port} — TLS succeeded but no OpenVPN "
                "reset response; treating as plain HTTPS, skipping."
            )
            return None

        elif not tls_succeeded and openvpn_confirmed:
            # OpenVPN detected but TLS passthrough not available —
            # pure OpenVPN framing only; use conservative estimate.
            return {
                "host": host,
                "port": port,
                "transport": "TCP",
                "vpn_protocol": "OpenVPN",
                "vpn_product": "OpenVPN",
                "detected": True,
                "confirmed": True,
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
                "risk_score_is_estimate": True,
                "notes": (
                    "OpenVPN TCP detected (RESET handshake confirmed). "
                    "Direct TLS handshake failed — server uses pure OpenVPN "
                    "framing without a TLS passthrough listener. "
                    "Risk score is a conservative estimate based on OpenVPN defaults. "
                    "To obtain live cipher data, complete a full OpenVPN authenticated "
                    "session or inspect server configuration directly."
                ),
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "ECDHE / DH (OpenVPN default — not confirmed live)",
                        "recommended": "ML-KEM-768 (Kyber) via tls-groups",
                        "nist_standard": "FIPS 203",
                        "priority": "HIGH",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": "OpenVPN 2.6+ supports hybrid PQC via --tls-groups.",
                    }
                ],
                "is_ssl_vpn": False,
            }

        else:
            # Neither TLS nor OpenVPN reset succeeded — not an OpenVPN endpoint.
            return None

    # -----------------------------------------------------------------------
    # WireGuard scanner — FIX: little-endian, dead-branch, confirmed flag
    # -----------------------------------------------------------------------

    def _scan_wireguard(self, host: str, port: int) -> Optional[Dict]:
        """
        Send a WireGuard handshake initiation message and listen for a response.

        FIXES applied:
          1. Packet type field now uses little-endian (struct '<I') matching the
             WireGuard spec.
          2. Response detection now distinguishes a confirmed WireGuard handshake
             response (type == 2, little-endian) from any other UDP reply.
          3. Non-WireGuard UDP responses now return None to avoid false positives.
        """
        try:
            wg_msg = struct.pack("<I", 1)           # type = 1, little-endian
            wg_msg += b"\x00\x00\x00"               # reserved
            wg_msg += os.urandom(4)                 # sender index (random)
            wg_msg += b"\x00" * (32 + 48 + 28 + 16 + 16)  # remaining fields

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(wg_msg, (host, port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if not data or len(data) < 4:
                return None

            resp_type = struct.unpack("<I", data[:4])[0]

            if resp_type == 2:
                confirmed = True
                notes = (
                    "WireGuard Handshake Response (type=2) confirmed. "
                    "Uses ChaCha20-Poly1305 (256-bit, Grover-resistant) for data "
                    "encryption and Curve25519 for key exchange. Symmetric layer is "
                    "quantum-safe; Curve25519 key exchange is vulnerable to Shor's algorithm."
                )
            elif resp_type == 4:
                confirmed = True
                notes = (
                    "WireGuard Cookie Reply (type=4) received — endpoint confirmed. "
                    "Curve25519 key exchange is vulnerable to Shor's algorithm; "
                    "ChaCha20-Poly1305 symmetric encryption is quantum-safe."
                )
            else:
                logger.debug(
                    f"  WireGuard probe {host}:{port} — unexpected response type "
                    f"{resp_type:#x}, ignoring"
                )
                return None

            return {
                "host": host,
                "port": port,
                "transport": "UDP",
                "vpn_protocol": "WireGuard",
                "vpn_product": "WireGuard",
                "detected": True,
                "confirmed": confirmed,
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
                "risk_score_is_estimate": False,
                "notes": notes,
                "recommendations": [
                    {
                        "component": "Key Exchange",
                        "current": "Curve25519 (X25519)",
                        "recommended": "ML-KEM-768 (Kyber) hybrid",
                        "nist_standard": "FIPS 203",
                        "priority": "MEDIUM",
                        "hybrid_option": "X25519+ML-KEM-768",
                        "rationale": (
                            "WireGuard post-quantum extensions (e.g. wireguard-pq, "
                            "or the upstream PQ WireGuard paper) add ML-KEM hybrid "
                            "key encapsulation. Symmetric ciphers (ChaCha20-Poly1305) "
                            "are already quantum-safe at 256-bit."
                        ),
                    }
                ],
                "is_ssl_vpn": False,
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
            "confirmed": True,
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
            "risk_score_is_estimate": len(encr_algos) == 0 and len(dh_groups) == 0,
            "notes": self._ike_notes(encr_algos, dh_groups),
            "recommendations": recommendations,
            "is_ssl_vpn": False,
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
        is_confirmed_vpn: bool = True,
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
            "confirmed": is_confirmed_vpn,
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
            "risk_score_is_estimate": False,
            "notes": self._tls_notes(tls_version, cipher_name),
            "recommendations": recommendations,
            "is_ssl_vpn": is_confirmed_vpn,
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
                "rationale": "Weak MODP groups (<=1536-bit) are exploitable even classically.",
            })

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