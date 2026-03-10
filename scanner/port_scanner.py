"""
QScan — Port Scanner Module

Identifies open ports with TLS-enabled services on target hosts.
Uses socket-based probing with concurrent execution.
"""

import socket
import ssl
import concurrent.futures
from typing import List, Dict

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


class PortScanner:
    """Scans target hosts for open TLS-enabled ports."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def scan(self, host: str, ports: List[int] = None) -> List[int]:
        """
        Scan a host for open ports from the configured port list.

        Args:
            host: Target hostname or IP address
            ports: Optional list of ports to scan (uses settings default if None)

        Returns:
            List of open port numbers
        """
        ports = ports or self.settings.target_ports
        open_ports = []

        logger.debug(f"Scanning {host} on {len(ports)} ports")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.settings.max_threads
        ) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"  Port {port} scan error: {e}")

        return sorted(open_ports)

    def scan_detailed(self, host: str, ports: List[int] = None) -> List[Dict]:
        """
        Scan ports with detailed info (service detection, TLS support).

        Returns:
            List of dicts with port details
        """
        ports = ports or self.settings.target_ports
        results = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.settings.max_threads
        ) as executor:
            futures = {
                executor.submit(self._detailed_check, host, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"  Port {port} detailed scan error: {e}")

        return sorted(results, key=lambda x: x["port"])

    def _check_port(self, host: str, port: int) -> bool:
        """Check if a port is open via TCP connection."""
        try:
            with socket.create_connection(
                (host, port), timeout=self.settings.timeout
            ) as sock:
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _detailed_check(self, host: str, port: int) -> Dict:
        """Check port with TLS detection and basic service identification."""
        result = None

        try:
            with socket.create_connection(
                (host, port), timeout=self.settings.timeout
            ) as sock:
                result = {
                    "host": host,
                    "port": port,
                    "state": "open",
                    "tls_enabled": False,
                    "service": self._guess_service(port),
                    "banner": None,
                }

                # Try TLS handshake
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with context.wrap_socket(
                        sock, server_hostname=host
                    ) as tls_sock:
                        result["tls_enabled"] = True
                        result["tls_version"] = tls_sock.version()

                        cipher = tls_sock.cipher()
                        if cipher:
                            result["cipher"] = cipher[0]
                            result["cipher_bits"] = cipher[2]

                except ssl.SSLError:
                    # Port is open but doesn't speak TLS
                    result["tls_enabled"] = False
                except Exception:
                    pass

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return result

    def _guess_service(self, port: int) -> str:
        """Guess the service name based on port number."""
        service_map = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            389: "LDAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP-STARTTLS",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            989: "FTPS-DATA",
            990: "FTPS",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5061: "SIP-TLS",
            5432: "PostgreSQL",
            5671: "AMQPS",
            6379: "Redis",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
            9443: "HTTPS-ALT",
        }
        return service_map.get(port, "UNKNOWN")
