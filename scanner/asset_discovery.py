"""
QScan — Asset Discovery Module

Discovers public-facing assets for a target domain using:
  - DNS subdomain enumeration
  - Certificate Transparency (CT) log parsing
  - DNS record resolution
"""

import socket
import ssl
import json
import concurrent.futures
from typing import List, Dict, Optional

import dns.resolver
import dns.exception
import requests

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)


class AssetDiscovery:
    """Discovers subdomains and public-facing assets for a given domain."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = settings.dns_resolvers
        self.resolver.timeout = settings.timeout
        self.resolver.lifetime = settings.timeout

    def discover(self, domain: str) -> List[str]:
        """
        Run full asset discovery pipeline for a domain.

        Returns a list of discovered subdomains/hosts.
        """
        logger.info(f"Starting asset discovery for: {domain}")
        discovered = set()

        # 1. Subdomain brute-force via DNS
        dns_results = self._dns_bruteforce(domain)
        discovered.update(dns_results)
        logger.info(f"  DNS bruteforce: found {len(dns_results)} subdomains")

        # 2. Certificate Transparency logs
        ct_results = self._ct_log_search(domain)
        discovered.update(ct_results)
        logger.info(f"  CT log search: found {len(ct_results)} subdomains")

        # 3. Common DNS records (MX, NS, SRV, etc.)
        record_results = self._dns_record_enum(domain)
        discovered.update(record_results)
        logger.info(f"  DNS records: found {len(record_results)} hosts")

        # Remove the base domain itself from results
        discovered.discard(domain)

        logger.info(f"  Total unique assets discovered: {len(discovered)}")
        return list(discovered)

    def _dns_bruteforce(self, domain: str) -> List[str]:
        """Enumerate subdomains using wordlist-based DNS resolution."""
        found = []

        def resolve_subdomain(subdomain_prefix: str) -> Optional[str]:
            fqdn = f"{subdomain_prefix}.{domain}"
            try:
                answers = self.resolver.resolve(fqdn, "A")
                if answers:
                    return fqdn
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.LifetimeTimeout,
                Exception,
            ):
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.settings.max_threads
        ) as executor:
            futures = {
                executor.submit(resolve_subdomain, prefix): prefix
                for prefix in self.settings.subdomain_wordlist
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    logger.debug(f"    ✓ Found: {result}")

        return found

    def _ct_log_search(self, domain: str) -> List[str]:
        """
        Search Certificate Transparency logs via crt.sh API.

        CT logs contain records of all publicly issued TLS certificates,
        which reveals subdomains that have been issued certificates.
        """
        found = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.settings.timeout)

            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name_value = cert.get("name_value", "")
                    # CT logs can contain wildcard entries and multiple names
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]  # Remove wildcard prefix
                        if name.endswith(domain) and name != domain:
                            found.append(name)

                found = list(set(found))  # Deduplicate

        except requests.RequestException as e:
            logger.warning(f"  CT log search failed: {e}")
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"  CT log response parse error: {e}")

        return found

    def _dns_record_enum(self, domain: str) -> List[str]:
        """Extract hostnames from MX, NS, SRV, and CNAME records."""
        found = []
        record_types = ["MX", "NS", "CNAME", "SRV", "TXT"]

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                for answer in answers:
                    hostname = None

                    if rtype == "MX":
                        hostname = str(answer.exchange).rstrip(".")
                    elif rtype in ("NS", "CNAME"):
                        hostname = str(answer.target).rstrip(".")
                    elif rtype == "SRV":
                        hostname = str(answer.target).rstrip(".")
                    elif rtype == "TXT":
                        # Look for SPF, DMARC records that reference domains
                        txt_data = str(answer)
                        # Could parse SPF includes here if needed
                        continue

                    if hostname and hostname.endswith(domain):
                        found.append(hostname)

            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.LifetimeTimeout,
                Exception,
            ):
                pass

        return list(set(found))

    def get_asset_details(self, host: str) -> Dict:
        """Get IP address and basic info for a discovered host."""
        details = {"hostname": host, "ip_addresses": [], "has_tls": False}

        try:
            # Resolve IP addresses
            answers = self.resolver.resolve(host, "A")
            details["ip_addresses"] = [str(a) for a in answers]
        except Exception:
            pass

        # Quick TLS check on port 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (host, 443), timeout=self.settings.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    details["has_tls"] = True
        except Exception:
            pass

        return details
