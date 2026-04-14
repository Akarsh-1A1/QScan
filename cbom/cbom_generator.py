"""
QScan - CBOM Generator Module
Generates a Cryptographic Bill of Materials (CBOM) in JSON format.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List

from utils.logger import get_logger

logger = get_logger(__name__)


class CBOMGenerator:
    """Generates a Cryptographic Bill of Materials from scan results."""

    CBOM_VERSION = "1.0"
    CBOM_SCHEMA = "https://qscan.github.io/cbom/schema/v1"

    def generate(self, domain: str, scan_results: List[Dict],
                 vpn_results: List[Dict] = None,
                 timestamp: str = None) -> Dict:

        timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        # --- SAFETY FIX ---
        scan_results = [r for r in scan_results if r]
        vpn_results = [r for r in (vpn_results or []) if r]

        cbom = {
            "cbom_version": self.CBOM_VERSION,
            "schema": self.CBOM_SCHEMA,
            "metadata": {
                "organization_domain": domain,
                "scan_timestamp": timestamp,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": "QScan Quantum Readiness Assessment Platform",
                "tool_version": "1.0.0",
                "total_assets_scanned": len(scan_results),
                "total_vpn_endpoints": len(vpn_results),
            },
            "summary": self._generate_summary(scan_results, vpn_results),
            "crypto_assets": [],
            "vpn_inventory": self._build_vpn_inventory(vpn_results),
            "risk_matrix": self._generate_risk_matrix(scan_results),
            "pqc_migration_plan": self._generate_migration_plan(scan_results, vpn_results),
        }

        for i, result in enumerate(scan_results):
            asset = self._build_asset_entry(result, index=i)
            cbom["crypto_assets"].append(asset)

        content_str = json.dumps(cbom, sort_keys=True, default=str)
        cbom["metadata"]["cbom_hash"] = hashlib.sha256(content_str.encode()).hexdigest()

        logger.info(
            f"CBOM generated: {len(cbom['crypto_assets'])} TLS assets, "
            f"{len(vpn_results)} VPN endpoints cataloged"
        )

        return cbom

    def _build_asset_entry(self, result: Dict, index: int) -> Dict:

        host = result.get("host", "unknown")
        port = result.get("port", 0)

        asset_id = f"ASSET-{index+1:04d}-{host.replace('.', '-')}-{port}"

        entry = {
            "asset_id": asset_id,
            "host": host,
            "port": port,
            "scan_timestamp": result.get("scan_timestamp"),
            "tls_configuration": {
                "protocol_version": result.get("tls_version"),
                "negotiated_cipher": result.get("cipher_suite"),
                "cipher_strength_bits": result.get("cipher_bits"),
                "supported_protocols": result.get("supported_protocols") or [],
                "key_exchange": result.get("key_exchange"),
            },
            "certificate_info": self._extract_cert_info(result),

            # --- SAFETY FIX ---
            "cipher_analysis": result.get("cipher_analysis") or {},
            "crypto_summary": result.get("crypto_summary") or {},

            "quantum_assessment": {
                "risk_score": result.get("quantum_risk_score", 0),
                "risk_level": result.get("quantum_risk_level", "UNKNOWN"),
                "pqc_status": result.get("pqc_status", "UNKNOWN"),
                "threat_assessment": result.get("quantum_threat_assessment") or {},
            },

            "hndl_risk": result.get("hndl_risk") or {},

            "recommendations": result.get("pqc_recommendations") or [],
        }

        return entry

    def _extract_cert_info(self, result: Dict) -> Dict:

        # --- SAFETY FIX ---
        cert = result.get("certificate") or {}
        chain = result.get("certificate_chain") or []

        return {
            "subject": cert.get("subject", {}),
            "issuer": cert.get("issuer", {}),
            "validity": {
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "days_until_expiry": cert.get("days_until_expiry"),
                "is_expired": cert.get("is_expired", False),
            },
            "fingerprint_sha256": cert.get("sha256_fingerprint"),
            "san": cert.get("san", []),
            "chain_length": len(chain),
            "chain_details": [
                {
                    "position": c.get("position"),
                    "subject": c.get("subject", {}),
                    "key_type": c.get("key_type"),
                    "key_bits": c.get("key_bits"),
                    "signature_algorithm": c.get("signature_algorithm"),
                }
                for c in chain
            ],
        }

    def _generate_summary(self, results: List[Dict], vpn_results: List[Dict] = None) -> Dict:

        total = len(results)

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        pqc_counts = {"PQC_READY": 0, "HYBRID_PQC": 0, "MIGRATION_NEEDED": 0, "CRITICAL": 0}

        with_fs = 0

        for r in results:

            level = r.get("quantum_risk_level", "UNKNOWN")

            if level in risk_counts:
                risk_counts[level] += 1

            status = r.get("pqc_status", "UNKNOWN")

            if status in pqc_counts:
                pqc_counts[status] += 1

            if (r.get("cipher_analysis") or {}).get("forward_secrecy"):
                with_fs += 1

        avg_risk = sum(r.get("quantum_risk_score", 0) for r in results) / max(total, 1)

        total_ciphers = 0
        weak_cipher_count = 0

        for r in results:

            summary = r.get("crypto_summary") or {}

            total_ciphers += summary.get("cipher_diversity", 0)

            weak_cipher_count += len(summary.get("weak_ciphers", []))

        return {
            "total_assets": total,
            "average_risk_score": round(avg_risk, 1),
            "risk_distribution": risk_counts,
            "pqc_status_distribution": pqc_counts,
            "forward_secrecy_adoption": f"{with_fs}/{total}",
            "cipher_surface": total_ciphers,
            "weak_cipher_exposure": weak_cipher_count,
            "overall_quantum_readiness": (
                "READY" if pqc_counts.get("PQC_READY", 0) == total
                else "PARTIAL" if pqc_counts.get("PQC_READY", 0) > 0
                else "NOT_READY"
            ),
            "vpn_endpoints": len(vpn_results or []),
            "vpn_pqc_ready": sum(
                1 for v in (vpn_results or []) if v.get("pqc_status") == "PQC_READY"
            ),
            "vpn_critical": sum(
                1 for v in (vpn_results or []) if v.get("quantum_risk_level") == "CRITICAL"
            ),
        }

    def _generate_risk_matrix(self, results: List[Dict]) -> List[Dict]:

        matrix = []

        for r in results:

            crypto_summary = r.get("crypto_summary") or {}
            threat = r.get("quantum_threat_assessment") or {}

            matrix.append({
                "host": r.get("host"),
                "port": r.get("port"),

                "risk_score": r.get("quantum_risk_score", 0),
                "risk_level": r.get("quantum_risk_level", "UNKNOWN"),

                "pqc_status": r.get("pqc_status", "UNKNOWN"),

                "cipher_diversity": crypto_summary.get("cipher_diversity", 0),
                "weak_ciphers": crypto_summary.get("weak_ciphers", []),

                "migration_deadline": threat.get("migration_deadline"),
                "urgency": threat.get("urgency"),
            })

        return sorted(matrix, key=lambda x: x["risk_score"], reverse=True)

    def _build_vpn_inventory(self, vpn_results: List[Dict]) -> List[Dict]:
        """Build a clean VPN inventory list for the CBOM."""
        inventory = []

        for v in (vpn_results or []):
            inventory.append({
                "host": v.get("host"),
                "port": v.get("port"),
                "transport": v.get("transport"),
                "vpn_protocol": v.get("vpn_protocol"),
                "vpn_product": v.get("vpn_product"),
                "scan_timestamp": v.get("scan_timestamp"),
                "tls_version": v.get("tls_version"),
                "cipher_suite": v.get("cipher_suite"),
                "cipher_bits": v.get("cipher_bits"),
                "encryption_algorithms": v.get("encryption_algorithms", []),
                "prf_algorithms": v.get("prf_algorithms", []),
                "integrity_algorithms": v.get("integrity_algorithms", []),
                "dh_groups": v.get("dh_groups", []),
                "quantum_assessment": {
                    "pqc_status": v.get("pqc_status", "UNKNOWN"),
                    "risk_level": v.get("quantum_risk_level", "UNKNOWN"),
                    "risk_score": v.get("quantum_risk_score", 0),
                },
                "notes": v.get("notes", ""),
                "recommendations": v.get("recommendations", []),
            })

        return inventory

    def _generate_migration_plan(self, results: List[Dict],
                                  vpn_results: List[Dict] = None) -> Dict:

        immediate, short_term, planned = [], [], []

        for r in results:

            host = r.get("host", "unknown")
            port = r.get("port", 0)

            for rec in r.get("pqc_recommendations") or []:

                item = {"host": host, "port": port, **rec}

                pri = rec.get("priority", "MEDIUM")

                if pri == "CRITICAL":
                    immediate.append(item)

                elif pri == "HIGH":
                    short_term.append(item)

                else:
                    planned.append(item)

        # Include VPN recommendations
        for v in (vpn_results or []):
            host = v.get("host", "unknown")
            port = v.get("port", 0)

            for rec in v.get("recommendations") or []:
                item = {"host": host, "port": port, "asset_type": "VPN", **rec}
                pri = rec.get("priority", "MEDIUM")

                if pri == "CRITICAL":
                    immediate.append(item)
                elif pri == "HIGH":
                    short_term.append(item)
                else:
                    planned.append(item)

        return {
            "immediate_actions": immediate,
            "short_term_actions": short_term,
            "planned_actions": planned,
            "total_recommendations": len(immediate) + len(short_term) + len(planned),
        }