"""
QScan — Quantum Readiness Assessment Platform
Main CLI Entry Point

Usage:
    python main.py --domain <target_domain> [--discover] [--cbom] [--output <path>]
"""

import argparse
import sys
import json
import os
from datetime import datetime

from config.settings import Settings
from scanner.asset_discovery import AssetDiscovery
from scanner.tls_scanner import TLSScanner
from scanner.port_scanner import PortScanner
from crypto.cipher_parser import CipherParser
from crypto.pqc_classifier import PQCClassifier
from cbom.cbom_generator import CBOMGenerator
from utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="qscan",
        description="QScan — Quantum Readiness Assessment Platform for Banking Infrastructure",
        epilog="Example: python main.py --domain example.com --discover --cbom",
    )

    parser.add_argument(
        "--domain",
        type=str,
        required=True,
        help="Target domain to scan (e.g., example.com)",
    )

    parser.add_argument(
        "--discover",
        action="store_true",
        default=False,
        help="Enable asset discovery (subdomain enumeration)",
    )

    parser.add_argument(
        "--cbom",
        action="store_true",
        default=False,
        help="Generate Cryptographic Bill of Materials (CBOM)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory for results (default: ./results/<domain>)",
    )

    parser.add_argument(
        "--ports",
        type=str,
        default="443,8443,8080,993,995,465,587",
        help="Comma-separated list of ports to scan (default: common TLS ports)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent scanning threads (default: 10)",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )

    return parser.parse_args()


def banner():
    """Display QScan banner."""
    print(
        r"""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     ██████  ███████  ██████  █████  ███    ██         ║
    ║    ██    ██ ██      ██      ██   ██ ████   ██         ║
    ║    ██    ██ ███████ ██      ███████ ██ ██  ██         ║
    ║    ██ ▄▄ ██      ██ ██      ██   ██ ██  ██ ██         ║
    ║     ██████  ███████  ██████ ██   ██ ██   ████         ║
    ║        ▀▀                                             ║
    ║   Quantum Readiness Assessment Platform               ║
    ║   v1.0.0 — PNB Cybersecurity Hackathon 2025           ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    )


def run_pipeline(args):
    """Execute the QScan scanning pipeline."""
    settings = Settings(
        timeout=args.timeout,
        max_threads=args.threads,
        target_ports=[int(p.strip()) for p in args.ports.split(",")],
    )

    domain = args.domain
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or os.path.join("results", f"{domain}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    all_scan_results = []

    # ─── Phase 1: Asset Discovery ───────────────────────────────
    targets = [domain]

    if args.discover:
        logger.info(f"[Phase 1] Running asset discovery for: {domain}")
        discovery = AssetDiscovery(settings)
        discovered_assets = discovery.discover(domain)
        targets.extend(discovered_assets)
        targets = list(set(targets))  # deduplicate

        logger.info(f"  ✓ Discovered {len(targets)} unique targets")

        # Save discovery results
        discovery_output = os.path.join(output_dir, "discovered_assets.json")
        with open(discovery_output, "w") as f:
            json.dump(
                {"domain": domain, "targets": targets, "timestamp": timestamp},
                f,
                indent=2,
            )
    else:
        logger.info(f"[Phase 1] Skipping asset discovery — scanning {domain} only")

    # ─── Phase 2: Port Scanning ─────────────────────────────────
    logger.info(f"[Phase 2] Scanning ports on {len(targets)} target(s)")
    port_scanner = PortScanner(settings)
    port_results = {}

    for target in targets:
        open_ports = port_scanner.scan(target)
        if open_ports:
            port_results[target] = open_ports
            logger.info(f"  ✓ {target}: {len(open_ports)} open port(s) — {open_ports}")

    # ─── Phase 3: TLS Scanning ──────────────────────────────────
    logger.info(f"[Phase 3] Running TLS analysis")
    tls_scanner = TLSScanner(settings)

    for target, ports in port_results.items():
        for port in ports:
            logger.info(f"  → Scanning {target}:{port}")
            tls_result = tls_scanner.scan(target, port)
            if tls_result:
                all_scan_results.append(tls_result)

    if not all_scan_results:
        # If port scanning returned nothing, try default HTTPS
        logger.info(f"  → Attempting default HTTPS scan on {domain}:443")
        tls_result = tls_scanner.scan(domain, 443)
        if tls_result:
            all_scan_results.append(tls_result)

    # ─── Phase 4: Cryptographic Parsing ─────────────────────────
    logger.info(f"[Phase 4] Parsing cryptographic configurations")
    cipher_parser = CipherParser()
    pqc_classifier = PQCClassifier()

    parsed_results = []
    for result in all_scan_results:
        parsed = cipher_parser.parse(result)
        classified = pqc_classifier.classify(parsed)
        parsed_results.append(classified)
        
        status = classified.get("pqc_status", "UNKNOWN")
        risk = classified.get("quantum_risk_level", "UNKNOWN")
        logger.info(f"  ✓ {classified['host']}:{classified['port']} — PQC: {status} | Risk: {risk}")

    # ─── Phase 5: CBOM Generation ───────────────────────────────
    if args.cbom or True:  # Always generate CBOM
        logger.info(f"[Phase 5] Generating Cryptographic Bill of Materials (CBOM)")
        cbom_generator = CBOMGenerator()
        cbom = cbom_generator.generate(
            domain=domain,
            scan_results=parsed_results,
            timestamp=timestamp,
        )

        cbom_output = os.path.join(output_dir, "cbom.json")
        with open(cbom_output, "w") as f:
            json.dump(cbom, f, indent=2)
        logger.info(f"  ✓ CBOM saved to: {cbom_output}")

    # ─── Save Full Results ──────────────────────────────────────
    full_output = os.path.join(output_dir, "scan_results.json")
    with open(full_output, "w") as f:
        json.dump(parsed_results, f, indent=2, default=str)
    logger.info(f"  ✓ Full results saved to: {full_output}")

    # ─── Summary ────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Domain:          {domain}")
    print(f"  Targets Scanned: {len(targets)}")
    print(f"  Assets Analyzed: {len(parsed_results)}")
    print(f"  Output:          {output_dir}")

    # Risk summary
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for r in parsed_results:
        level = r.get("quantum_risk_level", "UNKNOWN")
        if level in risk_counts:
            risk_counts[level] += 1

    print(f"\n  Quantum Risk Breakdown:")
    for level, count in risk_counts.items():
        if count > 0:
            print(f"    {level:10s}: {count}")

    pqc_ready = sum(1 for r in parsed_results if r.get("pqc_status") == "PQC_READY")
    print(f"\n  PQC Ready:       {pqc_ready}/{len(parsed_results)}")
    print("=" * 60 + "\n")


def main():
    """Main entry point."""
    banner()
    args = parse_arguments()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logger(level=log_level)

    logger.info(f"Starting QScan for domain: {args.domain}")

    try:
        run_pipeline(args)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
