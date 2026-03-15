"""
QScan — Quantum Readiness Assessment Platform
Main CLI Entry Point
"""

import argparse
import sys
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    parser = argparse.ArgumentParser(
        prog="qscan",
        description="QScan — Quantum Readiness Assessment Platform for Banking Infrastructure",
    )

    parser.add_argument("--domain", type=str, required=True)
    parser.add_argument("--discover", action="store_true", default=False)
    parser.add_argument("--cbom", action="store_true", default=False)
    parser.add_argument("--output", type=str, default=None)

    parser.add_argument(
        "--ports",
        type=str,
        default="443,8443,8080,993,995,465,587",
    )

    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--verbose", action="store_true", default=False)

    return parser.parse_args()


def banner():
    print(
        r"""
╔═══════════════════════════════════════════════════════╗
║   QScan — Quantum Readiness Assessment Platform       ║
║   v1.0.0 — PNB Cybersecurity Hackathon 2025           ║
╚═══════════════════════════════════════════════════════╝
"""
    )


def run_pipeline(args):

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

    # ─────────────────────────────────────────────
    # Phase 1 — Asset Discovery
    # ─────────────────────────────────────────────

    targets = [domain]

    if args.discover:

        logger.info(f"[Phase 1] Running asset discovery for: {domain}")

        discovery = AssetDiscovery(settings)

        discovered_assets = discovery.discover(domain)

        targets.extend(discovered_assets)

        targets = list(set(targets))

        logger.info(f"  ✓ Discovered {len(targets)} unique targets")

        with open(os.path.join(output_dir, "discovered_assets.json"), "w") as f:
            json.dump(
                {"domain": domain, "targets": targets, "timestamp": timestamp},
                f,
                indent=2,
            )

    else:
        logger.info(f"[Phase 1] Skipping asset discovery — scanning {domain} only")

    # ─────────────────────────────────────────────
    # Phase 2 — Port Scanning (PARALLEL)
    # ─────────────────────────────────────────────

    logger.info(f"[Phase 2] Scanning ports on {len(targets)} target(s)")

    port_scanner = PortScanner(settings)

    port_results = {}

    with ThreadPoolExecutor(max_workers=settings.max_threads) as executor:

        future_map = {
            executor.submit(port_scanner.scan, target): target for target in targets
        }

        for future in as_completed(future_map):

            target = future_map[future]

            try:
                open_ports = future.result()

                if open_ports:
                    port_results[target] = open_ports

                    logger.info(
                        f"  ✓ {target}: {len(open_ports)} open port(s) — {open_ports}"
                    )

            except Exception as e:
                logger.warning(f"Port scan failed for {target}: {e}")

    # ─────────────────────────────────────────────
    # Phase 3 — TLS Scanning (PARALLEL)
    # ─────────────────────────────────────────────

    logger.info(f"[Phase 3] Running TLS analysis")

    tls_scanner = TLSScanner(settings)

    scanned_hosts = set()

    scan_jobs = []

    for target, ports in port_results.items():
        for port in ports:
            if (target, port) not in scanned_hosts:
                scan_jobs.append((target, port))

    with ThreadPoolExecutor(max_workers=settings.max_threads) as executor:

        future_map = {
            executor.submit(tls_scanner.scan, host, port): (host, port)
            for host, port in scan_jobs
        }

        for future in as_completed(future_map):

            host, port = future_map[future]

            try:
                tls_result = future.result()

                if tls_result:

                    logger.info(f"  ✓ TLS {host}:{port}")

                    all_scan_results.append(tls_result)

                    scanned_hosts.add((host, port))

                    # SAN discovery

                    san_assets = tls_result.get("discovered_san_assets", [])

                    for san in san_assets:

                        if san not in targets:

                            logger.info(f"  ↳ SAN discovered: {san}")

                            targets.append(san)

                            open_ports = port_scanner.scan(san)

                            if open_ports:

                                for p in open_ports:

                                    if (san, p) not in scanned_hosts:

                                        logger.info(f"    → Scanning SAN {san}:{p}")

                                        san_result = tls_scanner.scan(san, p)

                                        if san_result:
                                            all_scan_results.append(san_result)

                                            scanned_hosts.add((san, p))

            except Exception as e:
                logger.warning(f"TLS scan failed for {host}:{port}: {e}")

    # fallback scan

    if not all_scan_results:

        logger.info(f"  → Attempting default HTTPS scan on {domain}:443")

        tls_result = tls_scanner.scan(domain, 443)

        if tls_result:
            all_scan_results.append(tls_result)

    # ─────────────────────────────────────────────
    # Phase 4 — Crypto Parsing
    # ─────────────────────────────────────────────

    logger.info(f"[Phase 4] Parsing cryptographic configurations")

    cipher_parser = CipherParser()

    pqc_classifier = PQCClassifier()

    parsed_results = []

    for result in all_scan_results:

        try:
            parsed = cipher_parser.parse(result)
            classified = pqc_classifier.classify(parsed)
            parsed_results.append(classified)

        except Exception as e:
            logger.warning(
                f"Crypto parsing failed for {result.get('host')}:{result.get('port')} — {e}"
            )

        status = classified.get("pqc_status", "UNKNOWN")

        risk = classified.get("quantum_risk_level", "UNKNOWN")

        logger.info(
            f"  ✓ {classified['host']}:{classified['port']} — PQC: {status} | Risk: {risk}"
        )

    # ─────────────────────────────────────────────
    # Phase 5 — CBOM Generation
    # ─────────────────────────────────────────────

    logger.info(f"[Phase 5] Generating Cryptographic Bill of Materials (CBOM)")

    cbom_generator = CBOMGenerator()

    cbom = cbom_generator.generate(
        domain=domain,
        scan_results=parsed_results,
        timestamp=timestamp,
    )

    with open(os.path.join(output_dir, "cbom.json"), "w") as f:
        json.dump(cbom, f, indent=2)

    logger.info(f"  ✓ CBOM saved")

    with open(os.path.join(output_dir, "scan_results.json"), "w") as f:
        json.dump(parsed_results, f, indent=2, default=str)

    logger.info(f"  ✓ Full results saved")

    # ─────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────

    print("\n" + "=" * 60)

    print("SCAN SUMMARY")

    print("=" * 60)

    print(f"Domain:          {domain}")
    print(f"Targets Scanned: {len(targets)}")
    print(f"Assets Analyzed: {len(parsed_results)}")

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}

    for r in parsed_results:

        level = r.get("quantum_risk_level")

        if level in risk_counts:
            risk_counts[level] += 1

    print("\nQuantum Risk Breakdown:")

    for level, count in risk_counts.items():

        if count > 0:
            print(f"{level:10s}: {count}")

    pqc_ready = sum(1 for r in parsed_results if r.get("pqc_status") == "PQC_READY")

    print(f"\nPQC Ready: {pqc_ready}/{len(parsed_results)}")

    print("=" * 60 + "\n")


def main():

    banner()

    args = parse_arguments()

    log_level = "DEBUG" if args.verbose else "INFO"

    setup_logger(level=log_level)

    logger.info(f"Starting QScan for domain: {args.domain}")

    try:
        run_pipeline(args)

    except KeyboardInterrupt:

        logger.warning("Scan interrupted")

        sys.exit(1)

    except Exception as e:

        logger.error(f"Scan failed: {e}")

        sys.exit(1)


if __name__ == "__main__":
    main()