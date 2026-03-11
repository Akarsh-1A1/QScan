# QScan Results: `pnbindia.in`

The QScan pipeline, newly driven by our AI/ML engine and realistic feature set, was run against **pnbindia.in**. 

## Asset Discovered
* **Host**: `pnbindia.in:443`
* **TLS Version**: TLSv1.2
* **Cipher Suite**: `ECDHE-RSA-AES256-GCM-SHA384`

## Quantum Risk Analysis
* **Rule-Based Score**: `60.8`
* **ML-Predicted Score**: `60.7`
* **Blended Score**: `60.7`
* **Risk Level**: `HIGH`
* **Anomaly Detected**: `False`

**Why HIGH Risk?**
* **Key Exchange (ECDHE)** is vulnerable to Shor's algorithm (no quantum-resistance).
* **Authentication (RSA)** is vulnerable to Shor's algorithm.
* **Positive attribute**: It *does* use AES-256-GCM and supports Forward Secrecy, providing partial "Harvest Now, Decrypt Later" protection for past sessions.

## PQC Readiness & Recommendations
* **Status**: `MIGRATION_NEEDED`
* **Threat Timeline**: Urgency is `NEAR-TERM` with a recommended migration deadline around `2027` before Q-Day risks become critical.

**Actionable Next Steps (NIST Standards)**:
1. **Key Exchange**: Migrate `ECDHE` to **ML-KEM-768 (Kyber)** (FIPS 203). Wait-state hybrid option: `X25519+ML-KEM-768`.
2. **Authentication**: Migrate `RSA` to **ML-DSA-65 (Dilithium)** (FIPS 204). Wait-state hybrid option: `RSA+ML-DSA-65`.

*The full JSON output (including the Cryptographic Bill of Materials - CBOM) has been saved to the `/results` directory.*
