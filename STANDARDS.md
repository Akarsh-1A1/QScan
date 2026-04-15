# QScan — Standards & Guidelines Reference

> **Purpose**: Comprehensive catalogue of every cryptographic standard, guideline, and regulatory reference hardcoded in QScan. This document serves as both developer documentation and a compliance audit trail for the NIST Compliance Agent.
>
> **Last Updated**: April 2026 | **QScan Version**: 1.0.0

---

## 1. NIST Post-Quantum Cryptography Standards (FIPS)

These are the primary standards QScan uses to recommend PQC migration paths.

| Standard | Full Name | Algorithm | Type | Status | Released | Source Files |
|---|---|---|---|---|---|---|
| **FIPS 203** | Module-Lattice-Based Key-Encapsulation Mechanism Standard | ML-KEM (Kyber) | Key Encapsulation | ✅ Finalized | Aug 2024 | `crypto/pqc_classifier.py` |
| **FIPS 204** | Module-Lattice-Based Digital Signature Standard | ML-DSA (Dilithium) | Digital Signature | ✅ Finalized | Aug 2024 | `crypto/pqc_classifier.py` |
| **FIPS 205** | Stateless Hash-Based Digital Signature Standard | SLH-DSA (SPHINCS+) | Digital Signature | ✅ Finalized | Aug 2024 | `config/settings.py`, `crypto/hndl_simulator.py` |

**Official URL**: https://csrc.nist.gov/projects/post-quantum-cryptography

### References in Code

- **`crypto/pqc_classifier.py`** — `pqc_replacements` dict maps vulnerable algorithms → FIPS standard replacements
  - RSA → ML-KEM-768 (FIPS 203)
  - ECDHE → ML-KEM-768 (FIPS 203)
  - DHE → ML-KEM-1024 (FIPS 203)
  - ECDH → ML-KEM-768 (FIPS 203)
  - DH → ML-KEM-1024 (FIPS 203)
  - ECDSA → ML-DSA-65 (FIPS 204)
  - DSA → ML-DSA-87 (FIPS 204)
  - Ed25519 → ML-DSA-44 (FIPS 204)

---

## 2. NIST PQC Algorithms (Approved & Under Standardization)

Algorithms recognized by QScan as post-quantum safe.

| Algorithm | Standard Name | FIPS/Draft | Type | Status | Source Files |
|---|---|---|---|---|---|
| **ML-KEM** | CRYSTALS-Kyber | FIPS 203 | Key Encapsulation | ✅ Standardized | `config/settings.py`, `crypto/pqc_classifier.py`, `crypto/hndl_simulator.py` |
| **ML-DSA** | CRYSTALS-Dilithium | FIPS 204 | Digital Signature | ✅ Standardized | `config/settings.py`, `crypto/pqc_classifier.py`, `crypto/hndl_simulator.py` |
| **SLH-DSA** | SPHINCS+ | FIPS 205 | Digital Signature (Hash-based) | ✅ Standardized | `config/settings.py`, `crypto/hndl_simulator.py`, `crypto/cipher_parser.py` |
| **FN-DSA** | Falcon | Draft | Digital Signature (Lattice) | 🔄 Under Standardization | `config/settings.py`, `crypto/hndl_simulator.py` |
| **HQC** | Hamming Quasi-Cyclic | Draft | Key Encapsulation | 🔄 Under Standardization | `config/settings.py` |
| **BIKE** | Bit Flipping Key Encapsulation | — | Key Encapsulation | 🔄 NIST Alternate | `config/settings.py` |
| **Classic McEliece** | Classic McEliece | — | Key Encapsulation (Code-based) | 🔄 NIST Alternate | `config/settings.py` |

**Organisation**: NIST (National Institute of Standards and Technology)
**Official URL**: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms

---

## 3. NIST IR 8547 — Transition to Post-Quantum Cryptography Standards

QScan uses this report for CRQC (Cryptographically Relevant Quantum Computer) timeline estimates.

| Document | Full Name | Organisation | Status |
|---|---|---|---|
| **NIST IR 8547** | Transition to Post-Quantum Cryptography Standards | NIST | 📄 Initial Public Draft |

**Official URL**: https://csrc.nist.gov/pubs/ir/8547/ipd

### Hardcoded CRQC Timelines

These estimates represent years until a CRQC can break each algorithm. Used in the Mosca Inequality / HNDL Risk Calculator.

| Algorithm | Years to CRQC | Source | Source Files |
|---|---|---|---|
| RSA | 7 | NIST IR 8547 | `crypto/hndl_simulator.py`, `qscan-frontend/src/components/charts/QuantumCharts.jsx` |
| RSA-2048 | 7 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| RSA-4096 | 8 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| RSA-PSS | 7 | NIST IR 8547 | `crypto/hndl_simulator.py` |
| DH | 7 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| DHE | 7 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| ECDHE | 9 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| ECDH | 9 | NIST IR 8547 | `crypto/hndl_simulator.py` |
| ECDSA | 9 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| X25519 | 9 | NIST IR 8547 | `crypto/hndl_simulator.py`, `QuantumCharts.jsx` |
| P-256 | 9 | NIST IR 8547 | `crypto/hndl_simulator.py` |
| P-384 | 9 | NIST IR 8547 | `crypto/hndl_simulator.py` |

### Key Deprecation Timeline (NIST IR 8547)

NIST will deprecate quantum-vulnerable algorithms from its standards by **2035**, with high-risk systems transitioning much earlier.

---

## 4. Quantum-Vulnerable Algorithms

Algorithms classified as vulnerable to Shor's algorithm on a CRQC.

| Algorithm | Family | Vulnerability | Quantum Attack | Source Files |
|---|---|---|---|---|
| **RSA** | RSA | Integer Factoring | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py`, `crypto/pqc_classifier.py` |
| **DSA** | DSA | Discrete Log Problem | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **ECDSA** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **ECDH** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **ECDHE** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **DH** | DH | Discrete Log Problem | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **DHE** | DH | Discrete Log Problem | Shor's Algorithm | `config/settings.py`, `crypto/cipher_parser.py` |
| **EdDSA** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py` |
| **Ed25519** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py`, `crypto/pqc_classifier.py` |
| **Ed448** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py` |
| **X25519** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py` |
| **X448** | ECC | Elliptic Curve DLP | Shor's Algorithm | `config/settings.py` |

**Organisation**: NIST
**Reference**: NIST SP 800-57 Part 1 Rev. 5, NIST IR 8547

---

## 5. Quantum-Safe Symmetric Algorithms

Symmetric algorithms considered safe against quantum attacks (Grover's algorithm halves effective key size).

| Algorithm | Key Size | Effective Post-Quantum Security | Status | Source Files |
|---|---|---|---|---|
| **AES-256** | 256-bit | 128-bit (post-Grover) | ✅ Quantum Safe | `config/settings.py`, `crypto/cipher_parser.py` |
| **AES-192** | 192-bit | 96-bit (post-Grover) | ✅ Quantum Safe | `config/settings.py` |
| **AES-128** | 128-bit | 64-bit (post-Grover) | ⚠️ Partially Safe | `config/settings.py`, `crypto/cipher_parser.py` |
| **ChaCha20** | 256-bit | 128-bit (post-Grover) | ✅ Quantum Safe | `config/settings.py` |
| **ChaCha20-Poly1305** | 256-bit | 128-bit (post-Grover) | ✅ Quantum Safe | `config/settings.py`, `crypto/cipher_parser.py` |

**Organisation**: NIST
**Reference**: NIST SP 800-38A (AES), NIST SP 800-38D (AES-GCM)

---

## 6. TLS Protocol Version Risk Classification

| Protocol | Risk Level | Status | Standard | Source Files |
|---|---|---|---|---|
| **TLS 1.3** | LOW | ✅ Current | RFC 8446 (IETF) | `config/settings.py`, `crypto/pqc_classifier.py` |
| **TLS 1.2** | MEDIUM | ✅ Supported | RFC 5246 (IETF) | `config/settings.py`, `crypto/pqc_classifier.py` |
| **TLS 1.1** | HIGH | ❌ Deprecated | RFC 4346 (IETF) | `config/settings.py`, `crypto/pqc_classifier.py` |
| **TLS 1.0** | CRITICAL | ❌ Deprecated | RFC 2246 (IETF) | `config/settings.py`, `crypto/pqc_classifier.py` |
| **SSL 3.0** | CRITICAL | ❌ Deprecated | RFC 6101 (IETF) | `config/settings.py` |
| **SSL 2.0** | CRITICAL | ❌ Deprecated | — | `config/settings.py` |

**Organisation**: IETF (Internet Engineering Task Force)
**Deprecation Reference**: RFC 8996 — "Deprecating TLS 1.0 and TLS 1.1"

---

## 7. Deprecated / Weak Cipher Algorithms

| Algorithm | Key Size | Status | Why Weak | Source Files |
|---|---|---|---|---|
| **3DES (Triple DES)** | 168-bit | ❌ Deprecated | Sweet32 attack, slow | `crypto/cipher_parser.py` |
| **RC4** | 128-bit | ❌ Deprecated | Multiple bias attacks | `crypto/cipher_parser.py`, `ai_ml/anomaly_detection.py` |
| **DES** | 56-bit | ❌ Deprecated | Brute-forceable | `crypto/cipher_parser.py`, `ai_ml/anomaly_detection.py` |
| **NULL** | 0-bit | ❌ Prohibited | No encryption | `crypto/cipher_parser.py`, `ai_ml/anomaly_detection.py` |

**Organisation**: NIST
**Reference**: NIST SP 800-131A Rev. 2 — "Transitioning the Use of Cryptographic Algorithms and Key Lengths"

---

## 8. Hash / MAC Algorithms

| Algorithm | Output Size | Status | Source Files |
|---|---|---|---|
| **SHA-384** | 384-bit | ✅ Current | `crypto/cipher_parser.py` |
| **SHA-256** | 256-bit | ✅ Current | `crypto/cipher_parser.py` |
| **SHA-1** | 160-bit | ❌ Deprecated for signatures | `crypto/cipher_parser.py` |
| **MD5** | 128-bit | ❌ Deprecated | `crypto/cipher_parser.py` |
| **AEAD** | Varies | ✅ Current (TLS 1.3) | `crypto/cipher_parser.py` |

**Organisation**: NIST
**Reference**: NIST FIPS 180-4 (SHA), NIST SP 800-131A Rev. 2

---

## 9. Hybrid PQC Key Exchange Recommendations

Hybrid options recommended by QScan for transitional deployments.

| Current Algorithm | Hybrid KEM | Target Standard | Priority | Source Files |
|---|---|---|---|---|
| RSA | X25519 + ML-KEM-768 | FIPS 203 | HIGH | `crypto/pqc_classifier.py` |
| ECDHE | X25519 + ML-KEM-768 | FIPS 203 | MEDIUM | `crypto/pqc_classifier.py` |
| DHE | FFDHE + ML-KEM-1024 | FIPS 203 | HIGH | `crypto/pqc_classifier.py` |
| ECDH | ECDH + ML-KEM-768 | FIPS 203 | MEDIUM | `crypto/pqc_classifier.py` |
| DH | DH + ML-KEM-1024 | FIPS 203 | HIGH | `crypto/pqc_classifier.py` |
| ECDSA | ECDSA + ML-DSA-65 | FIPS 204 | MEDIUM | `crypto/pqc_classifier.py` |
| Ed25519 | Ed25519 + ML-DSA-44 | FIPS 204 | MEDIUM | `crypto/pqc_classifier.py` |

**Organisation**: NIST / IETF
**Reference**: IETF Draft — "Hybrid Key Exchange in TLS 1.3"

---

## 10. PQC Readiness Detection Indicators

Cipher suite patterns QScan checks to detect PQC-ready configurations.

| Indicator | Algorithm | Standard | Source Files |
|---|---|---|---|
| `KYBER` | ML-KEM (Kyber) | FIPS 203 | `crypto/pqc_classifier.py` |
| `ML_KEM` | ML-KEM | FIPS 203 | `crypto/pqc_classifier.py` |
| `DILITHIUM` | ML-DSA (Dilithium) | FIPS 204 | `crypto/pqc_classifier.py` |
| `ML_DSA` | ML-DSA | FIPS 204 | `crypto/pqc_classifier.py` |
| `SPHINCS` | SLH-DSA (SPHINCS+) | FIPS 205 | `crypto/pqc_classifier.py` |
| `FALCON` | FN-DSA (Falcon) | Draft | `crypto/pqc_classifier.py` |

---

## 11. Mosca Inequality / HNDL Risk Model

The Mosca Inequality determines whether a "Harvest Now, Decrypt Later" breach window is open.

**Formula**: `X + Y > Z` → Breach window is OPEN

| Parameter | Description | Default Value | Source |
|---|---|---|---|
| **X** | Migration lead-time | 3 years | QScan default |
| **Y** | Data confidentiality shelf-life | 7 years | RBI banking mandate |
| **Z** | Years until CRQC breaks the algorithm | Per algorithm (see §3) | NIST IR 8547 |

**Source Files**: `crypto/hndl_simulator.py`, `qscan-backend/main.py`, `qscan-frontend/src/components/HNDL/`, `qscan-frontend/src/components/charts/QuantumCharts.jsx`

---

## 12. Quantum Threat Timeline Estimates

Hardcoded in `crypto/pqc_classifier.py` for threat assessment reporting.

| Key Exchange Algorithm | Estimated CRQC Threat | Migration Deadline (Risk ≥80) | Source |
|---|---|---|---|
| RSA, DH | 2028–2032 | 2026 | NIST IR 8547, expert estimates |
| ECDHE, ECDH | 2030–2035 | 2027 | NIST IR 8547, expert estimates |
| Other / Unknown | 2035+ | 2028–2030 | Conservative estimate |

**Source Files**: `crypto/pqc_classifier.py` (`_assess_threat_timeline`)

---

## 13. Regulatory Context

| Regulation / Framework | Organisation | Relevance to QScan |
|---|---|---|
| **Quantum Computing Cybersecurity Preparedness Act** | U.S. Congress | Mandates federal PQC migration |
| **NIST Cybersecurity Framework** | NIST | Risk management foundation |
| **RBI Cyber Security Framework** | Reserve Bank of India | 7-year data confidentiality mandate (Y=7 in Mosca) |
| **NIST SP 800-131A Rev. 2** | NIST | Algorithm deprecation timelines |
| **NIST SP 800-57 Part 1 Rev. 5** | NIST | Key management recommendations |

---

## File Index

Quick reference for which source files contain hardcoded standards:

| File | Standards Referenced |
|---|---|
| `config/settings.py` | Quantum-vulnerable algorithms, PQC algorithms, TLS risk levels, symmetric cipher safety |
| `crypto/pqc_classifier.py` | FIPS 203, 204 replacement mappings, PQC indicators, hybrid KEM options, threat timelines |
| `crypto/cipher_parser.py` | Cipher suite component classification (KEX, ENC, AUTH, MAC quantum safety) |
| `crypto/hndl_simulator.py` | NIST IR 8547 CRQC timelines, PQC safe algorithm set, Mosca parameters |
| `cbom/cbom_generator.py` | CBOM schema version, outputs NIST standard references in recommendations |
| `qscan-frontend/src/components/charts/QuantumCharts.jsx` | CRQC timeline data (NIST IR 8547), PQC safe algorithms |
| `qscan-frontend/src/pages/Landing.jsx` | NIST PQC display section |
| `qscan-frontend/src/pages/Certificate.jsx` | "NIST Algorithms Verified" label |
| `qscan-frontend/src/components/layout/Footer.jsx` | NIST PQC link |
