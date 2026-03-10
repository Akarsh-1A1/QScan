# QScan — Quantum Readiness Assessment Platform

<p align="center">
  <b>🛡️ QShield's Automated PQC Scanner for Banking Infrastructure</b>
</p>

> Evaluate the cryptographic security of banking systems and assess readiness for Post-Quantum Cryptography (PQC).

---

## 🚀 Overview

**QScan** is an automated Quantum Readiness Assessment Platform designed to:

- **Discover** public-facing banking assets (web servers, APIs, VPN endpoints)
- **Analyze** TLS/cryptographic configurations of each asset
- **Generate** a Cryptographic Bill of Materials (CBOM)
- **Score** quantum vulnerability using AI-driven risk analysis
- **Recommend** NIST-standardized PQC migration paths

## 🏗️ Architecture

```
Target Domain
      │
      ▼
Asset Discovery Module
(subdomains, APIs, VPN endpoints)
      │
      ▼
TLS / Crypto Scanner
      │
      ▼
Cryptographic Parser
      │
      ▼
CBOM Generator
      │
      ▼
Quantum Risk Analyzer
      │
      ▼
PQC Migration Advisor
      │
      ▼
Quantum Readiness Dashboard
```

## 📁 Project Structure

```
qscan/
├── README.md
├── requirements.txt
├── main.py                      # CLI entry point
├── config/
│   └── settings.py              # Global configuration
├── scanner/
│   ├── asset_discovery.py       # Subdomain & asset enumeration
│   ├── tls_scanner.py           # TLS handshake & cert analysis
│   └── port_scanner.py          # Port scanning module
├── crypto/
│   ├── cipher_parser.py         # Cipher suite parsing & classification
│   └── pqc_classifier.py        # PQC readiness classification
├── cbom/
│   └── cbom_generator.py        # CBOM JSON generation
├── utils/
│   └── logger.py                # Centralized logging
└── demo_results/
    └── sample_cbom.json         # Sample output
```

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/Akarsh-1A1/Qscan.git
cd Qscan

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

## 🔧 Usage

```bash
# Scan a single domain
python main.py --domain example.com

# Scan with asset discovery
python main.py --domain example.com --discover

# Scan and generate CBOM
python main.py --domain example.com --discover --cbom
```

## 🧩 Modules

| Module | Description |
|---|---|
| **Asset Discovery** | Enumerates subdomains, APIs, and public endpoints using DNS resolution and certificate transparency logs |
| **TLS Scanner** | Performs TLS handshakes to extract protocol versions, cipher suites, and certificate details |
| **Port Scanner** | Identifies open ports with TLS-enabled services |
| **Cipher Parser** | Classifies cipher suites by quantum vulnerability level |
| **PQC Classifier** | Evaluates quantum readiness and recommends NIST PQC algorithms |
| **CBOM Generator** | Produces a structured Cryptographic Bill of Materials in JSON format |

## 🔐 Quantum Risk Scoring

Each asset is assigned a **Quantum Risk Score** based on:

- Cryptographic algorithm type (RSA, ECC, AES, etc.)
- Key length and strength
- TLS protocol version
- Certificate properties
- System exposure level

## 📊 PQC Recommendations

The platform recommends NIST-standardized PQC algorithms:

| Algorithm | Use Case | Status |
|---|---|---|
| **ML-KEM (Kyber)** | Key Encapsulation | NIST Standardized |
| **ML-DSA (Dilithium)** | Digital Signatures | NIST Standardized |
| **SLH-DSA (SPHINCS+)** | Hash-based Signatures | NIST Standardized |
| **FN-DSA (Falcon)** | Digital Signatures | NIST Standardized |

## 🛣️ Roadmap

- [x] Core scanning pipeline
- [ ] AI-driven quantum risk scoring
- [ ] PQC migration advisor
- [ ] Quantum readiness dashboard
- [ ] SIEM integration
- [ ] Automated compliance reporting

## 📄 License

This project is developed for the **PNB Cybersecurity Hackathon 2025**.

## 👥 Team

- **Akarsh-1A1** — [GitHub](https://github.com/Akarsh-1A1)

---

<p align="center">
  <i>Built with ❤️ for a quantum-safe future</i>
</p>
