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
Quantum Risk Analyzer (Rule-Based)
      │
      ▼
AI/ML Risk Scoring Engine (XGBoost)
      │
      ▼
Anomaly Detection
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
│   └── pqc_classifier.py        # PQC readiness classification (rule-based)
├── ai_ml/
│   ├── risk_scoring_model.py    # ML-based quantum risk scoring (XGBoost)
│   ├── feature_engineering.py   # Feature extraction from scan data
│   ├── anomaly_detection.py     # Unusual crypto config detection
│   ├── training_data.py         # Training dataset generation
│   └── models/                  # Saved trained models
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
| **PQC Classifier** | Evaluates quantum readiness and recommends NIST PQC algorithms (rule-based) |
| **CBOM Generator** | Produces a structured Cryptographic Bill of Materials in JSON format |
| **AI Risk Scorer** | XGBoost/sklearn model that learns optimal risk scoring from scan data |
| **Feature Engineering** | Extracts and transforms crypto scan data into ML-ready features |
| **Anomaly Detection** | Isolation Forest model to flag unusual or suspicious crypto configurations |
| **Training Data** | Generates labeled datasets from real scans and synthetic crypto configs |

## 🔐 Quantum Risk Scoring

Each asset is assigned a **Quantum Risk Score** (0–100) using a **hybrid approach**:

1. **Rule-Based Scoring** (`pqc_classifier.py`) — weighted formula using:
   - Cryptographic algorithm type (RSA, ECC, AES, etc.)
   - Key length and strength
   - TLS protocol version
   - Certificate properties
   - Forward secrecy support

2. **AI/ML Scoring** (`ai_ml/risk_scoring_model.py`) — XGBoost model that:
   - Learns from labeled scan data and synthetic training sets
   - Discovers hidden risk patterns beyond manual rules
   - Provides more accurate scoring over time
   - Falls back to rule-based scoring when model is not yet trained

3. **Anomaly Detection** (`ai_ml/anomaly_detection.py`) — flags unusual configs that both rule-based and ML scoring might miss

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
- [x] AI/ML module structure (risk scoring, feature engineering, anomaly detection)
- [ ] AI/ML model training and integration
- [ ] PQC migration advisor
- [ ] Quantum readiness dashboard
- [ ] SIEM integration
- [ ] Automated compliance reporting

## 📄 License

This project is developed for the **PNB Cybersecurity Hackathon 2025**.

## 👥 Team

- **Akarsh Raj** — [GitHub](https://github.com/Akarsh-1A1)

---

<p align="center">
  <i>Built with ❤️ for a quantum-safe future</i>
</p>
