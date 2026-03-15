<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Redis-7+-DC382D?style=for-the-badge&logo=redis&logoColor=white" />
  <img src="https://img.shields.io/badge/XGBoost-ML-FF6F00?style=for-the-badge&logo=xgboost&logoColor=white" />
</p>

# QScan — Quantum Readiness Assessment Platform

<p align="center">
  <b>🛡️ QShield's Automated PQC Scanner for Banking Infrastructure</b>
</p>

> Evaluate the cryptographic security of banking systems and assess readiness for Post-Quantum Cryptography (PQC) — powered by AI/ML risk scoring, anomaly detection, and NIST-standardized migration advisories.

---

## 📸 Screenshots

### Quantum Readiness Dashboard
| Readiness Score | Risk Matrix |
|:---:|:---:|
| ![Quantum Readiness Score](Run%20Snapshots/IMG-20260315-WA0040.jpg) | ![Risk Matrix](Run%20Snapshots/IMG-20260315-WA0041.jpg) |

### Detailed Scan Results & Threat Assessment
| Asset Scan Results (TLS, Cipher, Anomaly Detection) | Quantum Threat Assessment & PQC Migration Recommendations |
|:---:|:---:|
| ![Scan Results](Run%20Snapshots/IMG-20260315-WA0044.jpg) | ![Threat Assessment](Run%20Snapshots/IMG-20260315-WA0043.jpg) |

### PQC Migration Plan & CBOM Output
| PQC Migration Plan | CBOM JSON Output |
|:---:|:---:|
| ![PQC Migration Plan](Run%20Snapshots/IMG-20260315-WA0042.jpg) | ![CBOM Output](Run%20Snapshots/IMG-20260315-WA0039.jpg) |

---

## 🚀 Overview

**QScan** is a full-stack Quantum Readiness Assessment Platform built for the **PNB Cybersecurity Hackathon 2026**. It provides an end-to-end pipeline to:

- 🔍 **Discover** public-facing banking assets (subdomains, APIs, VPN endpoints) via DNS enumeration & certificate transparency
- 🔐 **Analyze** TLS/cryptographic configurations with deep cipher suite inspection
- 📦 **Generate** a structured Cryptographic Bill of Materials (CBOM) in JSON format
- 🤖 **Score** quantum vulnerability using both rule-based and AI/ML-driven risk analysis (XGBoost + Isolation Forest anomaly detection)
- 📋 **Recommend** NIST-standardized PQC migration paths with urgency timelines
- 📊 **Visualize** all results through an interactive, real-time Quantum Readiness Dashboard

---

## 🏗️ Architecture

```
                        ┌──────────────────────┐
                        │   React Frontend     │
                        │   (Dashboard UI)     │
                        └──────────┬───────────┘
                                   │ REST API
                        ┌──────────▼───────────┐
                        │   FastAPI Backend     │
                        │   + Redis Cache       │
                        └──────────┬───────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │           QScan Core Engine              │
              │                                         │
              │  ┌─────────────┐  ┌──────────────────┐  │
              │  │   Asset     │  │   Port Scanner   │  │
              │  │  Discovery  │  │                  │  │
              │  └──────┬──────┘  └────────┬─────────┘  │
              │         └────────┬─────────┘            │
              │                  ▼                      │
              │         ┌────────────────┐              │
              │         │  TLS Scanner   │              │
              │         └───────┬────────┘              │
              │                 ▼                       │
              │    ┌────────────────────────┐           │
              │    │   Crypto Parser +      │           │
              │    │   PQC Classifier       │           │
              │    └────────────┬───────────┘           │
              │                 ▼                       │
              │  ┌──────────────────────────────────┐   │
              │  │        AI/ML Engine              │   │
              │  │  ┌──────────┐ ┌───────────────┐  │   │
              │  │  │ XGBoost  │ │  Isolation    │  │   │
              │  │  │ Risk     │ │  Forest       │  │   │
              │  │  │ Scoring  │ │  Anomaly Det. │  │   │
              │  │  └──────────┘ └───────────────┘  │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                       │
              │         ┌────────────────┐              │
              │         │ CBOM Generator │              │
              │         └────────────────┘              │
              └─────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
QScan/
├── main.py                          # CLI entry point (5-phase pipeline)
├── setup.py                         # pip-installable package + `qscan` command
├── requirements.txt                 # Python dependencies
│
├── config/
│   └── settings.py                  # Global configuration
│
├── scanner/
│   ├── asset_discovery.py           # Subdomain & asset enumeration (DNS + CT logs)
│   ├── tls_scanner.py               # TLS handshake & certificate analysis
│   └── port_scanner.py              # Port scanning module
│
├── crypto/
│   ├── cipher_parser.py             # Cipher suite parsing & classification
│   └── pqc_classifier.py           # PQC readiness classification (rule-based)
│
├── ai_ml/
│   ├── risk_scoring_model.py        # XGBoost quantum risk scoring
│   ├── feature_engineering.py       # Feature extraction from scan data
│   ├── anomaly_detection.py         # Isolation Forest anomaly detection
│   ├── training_data.py             # Training dataset generation
│   └── models/                      # Saved trained models (.joblib)
│
├── cbom/
│   └── cbom_generator.py            # CBOM JSON generation
│
├── utils/
│   └── logger.py                    # Centralized logging
│
├── qscan-backend/                   # FastAPI REST API server
│   ├── main.py                      # API routes + background scan worker
│   ├── config.py                    # Redis & server settings (Pydantic)
│   └── requirements.txt             # Backend-specific dependencies
│
├── qscan-frontend/                  # React 19 Dashboard
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Landing.jsx          # Home / landing page
│   │   │   ├── NewScan.jsx          # Start new scan form
│   │   │   ├── Results.jsx          # Full scan results dashboard
│   │   │   ├── History.jsx          # Scan history list
│   │   │   └── Certificate.jsx      # Certificate detail view
│   │   ├── components/              # Reusable UI components
│   │   ├── api/                     # Axios API client
│   │   ├── hooks/                   # Custom React hooks
│   │   ├── styles/                  # CSS stylesheets
│   │   └── utils/                   # Frontend utilities
│   └── package.json
│
├── demo_results/                    # Sample scan outputs
├── results/                         # Scan output directory
└── Run Snapshots/                   # Application screenshots
```

---

## ⚙️ Installation & Setup

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| Node.js | 18+ |
| Redis | 7+ |
| nmap | Latest (for port scanning) |

### 1. Clone & Install Core Scanner

```bash
# Clone the repository
git clone https://github.com/Akarsh-1A1/Qscan.git
cd QScan

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install core dependencies
pip install -r requirements.txt

# Install qscan as a CLI tool
pip install -e .
```

### 2. Set Up Backend (FastAPI + Redis)

```bash
cd qscan-backend

# Install backend dependencies
pip install -r requirements.txt

# Configure Redis credentials in .env file
# See config.py for available options:
#   REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_SCAN_TTL
#   SERVER_HOST, SERVER_PORT, QSCAN_TIMEOUT, CORS_ORIGINS

# Start the API server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

> **API Docs:** Swagger UI → http://localhost:8000/docs | ReDoc → http://localhost:8000/redoc

### 3. Set Up Frontend (React Dashboard)

```bash
cd qscan-frontend

# Install dependencies
npm install

# Start the development server
npm start
```

> The frontend runs at http://localhost:3000 and connects to the backend API at port 8000.

---

## 🔧 Usage

### CLI Mode

```bash
# Scan a single domain
python main.py --domain example.com

# Scan with asset discovery (subdomains, SAN assets)
python main.py --domain example.com --discover

# Scan and generate CBOM
python main.py --domain example.com --discover --cbom

# Custom ports and verbose output
python main.py --domain example.com --discover --cbom --ports 443,8443,993 --verbose
```

### Web Dashboard Mode

1. Start Redis server
2. Start the backend: `uvicorn main:app --reload` (from `qscan-backend/`)
3. Start the frontend: `npm start` (from `qscan-frontend/`)
4. Navigate to http://localhost:3000
5. Enter a target domain in **New Scan** and monitor progress in real-time
6. View results, risk matrix, CBOM, and PQC migration recommendations

---

## 🧩 Feature Overview

### Core Scanning Pipeline

| Module | Description |
|---|---|
| **Asset Discovery** | Enumerates subdomains, APIs, and public endpoints using DNS resolution, certificate transparency logs, and SAN extraction |
| **Port Scanner** | Multi-threaded port scanning to identify TLS-enabled services |
| **TLS Scanner** | Deep TLS handshake analysis — protocol versions, cipher suites, certificate details, key exchange |
| **Cipher Parser** | Classifies cipher suites by quantum vulnerability level |
| **PQC Classifier** | Evaluates quantum readiness and assigns risk levels (CRITICAL / HIGH / MEDIUM / LOW / SAFE) |
| **CBOM Generator** | Produces a structured Cryptographic Bill of Materials with risk matrix and migration plan |

### AI/ML Engine

| Module | Description |
|---|---|
| **XGBoost Risk Scoring** | ML model that learns quantum risk patterns from labeled scan data and synthetic training sets |
| **Feature Engineering** | Extracts and transforms raw crypto scan data into ML-ready feature vectors |
| **Anomaly Detection** | Isolation Forest model that flags unusual or suspicious cryptographic configurations |
| **Training Data Generator** | Generates labeled datasets from real scans and synthetic crypto configs for model training |

### Web Dashboard (React)

| Page | Description |
|---|---|
| **Landing** | Home page with platform overview and API connection status |
| **New Scan** | Form to initiate scans with domain input, discovery toggle, and port selection |
| **Results** | Full scan results — Quantum Readiness Score, Risk Matrix, Asset details, Cipher suites, Anomaly flags, PQC Migration Plan, Certificate info, and Threat Assessment |
| **History** | Browse and manage past scan records |
| **Certificate** | Detailed certificate information view |

### REST API (FastAPI + Redis)

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/scan` | `POST` | Start a new scan (async, returns scan ID) |
| `/api/v1/scan/{id}` | `GET` | Poll scan status and progress |
| `/api/v1/scan/{id}/results` | `GET` | Retrieve full scan results |
| `/api/v1/scan/{id}/cbom` | `GET` | Get Cryptographic Bill of Materials |
| `/api/v1/history` | `GET` | List all past scans |
| `/api/v1/scan/{id}` | `DELETE` | Remove a scan record |
| `/api/v1/health` | `GET` | Health check (verifies Redis connectivity) |

---

## 🔐 Quantum Risk Scoring

Each asset is assigned a **Quantum Risk Score** (0–100) using a **hybrid approach**:

### 1. Rule-Based Scoring (`pqc_classifier.py`)

Weighted formula evaluating:
- Cryptographic algorithm type (RSA, ECC, AES, etc.)
- Key length and effective strength
- TLS protocol version (TLS 1.2 vs 1.3)
- Certificate properties and validity
- Forward secrecy support

### 2. AI/ML Scoring (`ai_ml/risk_scoring_model.py`)

XGBoost model that:
- Learns from labeled scan data and synthetic training sets
- Discovers hidden risk patterns beyond manual rules
- Provides confidence-scored predictions
- Falls back to rule-based scoring when model is unavailable

### 3. Anomaly Detection (`ai_ml/anomaly_detection.py`)

Isolation Forest model that:
- Flags unusual crypto configurations that rule-based + ML scoring might miss
- Provides anomaly scores with confidence levels (Normal / Anomalous)
- Detects misconfigurations, deprecated cipher usage, or unexpected combinations

---

## 📊 PQC Migration Recommendations

The platform recommends NIST-standardized Post-Quantum Cryptography algorithms with urgency timelines:

| Algorithm | Use Case | Standard | Replaces |
|---|---|---|---|
| **ML-KEM (Kyber)** | Key Encapsulation | FIPS 203 | RSA, ECDH |
| **ML-DSA (Dilithium)** | Digital Signatures | FIPS 204 | RSA, ECDSA |
| **SLH-DSA (SPHINCS+)** | Hash-based Signatures | FIPS 205 | RSA, ECDSA |
| **FN-DSA (Falcon)** | Digital Signatures | NIST Standardized | RSA, ECDSA |

Each asset receives:
- **Estimated Quantum Threat timeline** (e.g., 2030–2035)
- **Migration Deadline** with urgency level (NEAR-TERM / MID-TERM)
- **Hybrid transition paths** (e.g., X25519+ML-KEM-768)

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Core Scanner** | Python 3.11+ — cryptography, pyOpenSSL, dnspython, python-nmap |
| **AI/ML** | scikit-learn, XGBoost, NumPy, Pandas, joblib |
| **Backend API** | FastAPI, Uvicorn, Pydantic |
| **Cache/Store** | Redis (async via redis-py) |
| **Frontend** | React 19, React Router, Recharts, Framer Motion, Axios |
| **UI** | Lucide React icons , interqactive designs

---

## 🛣️ Completed Milestones

- [x] Core scanning pipeline (Asset Discovery → TLS Scanner → Port Scanner)
- [x] Cryptographic parsing and PQC classification
- [x] CBOM generation with detailed risk matrix
- [x] AI/ML risk scoring engine (XGBoost)
- [x] Anomaly detection (Isolation Forest)
- [x] Feature engineering pipeline
- [x] FastAPI REST backend with async scan execution
- [x] Redis integration for persistent scan storage
- [x] React 19 interactive dashboard
- [x] Quantum Readiness Score visualization
- [x] Risk Matrix with per-asset breakdown
- [x] PQC Migration Plan with urgency timelines
- [x] Quantum Threat Assessment display
- [x] Certificate information viewer
- [x] Scan history & management
- [x] Real-time scan progress tracking

---

## 📄 License

This project is developed for the **PNB Cybersecurity Hackathon 2026**.

---

## 👥 Team — QShield

| Member | GitHub |
|---|---|
| **Akarsh Raj** | [@Akarsh-1A1](https://github.com/Akarsh-1A1) |
| **Subhanshu Kumar** | [@Subhansh-1-u](https://github.com/Subhansh-1-u) |
| **Naman V Shetty** | [@namanshetty25](https://github.com/namanshetty25) |
| **Tanish Yadav** | [@tanpsi](https://github.com/tanpsi) |

---

<p align="center">
  <b>⚛️ Built for a quantum-safe future</b><br/>
  <sub>PNB Cybersecurity Hackathon 2025 — Team QShield</sub>
</p>
