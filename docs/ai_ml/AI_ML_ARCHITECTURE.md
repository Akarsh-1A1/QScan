# QScan: AI/ML Module Architecture Guide

This guide provides a detailed breakdown of the internal components within the `ai_ml/` directory and explains how they work together to provide Quantum-Ready risk assessments.

---

## 1. `feature_engineering.py` (The Translator)
**Role**: Converts raw, messy cryptographic scan results into a clean, numeric format that Machine Learning models can understand.

*   **What it does**: It takes a dictionary containing TLS data (ciphers, bits, versions) and extracts **24 specific features**.
*   **Why it's important**: Models can't process text labels like "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" directly. This file "translates" that string into:
    *   Is it AEAD? (1 or 0)
    *   Is it CBC? (1 or 0)
    *   What is the key size? (256)
*   **Key Class**: `FeatureExtractor`

## 2. `training_data.py` (The Teacher)
**Role**: Generates high-quality, realistic training examples to "teach" the AI what a safe vs. dangerous server looks like.

*   **What it does**: Instead of using random combinations, it uses **Cipher Suite Ecosystems**. It knows that `AES-GCM` usually goes with `TLS 1.2+` and `ECDHE`.
*   **Synthetic Generation**: It generates 2,000+ "mock" servers based on NIST SP 800-52r2 standards, labels them using our rule-based classifier, and feeds them to the model.
*   **Key Class**: `TrainingDataGenerator`

## 3. `risk_scoring_model.py` (The Brain)
**Role**: Provides the final numerical "Quantum Risk Score" using the **XGBoost** Gradient Boosting algorithm.

*   **What it does**: It analyzes the 24 features provided by the Translator and predicts a score from 0 (Safe) to 100 (Critical).
*   **Intelligence**: It learns complex patterns that rules might miss—for example, it might learn that while SHA1 is generally bad, it's *extremely* risky when combined with an old TLS 1.0 protocol.
*   **Hybrid Logic**: If the model hasn't been trained yet, it automatically "falls back" to the rule-based system to ensure you always get a result.
*   **Key Class**: `RiskScoringModel`

## 4. `anomaly_detection.py` (The Guard)
**Role**: Identifies "weird" or "suspicious" configurations using the **Isolation Forest** algorithm.

*   **What it does**: It doesn't look for "bad" configs; it looks for "unusual" ones. If every server in your organization uses AES-GCM, and one suddenly uses NULL encryption or a rare EXPORT cipher, this flags it even if it was technically "allowed" by a firewall.
*   **Heuristics**: It also includes hardcoded "Security Redlines" (like checking for NULL ciphers or ancient SSLv2) to provide instant detection of critical misconfigurations.
*   **Key Class**: `CryptoAnomalyDetector`

---

## Data Flow Pipeline

When you run `python main.py --domain example.com`, the data flows like this:

1.  **Scanner**: Connects to the server and grabs the raw TLS/Cipher strings.
2.  **`feature_engineering.py`**: Turns those strings into a 24-element numeric vector.
3.  **`risk_scoring_model.py`**: Predicts the Quantum Risk Score based on those features.
4.  **`anomaly_detection.py`**: Checks if the configuration is suspicious compared to normal patterns.
5.  **Main Output**: Combines the Risk Score + Anomalies + PQC Recommendations into a final **CBOM (Cryptographic Bill of Materials)**.

---

## Summary of AI/ML Files

| File | Primary Technology | Purpose |
| :--- | :--- | :--- |
| `feature_engineering.py` | NumPy / Logic | Feature Extraction |
| `training_data.py` | Random / Synthetic | Dataset Generation |
| `risk_scoring_model.py` | XGBoost (Trees) | Predictive Risk Scoring |
| `anomaly_detection.py` | Isolation Forest | Outlier/Threat Detection |
