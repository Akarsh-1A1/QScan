# QScan: ML Feature Engineering Guide

This document explains the logic, encoding, and security rationale for the **24 features** extracted by the `FeatureExtractor` in `ai_ml/feature_engineering.py`. These features transform raw TLS scan results into numeric vectors for the XGBoost Risk Scoring model.

## 1. Protocol Features

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `tls_version` | Ordinal | SSLv2=0, SSLv3=1, ..., TLSv1.3=5. | Higher versions support modern, quantum-resistant-capable handshakes. |
| `protocol_deprecated` | Boolean | 1 if version < TLS 1.2. | Direct indicator of EOL protocol support which lacks modern security properties. |
| `num_deprecated_protocols` | Numeric | Count of supported legacy protocols (SSLv2-TLS1.1). | Measures the "attack surface" for protocol downgrade attacks. |

## 2. Key Exchange & Authentication

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `kex_algorithm` | Categorical | RSA=0, DH=1, DHE=2, ECDH=3, ECDHE=4, ... | Different algorithms have different susceptibility to Shor's algorithm. |
| `kex_quantum_safe` | Boolean | 1 if ML-KEM (Kyber) or similar is used. | The primary indicator of Post-Quantum transition. |
| `forward_secrecy` | Boolean | 1 if ephemeral keys are used (ECDHE/DHE). | Protects against "Harvest Now, Decrypt Later" for *past* traffic. |
| `auth_algorithm` | Categorical | RSA=0, DSA=1, ECDSA=2, PSK=3. | Categorizes the identity verification mechanism. |
| `auth_quantum_safe` | Boolean | 1 if ML-DSA (Dilithium) or similar is used. | Indicates if the digital signature can be forged by a quantum computer. |

## 3. Symmetric Encryption Details

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `enc_algorithm` | Categorical | NULL=0, DES=1, ..., AES-GCM=6, ChaCha20=9. | Identifies the bulk encryption primitive used. |
| `enc_bits` | Numeric | Key size in bits (128, 256). | Direct measurement of classical brute-force resistance. |
| `enc_quantum_safe` | Boolean | 1 for AES/ChaCha20. | Grover's algorithm only halves symmetric bits; 128+ bits are generally safe. |
| `is_aead_cipher` | Boolean | 1 if GCM, CCM, or Poly1305. | Modern AEAD provides built-in integrity; protects against many legacy attacks. |
| `is_cbc_cipher` | Boolean | 1 if Cipher Block Chaining is used. | CBC mode is prone to padding oracle attacks (e.g., Lucky13). |
| `is_export_cipher` | Boolean | 1 if "EXPORT" grade (weak keys). | Heavily restricted 40/56-bit keys that are trivially breakable today. |
| `is_null_cipher` | Boolean | 1 if no encryption (NULL). | Critical failure; traffic is sent in plaintext. |
| `cipher_strength_bits` | Numeric | Scalar value of symmetric bits. | Redundancy for `enc_bits` but specifically focused on bulk strength. |

## 4. Hashing & Integrity

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `uses_sha1` | Boolean | 1 if SHA1 is used in MAC or Signatures. | SHA1 is collision-vulnerable and deprecated by NIST. |
| `uses_md5` | Boolean | 1 if MD5 is used in MAC or Signatures. | MD5 is cryptographically broken and highly dangerous. |

## 5. Certificate & Trust

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `cert_key_type` | Categorical | RSA=0, EC/ECC=1, DSA=2. | Identifies the leaf certificate algorithm. |
| `cert_key_bits` | Numeric | Public key size (e.g., 2048). | Critical for PQC; RSA-2048 is more vulnerable than RSA-4096. |
| `num_chain_vulnerabilities`| Numeric | Count of issues (expired, weak sig, etc.). | General health indicator of the PKI deployment. |
| `has_weak_signature` | Boolean | 1 if any weak algorithm found in chain. | Indicates potential for certificate forgery. |

## 6. Quantum Posture Summary

| Feature | Type | Logic / Encoding | Security Rationale |
| :--- | :--- | :--- | :--- |
| `num_quantum_vulnerable` | Numeric | Count of specific non-PQC components. | Cumulative measure of Shor's algorithm risk. |
| `num_quantum_safe` | Numeric | Count of PQC or High-entropy components. | Positive measure of quantum readiness. |

---

### Encoding Summary
*   **Categorical/Ordinal Scaling**: We map strings (like "TLSv1.2") to integers so the XGBoost Trees can find split-points (e.g., `tls_version < 4` means deprecated).
*   **Boolean/Binary**: Used for clear security flags (e.g., `is_null_cipher`).
*   **Numeric**: Used for key sizes and counts where magnitude matters.
