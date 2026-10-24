# CBOM-Scan ⚛️

[![CI](https://github.com/hashim-work-svg/cbomscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hashim-work-svg/cbomscan/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20CGO_ENABLED%3D0-brightgreen.svg)](#installation)

> **Cryptographic Bill of Materials (CBOM) & Post-Quantum Risk Discovery Scanner.**

---

## 1. Problem & Industry Evidence

The cryptographic transition to Post-Quantum Cryptography (PQC) is no longer theoretical—it is an imminent regulatory and engineering mandate:

* **NIST Deprecation Timelines:** NIST has designated **2030** as the deprecation date and **2035** as the full disallowance date for RSA, DSA, and Elliptic-Curve public-key cryptography (ECC/ECDSA/ECDH).
* **The Transition Gap:** 2026 global cybersecurity benchmarks indicate that **only ~38% of organizations are actively transitioning to post-quantum cryptography**, while **~68% report that discovering and managing cryptographic assets across codebases is very difficult**.
* **Regulatory Mandates:** US federal directives and EU guidance mandate that organizations establish a comprehensive **Cryptographic Bill of Materials (CBOM)** to audit algorithmic exposure to quantum decryption (Shor's algorithm) and *Store-Now-Decrypt-Later* (SNDL) attacks.

**`cbomscan`** solves this by providing automated discovery of cryptographic primitives across source code repositories, server configuration files, and X.509 certificates, classifying risks, scoring migration priorities, and outputting standard CycloneDX CBOM files.

---

## 2. Key Capabilities

* 🔍 **Multi-Target Cryptographic Discovery:** Scans source code repositories (Go, Python, Java, JavaScript/TypeScript), server configurations (nginx, sshd, OpenSSL), and X.509 certificates (PEM and DER).
* 📜 **Native X.509 Certificate Analysis:** Inspects asymmetric key types (RSA, ECDSA, Ed25519), key lengths, elliptic curves (P-256, P-384, P-521), signature algorithms, and expiration dates without external OpenSSL dependencies.
* 🏷️ **Post-Quantum Risk Classification:**
  * 🔴 `quantum-vulnerable`: RSA, ECC, ECDH, ECDSA (vulnerable to Shor's algorithm).
  * ⚠️ `legacy-broken`: MD5, SHA-1, DES, 3DES, RC4, RSA < 2048 bits.
  * 🟢 `quantum-safer-candidate`: AES-256, SHA-256+, ML-KEM, ML-DSA.
* 📊 **Standardized Migration Priority Score (0–100):** Ranks findings based on algorithmic severity, sensitive path context (`auth`, `payment`, `pki`), and certificate expiration urgency.
* ⚡ **Single Static Binary (`CGO_ENABLED=0`):** Shipped as one self-contained executable with all rules embedded via `go:embed`. Runs on Linux, macOS, and Windows.

---

## 3. Architecture Overview

```
[Source Code / Configs / X.509 Certificates]
                    │
                    ▼
          ┌───────────────────┐
          │   Target Router   │
          └─────────┬─────────┘
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
┌──────────────┐          ┌──────────────┐
│  Regex Rule  │          │    X.509     │
│    Engine    │          │  ASN.1/DER   │
└──────┬───────┘          └──────┬───────┘
       │                         │
       └────────────┬────────────┘
                    ▼
          ┌───────────────────┐
          │  Risk Classifier  │ ──► quantum-vulnerable / legacy-broken
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │  Priority Scorer  │ ──► 0-100 Migration Priority Formula
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Export & Display  │ ──► CLI Tables / CycloneDX CBOM JSON
          └───────────────────┘
```

---

## 4. Quickstart

### Scan a Local Directory or Repository:
```bash
# Scan current directory for cryptographic usage and certificates
./cbomscan scan .

# Scan specific directory
./cbomscan scan /path/to/project
```

### Scan a Certificate File:
```bash
./cbomscan scan /etc/ssl/certs/server.crt
```

---

## 5. What `cbomscan` Does Not Do (Honest Limitations)

1. **Regex Heuristics:** Source code pattern matching is regex-based. It can produce false positives (e.g. comments or test variable names containing `rsa`) and false negatives (e.g. dynamically constructed algorithm strings or obfuscated reflection calls).
2. **No Arbitrary Network Scanning:** `cbomscan` never performs unauthorized port or network scanning. All scans target local files and explicitly provided paths.
3. **No Cryptographic Implementation:** The tool inspects and audits cryptographic assets; it does not implement encryption algorithms.

---

## 6. Regulatory & Compliance Notice

> [!IMPORTANT]
> **Notice:** `cbomscan` is an engineering auditing tool and does not provide formal legal, cryptographic certification, or FIPS compliance determination. Consult qualified cryptographic security professionals for formal verification.

---

## 7. License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Muhammad Hashim.
