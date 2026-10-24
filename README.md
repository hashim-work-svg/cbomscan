# CBOM-Scan ⚛️

[![CI](https://github.com/hashim-work-svg/cbomscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hashim-work-svg/cbomscan/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20CGO_ENABLED%3D0-brightgreen.svg)](#installation)

> **Cryptographic Bill of Materials (CBOM) & Post-Quantum Risk Discovery Scanner.**

---

## 1. Problem & Context

The cryptographic transition to Post-Quantum Cryptography (PQC) is an imminent regulatory and engineering imperative:

* **NIST Transition Roadmap (NIST IR 8547):** NIST has slated **2030** for deprecation and **2035** for full disallowance of classical asymmetric cryptography (RSA, DSA, ECDSA, ECDH) vulnerable to Shor's algorithm on Cryptanalytically Relevant Quantum Computers (CRQCs).
* **The Discovery Gap:** Industry reports highlight that finding and cataloging cryptographic assets embedded in legacy microservices, dependency trees, and server configurations is the most arduous first step in PQC migration.
* **Cryptographic Inventories:** Directives such as US OMB Memorandum M-23-02 and European PQC migration guidelines mandate that organizations establish a comprehensive cryptographic inventory or **Cryptographic Bill of Materials (CBOM)** to assess Store-Now-Decrypt-Later (SNDL) exposures.

**`cbomscan`** automates this discovery across source code repositories (Go, Python, Java, JavaScript/TypeScript), server configuration files (nginx, sshd, OpenSSL), and X.509 certificates (PEM and DER), classifying risks, scoring migration priorities (0–100), and exporting standard CycloneDX 1.6 CBOM files.

---

## 2. Implementation Status

| Capability | Status | Description |
| :--- | :---: | :--- |
| **Multi-Language Scanning (Go, Python, Java, JS)** | ✅ Shipped | Embedded YAML rules with line-by-line inspection |
| **Server Config Auditing (nginx, sshd, OpenSSL)** | ✅ Shipped | Audits TLS protocols, legacy SSH ciphers, and KEX |
| **Native X.509 PEM & DER Certificate Parser** | ✅ Shipped | Key sizes, curves, validity, expiration urgency |
| **CycloneDX 1.6 CBOM JSON Exporter** | ✅ Shipped | Standard `cryptographic-asset` component schema |
| **Migration Priority Scoring Engine (0–100)** | ✅ Shipped | Formula-based ranking (`docs/scoring.md`) |
| **Executive Markdown & CSV Reports** | ✅ Shipped | `--format md` and `--format csv` outputs |
| **Zero-Install Demo Mode** | ✅ Shipped | `cbomscan demo` runs on embedded synthetic project |
| **CI Failure Gating** | ✅ Shipped | `--fail-on critical` exits non-zero for CI pipelines |

---

## 3. Installation

Download pre-compiled static binaries from [GitHub Releases](https://github.com/hashim-work-svg/cbomscan/releases), or install via Go:

```bash
go install github.com/hashim-work-svg/cbomscan/cmd/cbomscan@latest
```

Or build from source:

```bash
git clone https://github.com/hashim-work-svg/cbomscan.git
cd cbomscan
make build-static
```

---

## 4. Quickstart

### Zero-Install Demo:
Run a complete demonstration against an embedded synthetic microservice:
```bash
cbomscan demo
```

### Scan a Repository or Directory:
```bash
# Scan current directory for cryptographic usage and certificates
cbomscan scan .

# Scan specific path and export CycloneDX 1.6 CBOM JSON
cbomscan scan ./src --format cbom -o cbom.json

# Generate executive Markdown summary
cbomscan scan ./src --format md -o report.md

# Generate CSV export
cbomscan scan ./src --format csv -o findings.csv

# CI/CD Gate: Fail build if any Critical findings exist
cbomscan scan . --fail-on critical
```

### Scan an X.509 Certificate:
```bash
cbomscan scan /etc/ssl/certs/server.crt
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
