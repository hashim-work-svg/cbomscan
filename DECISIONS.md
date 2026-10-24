# Architecture Decision Records (ADRs) - CBOM-Scan

## ADR-0001: Pure-Go Static Single-Binary Architecture (CGO_ENABLED=0)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  A cryptographic asset scanner must deploy effortlessly across CI/CD runners, container images, developer laptops, and air-gapped auditor environments without external C libraries or dynamic linking issues.
* **Decision:**
  Compile all binaries with `CGO_ENABLED=0`. Rely solely on Go standard library (`crypto/x509`, `encoding/pem`) and pure-Go YAML parsers (`gopkg.in/yaml.v3`).
* **Consequences:**
  Cross-compilation for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64) produces 100% statically linked executables with zero external dependencies.

---

## ADR-0002: Dual Inspection Engine (Regex Source Rules + Native X.509 ASN.1)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Cryptographic usage exists in both source code (API imports and method calls) and deployed assets (TLS certificates). Tree-sitter parsers add massive CGo overhead and compilation complexity.
* **Decision:**
  Implement a dual-engine architecture:
  1. Data-driven, line-by-line regular expression rules defined in embedded YAML files (`rules/*.yaml`) for source code and server configurations.
  2. Native Go ASN.1/DER/PEM certificate parsing using `crypto/x509` for cryptographic certificates.
* **Consequences:**
  Fast, extensible, and pure-Go without heavy tree-sitter or C compilation overhead.

---

## ADR-0003: Post-Quantum Risk Classification Taxonomy
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Security teams must distinguish between legacy algorithmic failures (e.g. MD5 collision attacks) and future quantum-computing threats (e.g. Shor's algorithm breaking RSA/ECC).
* **Decision:**
  Adopt a four-tier risk classification taxonomy:
  - `quantum-vulnerable`: RSA, ECC, DH, ECDH, ECDSA.
  - `legacy-broken`: MD5, SHA-1, DES, 3DES, RC4, RSA < 2048.
  - `quantum-safer-candidate`: AES-256, SHA-256+, ML-KEM, ML-DSA.
  - `unknown`: Unrecognized or ambiguous primitives.
* **Consequences:**
  Directly aligns with NIST IR 8547 and FIPS 203/204/205 post-quantum migration standards.

---

## ADR-0004: In-Memory Ephemeral Certificate Generation for Tests
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Committed cryptographic private keys in git repositories trigger security alarms, violate security hygiene policies, and risk credential leakage.
* **Decision:**
  Generate all test certificates dynamically in memory at test execution time using standard library `crypto/rand`, `crypto/rsa`, `crypto/ecdsa`, and `crypto/ed25519`. Never commit static private keys to the repository.
* **Consequences:**
  Guarantees zero credentials or static private keys in version control while achieving comprehensive test coverage across RSA, ECC, Ed25519, and expired certificates.
