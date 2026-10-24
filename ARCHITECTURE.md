# Architecture: CBOM-Scan

`cbomscan` discovers and inventories cryptographic assets across source code repositories, configurations, and X.509 certificates, computes post-quantum migration risk scores, and outputs a standard CycloneDX Cryptographic Bill of Materials (CBOM).

## System Architecture Diagram

```mermaid
flowchart TD
    subgraph Targets["Scan Targets"]
        SrcCode["Source Code Files\n(Go, Python, Java, JS/TS)"]
        Configs["Configurations\n(nginx.conf, sshd_config, OpenSSL)"]
        Certs["X.509 Certificates\n(PEM and DER Encoded)"]
    end

    subgraph Scanner["CBOM-Scan Engine (Single Static Go Binary)"]
        TargetRouter{"Target File Router"}
        
        subgraph RegexEngine["Rule Matching Engine (internal/rules)"]
            RuleEmbed["Embedded YAML Rules\n(go:embed rules/*.yaml)"]
            Matcher["Line-by-Line Regex Matcher\n(Extracts Line Numbers & Snippets)"]
        end

        subgraph CertEngine["X.509 Analysis Engine (internal/certs)"]
            ASN1["ASN.1 / PEM Decoder\n(crypto/x509 & encoding/pem)"]
            KeyInspector["Key & Curve Inspector\n(RSA BitLen, Curve, Expiry)"]
        end

        subgraph Scoring["Risk & Priority Model (internal/score)"]
            Classifier["Post-Quantum Risk Classifier\n(quantum-vulnerable, legacy-broken,\nquantum-safer-candidate)"]
            PriorityScore["Migration Priority Scorer (0-100)\n(Context multiplier + Expiry factor)"]
        end

        subgraph Exporters["Report & CBOM Exporters (internal/cbom, report)"]
            CBOMGen["CycloneDX CBOM JSON Generator\n(cryptographic-asset component schema)"]
            MDGen["Markdown Summary Report Generator"]
            CSVGen["CSV Findings Exporter"]
        end
    end

    subgraph Deliverables["Inspection Artifacts"]
        Console["Terminal Colorized Tables"]
        CBOMJSON["output.cbom.json (CycloneDX 1.6)"]
        MDReport["cbom-report.md"]
        CSVReport["findings.csv"]
    end

    SrcCode --> TargetRouter
    Configs --> TargetRouter
    Certs --> TargetRouter

    TargetRouter -->|".go, .py, .java, .js, .conf"| Matcher
    RuleEmbed -.-> Matcher
    TargetRouter -->|".crt, .pem, .der"| ASN1
    ASN1 --> KeyInspector

    Matcher --> Classifier
    KeyInspector --> Classifier
    Classifier --> PriorityScore

    PriorityScore --> Console
    PriorityScore --> CBOMGen
    PriorityScore --> MDGen
    PriorityScore --> CSVGen

    CBOMGen --> CBOMJSON
    MDGen --> MDReport
    CSVGen --> CSVReport
```

## Core Modules

1. **Rule Engine (`internal/rules`):**
   Loads embedded language and config rules. Uses compiled Go regular expressions to inspect files line-by-line, capturing line numbers, source snippets, and matched cryptographic tokens.

2. **Certificate Parser (`internal/certs`):**
   Decodes PEM blocks and raw DER byte sequences using standard library `crypto/x509`. Extracts asymmetric public key algorithms, RSA bit lengths, elliptic curves, validity dates, days until expiry, and signature digests.

3. **Risk Classifier:**
   Enforces NIST post-quantum guidance:
   - `quantum-vulnerable`: Asymmetric algorithms broken by Shor's algorithm (RSA, ECC, ECDH, ECDSA).
   - `legacy-broken`: Obsolete or cryptanalytically broken algorithms (MD5, SHA-1, DES, 3DES, RC4).
   - `quantum-safer-candidate`: Symmetric ciphers $\ge$ 128-bit security and approved PQC candidates (AES-256, SHA-256, ML-KEM, ML-DSA).

4. **Migration Scorer (`docs/scoring.md`):**
   Calculates a standardized $0-100$ priority score factoring in algorithmic vulnerability, sensitive path indicators (`auth`, `payment`), and certificate expiry urgency.
