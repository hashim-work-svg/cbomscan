# Security Policy: CBOM-Scan

## Threat Model & Considerations

`cbomscan` is a static analysis and cryptographic auditing tool that inspects untrusted source files, configurations, and X.509 certificate files.

| Risk Area | Mitigation Implemented | Residual Risk |
| :--- | :--- | :--- |
| **Malformed / Malicious Certificates** | Standard library `crypto/x509` ASN.1 parser with bounded buffer sizes; graceful error handling for unparseable certificates. | Memory consumption on extremely large invalid DER sequences. |
| **ReDoS (Regular Expression Denial of Service)** | Compiled, anchor-aware regex rules with bounded string inputs; line-by-line streaming scanning via `bufio.Scanner`. | Extremely long single-line minified files (mitigated by file size guards). |
| **Credential & Private Key Exposure** | Strictly inspects public certificates (`x509.Certificate`) and source references; never stores, extracts, or transmits private keys. | Users scanning files containing embedded unencrypted private keys. |
| **Network Scanning Limits** | The tool exclusively performs local file analysis. No unauthorized network or port scanning. | User opt-in TLS probing against unauthorized target domains. |

## Not Legal or Cryptographic Certification Notice

> [!IMPORTANT]
> **Notice:** `cbomscan` is an automated scanning heuristic. Regex-based pattern matching can produce false positives and false negatives (e.g., variable names containing algorithm substrings, or obfuscated dynamic invocations). It does not substitute for formal FIPS 140-3 cryptographic module validation or compliance auditing.

## Reporting a Security Vulnerability

If you identify a security issue in `cbomscan`, please report it responsibly by emailing `security@example.corp` or opening a private GitHub Security Advisory.
