# Security Policy: CBOM-Scan

## Threat Model & Considerations

`cbomscan` is a static analysis and cryptographic auditing tool that inspects untrusted source files, configurations, and X.509 certificate files.

| Risk Area | Mitigation Implemented | Residual Risk |
| :--- | :--- | :--- |
| **Malformed / Malicious Certificates** | Standard library `crypto/x509` ASN.1 parser with bounded buffer sizes; graceful error handling for unparseable certificates. | Memory consumption on extremely large invalid DER sequences. |
| **ReDoS / Resource Exhaustion** | Go's standard `regexp` engine uses RE2 (guaranteed linear time $O(n)$ matching with no backtracking, mathematically immune to exponential backtracking ReDoS). Bounded line buffers (2MB) and file size guards (10MB limit) prevent memory exhaustion. | Highly obfuscated code paths not expressible via static regex patterns. |
| **Credential & Private Key Exposure** | Strictly inspects public certificates (`x509.Certificate`) and source references; never stores, extracts, or transmits private keys. | Users scanning directories containing unencrypted private keys. |
| **Network Scanning Limits** | The tool exclusively performs local file analysis. No unauthorized network or port scanning. | Local inspection only. |

## Not Legal or Cryptographic Certification Notice

> [!IMPORTANT]
> **Notice:** `cbomscan` is an automated scanning heuristic. Regex-based pattern matching can produce false positives and false negatives (e.g., variable names containing algorithm substrings, or obfuscated dynamic invocations). It does not substitute for formal FIPS 140-3 cryptographic module validation or compliance auditing.

## Reporting a Security Vulnerability

If you identify a security issue in `cbomscan`, please open a private [GitHub Security Advisory](https://github.com/hashim-work-svg/cbomscan/security/advisories/new). Do not report security vulnerabilities via public GitHub issues.
