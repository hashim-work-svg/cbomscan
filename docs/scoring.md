# Post-Quantum Cryptographic Migration Priority Scoring Model

## 1. Objective

To provide security engineering teams with an automated, transparent, and reproducible priority ranking for replacing classical algorithms before NIST post-quantum deprecation dates (2030 deprecation, 2035 disallowance).

---

## 2. Scoring Formula

The **Migration Priority Score ($S$)** is calculated on a scale of **0 to 100**:

$$S = \min\left(100, \; B \times M_{\text{context}} + P_{\text{expiry}}\right)$$

Where:
* **$B$ (Base Classification Weight):**
  * `legacy-broken` (MD5, SHA-1, DES, 3DES, RC4, RSA < 2048): **$B = 80$** (Immediate compliance hazard).
  * `quantum-vulnerable` (RSA $\ge$ 2048, ECC, ECDH, ECDSA, Ed25519): **$B = 50$** (Subject to Store-Now-Decrypt-Later and Shor's algorithm).
  * `quantum-safer-candidate` (AES-256, SHA-256+, ML-KEM, ML-DSA): **$B = 10$** (Informational / Verification only).
  * `unknown`: **$B = 25$**.

* **$M_{\text{context}}$ (Path & Data Sensitivity Multiplier):**
  Identifies high-value attack surfaces based on component file paths:
  * Contains `auth`, `login`, `oauth`, `token`, `session`, `jwt`: **$1.3\times$**
  * Contains `payment`, `billing`, `card`, `stripe`, `checkout`: **$1.4\times$**
  * Contains `pki`, `cert`, `tls`, `ssl`, `vault`, `kms`: **$1.3\times$**
  * Contains `test`, `mock`, `fixture`: **$0.5\times$** (Reduced priority for test files)
  * Default: **$1.0\times$**

* **$P_{\text{expiry}}$ (Certificate Expiry Urgency Factor):**
  Applied exclusively to X.509 certificates based on remaining validity:
  * Already Expired: **$+25$**
  * Expiring within $\le 30$ days: **$+20$**
  * Expiring within $\le 90$ days: **$+10$**
  * Valid $> 90$ days: **$+0$**

---

## 3. Priority Tiers & Action Plan

| Score Range | Priority Tier | Recommended Remediation SLA |
| :---: | :--- | :--- |
| **85 – 100** | 🔴 **Critical** | Remediation required within **30 days** (Broken algorithms or active exposure in critical path). |
| **60 – 84** | 🟠 **High** | Plan replacement within **90 days** (Vulnerable public keys in auth or payment paths). |
| **35 – 59** | 🟡 **Medium** | Schedule into annual PQC migration roadmap (NIST FIPS 203/204 target). |
| **0 – 34** | 🟢 **Low / Info** | Audit and verify 256-bit key lengths; no immediate action required. |
