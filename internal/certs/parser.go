package certs

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

// ParseCertificateFile opens and inspects a PEM or DER certificate file.
func ParseCertificateFile(filePath string) ([]CertificateAnalysis, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %q: %w", filePath, err)
	}
	return ParseCertificateBytes(data, filePath)
}

// ParseCertificateBytes parses raw PEM or DER encoded bytes into certificate analyses.
func ParseCertificateBytes(data []byte, filePath string) ([]CertificateAnalysis, error) {
	var certs []*x509.Certificate

	// Try PEM decoding
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" || strings.Contains(block.Type, "CERTIFICATE") {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, c)
			}
		}
	}

	// If no PEM certificates found, attempt DER decoding
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, c)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoCertificateFound, filePath)
	}

	analyses := make([]CertificateAnalysis, 0, len(certs))
	now := time.Now().UTC()

	for _, cert := range certs {
		analysis := analyzeSingleCertificate(cert, filePath, now)
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// analyzeSingleCertificate inspects key parameters, algorithms, and evaluates post-quantum risk.
func analyzeSingleCertificate(cert *x509.Certificate, filePath string, now time.Time) CertificateAnalysis {
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	analysis := CertificateAnalysis{
		FilePath:           filePath,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    daysUntilExpiry,
		IsExpired:          isExpired,
		Classification:     rules.RiskQuantumVulnerable, // default for asymmetric certs
		RiskReasons:        make([]string, 0),
	}

	// Analyze public key
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		analysis.KeyType = "RSA"
		analysis.KeySizeBits = pub.N.BitLen()
		if analysis.KeySizeBits < 2048 {
			analysis.Classification = rules.RiskLegacyBroken
			analysis.RiskReasons = append(analysis.RiskReasons, fmt.Sprintf("RSA key size %d bits is legacy broken and cryptographically weak (< 2048 bits)", analysis.KeySizeBits))
			analysis.Recommendation = "Immediately upgrade key to at least RSA 3072 or prepare migration to ML-KEM / ML-DSA"
		} else {
			analysis.Classification = rules.RiskQuantumVulnerable
			analysis.RiskReasons = append(analysis.RiskReasons, "RSA public key is vulnerable to Shor's algorithm on cryptanalytically relevant quantum computers (CRQC)")
			analysis.Recommendation = "Plan transition to post-quantum signature algorithms (NIST FIPS 204 ML-DSA or FIPS 205 SLH-DSA)"
		}

	case *ecdsa.PublicKey:
		analysis.KeyType = "ECDSA"
		analysis.Curve = pub.Curve.Params().Name
		analysis.KeySizeBits = pub.Curve.Params().BitSize
		analysis.Classification = rules.RiskQuantumVulnerable
		analysis.RiskReasons = append(analysis.RiskReasons, fmt.Sprintf("Elliptic curve cryptography (%s) is vulnerable to Shor's discrete logarithm quantum attack", analysis.Curve))
		analysis.Recommendation = "Plan transition to hybrid classical/PQC or pure ML-DSA stateful signature algorithms"

	case ed25519.PublicKey:
		analysis.KeyType = "Ed25519"
		analysis.KeySizeBits = 256
		analysis.Classification = rules.RiskQuantumVulnerable
		analysis.RiskReasons = append(analysis.RiskReasons, "Ed25519 is vulnerable to Shor's algorithm for elliptic curve discrete logarithms")
		analysis.Recommendation = "Plan transition to stateful hash-based or lattice-based PQC signatures"

	case *dsa.PublicKey:
		analysis.KeyType = "DSA"
		analysis.KeySizeBits = pub.Parameters.P.BitLen()
		analysis.Classification = rules.RiskLegacyBroken
		analysis.RiskReasons = append(analysis.RiskReasons, "Digital Signature Algorithm (DSA) is deprecated and legacy broken")
		analysis.Recommendation = "Replace DSA with modern quantum-safer or post-quantum signature schemes immediately"

	default:
		analysis.KeyType = "Unknown"
		analysis.Classification = rules.RiskUnknown
		analysis.RiskReasons = append(analysis.RiskReasons, "Unrecognized public key algorithm")
	}

	// Check signature algorithm for legacy hash degradation
	sigLower := strings.ToLower(analysis.SignatureAlgorithm)
	if strings.Contains(sigLower, "md5") || strings.Contains(sigLower, "sha1") {
		analysis.Classification = rules.RiskLegacyBroken
		analysis.RiskReasons = append(analysis.RiskReasons, fmt.Sprintf("Signature algorithm %s uses a deprecated hash vulnerable to collision attacks", analysis.SignatureAlgorithm))
	}

	if isExpired {
		analysis.RiskReasons = append(analysis.RiskReasons, fmt.Sprintf("Certificate expired %d days ago", -daysUntilExpiry))
	}

	return analysis
}
