package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

// generateTestCert creates a throwaway self-signed certificate in memory.
func generateTestCert(t *testing.T, priv crypto.Signer, isExpired bool) (pemBytes, derBytes []byte) {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if isExpired {
		notBefore = time.Now().Add(-720 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "test-crypto-device.local",
			Organization: []string{"Acme Test Corp"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	return pemData, der
}

func TestCertificateAnalysis(t *testing.T) {
	t.Run("RSA 2048 Certificate (Quantum Vulnerable)", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate rsa 2048 key: %v", err)
		}
		pemData, _ := generateTestCert(t, key, false)

		analyses, err := ParseCertificateBytes(pemData, "server.crt")
		if err != nil {
			t.Fatalf("failed to parse certificate: %v", err)
		}
		if len(analyses) != 1 {
			t.Fatalf("expected 1 analysis, got %d", len(analyses))
		}

		res := analyses[0]
		if res.KeyType != "RSA" {
			t.Errorf("expected KeyType RSA, got %s", res.KeyType)
		}
		if res.KeySizeBits != 2048 {
			t.Errorf("expected KeySizeBits 2048, got %d", res.KeySizeBits)
		}
		if res.Classification != rules.RiskQuantumVulnerable {
			t.Errorf("expected classification %s, got %s", rules.RiskQuantumVulnerable, res.Classification)
		}
		if res.IsExpired {
			t.Errorf("expected valid cert, got expired")
		}
	})

	t.Run("RSA 1024 Certificate (Legacy Broken)", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate rsa 1024 key: %v", err)
		}
		pemData, _ := generateTestCert(t, key, false)

		analyses, err := ParseCertificateBytes(pemData, "legacy.crt")
		if err != nil {
			t.Fatalf("failed to parse legacy cert: %v", err)
		}
		res := analyses[0]
		if res.KeySizeBits != 1024 {
			t.Errorf("expected 1024 bits, got %d", res.KeySizeBits)
		}
		if res.Classification != rules.RiskLegacyBroken {
			t.Errorf("expected classification %s, got %s", rules.RiskLegacyBroken, res.Classification)
		}
	})

	t.Run("ECDSA P-256 Certificate (Quantum Vulnerable)", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ecdsa key: %v", err)
		}
		pemData, _ := generateTestCert(t, key, false)

		analyses, err := ParseCertificateBytes(pemData, "ecdsa.crt")
		if err != nil {
			t.Fatalf("failed to parse ecdsa cert: %v", err)
		}
		res := analyses[0]
		if res.KeyType != "ECDSA" {
			t.Errorf("expected ECDSA, got %s", res.KeyType)
		}
		if res.Curve != "P-256" {
			t.Errorf("expected curve P-256, got %s", res.Curve)
		}
		if res.Classification != rules.RiskQuantumVulnerable {
			t.Errorf("expected classification %s, got %s", rules.RiskQuantumVulnerable, res.Classification)
		}
	})

	t.Run("Ed25519 Certificate (Quantum Vulnerable)", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		pemData, _ := generateTestCert(t, priv, false)

		analyses, err := ParseCertificateBytes(pemData, "ed25519.crt")
		if err != nil {
			t.Fatalf("failed to parse ed25519 cert: %v", err)
		}
		res := analyses[0]
		if res.KeyType != "Ed25519" {
			t.Errorf("expected Ed25519, got %s", res.KeyType)
		}
		if res.Classification != rules.RiskQuantumVulnerable {
			t.Errorf("expected classification %s, got %s", rules.RiskQuantumVulnerable, res.Classification)
		}
	})

	t.Run("Expired Certificate Check", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate rsa key: %v", err)
		}
		pemData, _ := generateTestCert(t, key, true)

		analyses, err := ParseCertificateBytes(pemData, "expired.crt")
		if err != nil {
			t.Fatalf("failed to parse expired cert: %v", err)
		}
		res := analyses[0]
		if !res.IsExpired {
			t.Errorf("expected isExpired to be true")
		}
		if res.DaysUntilExpiry >= 0 {
			t.Errorf("expected negative days until expiry for expired cert, got %d", res.DaysUntilExpiry)
		}
	})

	t.Run("DER Formatted Certificate", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		_, derData := generateTestCert(t, key, false)

		analyses, err := ParseCertificateBytes(derData, "raw.der")
		if err != nil {
			t.Fatalf("failed to parse DER cert: %v", err)
		}
		if len(analyses) != 1 {
			t.Fatalf("expected 1 analysis from DER, got %d", len(analyses))
		}
	})

	t.Run("Invalid Non-Certificate Data", func(t *testing.T) {
		_, err := ParseCertificateBytes([]byte("random junk not a cert"), "bad.crt")
		if err == nil {
			t.Fatal("expected error on invalid data, got nil")
		}
	})

	t.Run("ParseCertificateFile with Valid and Invalid Paths", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pemData, _ := generateTestCert(t, key, false)

		tmpFile, err := os.CreateTemp("", "testcert-*.crt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(pemData); err != nil {
			t.Fatalf("failed to write cert data: %v", err)
		}
		tmpFile.Close()

		analyses, err := ParseCertificateFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("ParseCertificateFile failed: %v", err)
		}
		if len(analyses) != 1 {
			t.Fatalf("expected 1 analysis, got %d", len(analyses))
		}

		// Non-existent file
		_, err = ParseCertificateFile("non_existent_file.crt")
		if err == nil {
			t.Fatal("expected error for non-existent file, got nil")
		}
	})
}
