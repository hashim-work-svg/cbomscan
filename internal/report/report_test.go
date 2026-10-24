package report

import (
	"strings"
	"testing"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
	"github.com/hashim-work-svg/cbomscan/internal/score"
)

func TestGenerateMarkdownAndCSV(t *testing.T) {
	finding := rules.Finding{
		RuleID:         "go-md5-broken",
		Algorithm:      "MD5",
		Classification: rules.RiskLegacyBroken,
		Severity:       "critical",
		FilePath:       "internal/hash/md5.go",
		LineNumber:     15,
		MatchedText:    "md5.New()",
		Recommendation: "Upgrade to SHA-256",
	}
	scoredFinding := score.CalculateFindingScore(finding)

	cert := certs.CertificateAnalysis{
		FilePath:           "certs/tls.crt",
		Subject:            "CN=test.example.com",
		Issuer:             "CN=Root CA",
		KeyType:            "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Now().Add(-100 * 24 * time.Hour),
		NotAfter:           time.Now().Add(10 * 24 * time.Hour),
		DaysUntilExpiry:    10,
		IsExpired:          false,
		Classification:     rules.RiskQuantumVulnerable,
		Recommendation:     "Migrate to ML-DSA",
	}
	scoredCert := score.CalculateCertificateScore(cert)

	findings := []score.ScoredFinding{scoredFinding}
	certsList := []score.ScoredCertificate{scoredCert}

	// Test Markdown
	md := GenerateMarkdown(findings, certsList)
	if !strings.Contains(md, "Cryptographic Bill of Materials (CBOM) & Risk Report") {
		t.Errorf("expected markdown header, got: %s", md)
	}
	if !strings.Contains(md, "go-md5-broken") {
		t.Errorf("expected rule ID in markdown report, got: %s", md)
	}
	if !strings.Contains(md, "test.example.com") {
		t.Errorf("expected cert subject in markdown report, got: %s", md)
	}

	// Test CSV
	csvBytes, err := GenerateCSV(findings, certsList)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}
	csvStr := string(csvBytes)
	if !strings.Contains(csvStr, "AssetType,Identifier,Algorithm") {
		t.Errorf("expected CSV header, got: %s", csvStr)
	}
	if !strings.Contains(csvStr, "go-md5-broken") {
		t.Errorf("expected rule ID in CSV, got: %s", csvStr)
	}
}
