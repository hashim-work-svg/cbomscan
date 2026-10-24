package cbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
	"github.com/hashim-work-svg/cbomscan/internal/score"
)

func TestGenerateCBOM(t *testing.T) {
	finding := rules.Finding{
		RuleID:         "go-rsa-usage",
		Algorithm:      "RSA",
		Classification: rules.RiskQuantumVulnerable,
		Severity:       "high",
		FilePath:       "internal/auth/signer.go",
		LineNumber:     42,
		MatchedText:    "rsa.GenerateKey(rand.Reader, 2048)",
		Recommendation: "Migrate to ML-DSA",
	}
	scoredFinding := score.CalculateFindingScore(finding)

	cert := certs.CertificateAnalysis{
		FilePath:           "certs/gateway.pem",
		Subject:            "CN=api.gateway.local",
		Issuer:             "CN=Internal CA",
		KeyType:            "ECDSA",
		Curve:              "P-256",
		KeySizeBits:        256,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(60 * 24 * time.Hour),
		DaysUntilExpiry:    60,
		IsExpired:          false,
		Classification:     rules.RiskQuantumVulnerable,
		Recommendation:     "Plan migration to ML-DSA",
	}
	scoredCert := score.CalculateCertificateScore(cert)

	exporter := NewExporter("v0.1.0-test")
	doc, err := exporter.GenerateCBOM([]score.ScoredFinding{scoredFinding}, []score.ScoredCertificate{scoredCert})
	if err != nil {
		t.Fatalf("GenerateCBOM failed: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOMFormat CycloneDX, got %s", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("expected SpecVersion 1.6, got %s", doc.SpecVersion)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(doc.Components))
	}

	// Validate JSON marshaling
	jsonBytes, err := doc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("failed to unmarshal generated CBOM JSON: %v", err)
	}

	components, ok := raw["components"].([]interface{})
	if !ok || len(components) != 2 {
		t.Fatalf("invalid components structure in JSON: %v", raw["components"])
	}

	// Check cryptographic properties
	comp0 := components[0].(map[string]interface{})
	if comp0["type"] != "cryptographic-asset" {
		t.Errorf("expected component type cryptographic-asset, got %v", comp0["type"])
	}
	cryptoProps, ok := comp0["cryptoProperties"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing cryptoProperties on component 0")
	}
	if cryptoProps["assetType"] != "algorithm" {
		t.Errorf("expected assetType algorithm, got %v", cryptoProps["assetType"])
	}
}
