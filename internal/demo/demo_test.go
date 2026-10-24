package demo

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

func TestRunDemo(t *testing.T) {
	engine := rules.NewEngine()
	// Add test rules covering the demo items
	testYAML := []byte(`
rules:
  - id: "demo-rsa"
    pattern: 'rsa\.GenerateKey'
    classification: "quantum-vulnerable"
    algorithm: "RSA"
  - id: "demo-md5"
    pattern: 'md5\.New'
    classification: "legacy-broken"
    algorithm: "MD5"
  - id: "demo-aes"
    pattern: 'aes\.NewCipher'
    classification: "quantum-safer-candidate"
    algorithm: "AES"
  - id: "demo-tls"
    languages: ["configs"]
    pattern: 'TLSv1\.0'
    classification: "legacy-broken"
    algorithm: "TLSv1.0"
`)
	if err := engine.LoadFromYAML(testYAML); err != nil {
		t.Fatalf("failed to load test rules: %v", err)
	}

	var buf bytes.Buffer
	if err := Run(engine, "table", &buf); err != nil {
		t.Fatalf("Run table demo failed: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "CBOM-Scan Zero-Install Demonstration") {
		t.Errorf("expected demo header in output, got: %s", output)
	}
	if !strings.Contains(output, "demo-rsa") {
		t.Errorf("expected demo-rsa finding in output")
	}
	if !strings.Contains(output, "gateway_legacy.crt") {
		t.Errorf("expected demo certificate in output")
	}

	// Test markdown format
	var mdBuf bytes.Buffer
	if err := Run(engine, "md", &mdBuf); err != nil {
		t.Fatalf("Run md demo failed: %v", err)
	}
	if !strings.Contains(mdBuf.String(), "# Cryptographic Bill of Materials (CBOM)") {
		t.Errorf("expected markdown header in demo md output")
	}

	// Test csv format
	var csvBuf bytes.Buffer
	if err := Run(engine, "csv", &csvBuf); err != nil {
		t.Fatalf("Run csv demo failed: %v", err)
	}
	if !strings.Contains(csvBuf.String(), "AssetType,Identifier,Algorithm") {
		t.Errorf("expected csv header in demo csv output")
	}
}
