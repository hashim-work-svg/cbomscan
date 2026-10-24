package rules

import (
	"os"
	"testing"
)

func TestEngineLoadAndScan(t *testing.T) {
	sampleYAML := []byte(`
rules:
  - id: "test-rsa"
    name: "RSA Usage"
    description: "Detects RSA usage"
    languages: ["go"]
    file_globs: ["*.go"]
    pattern: 'rsa\.GenerateKey'
    classification: "quantum-vulnerable"
    algorithm: "RSA"
    severity: "high"
    recommendation: "Migrate to ML-DSA"

  - id: "test-md5"
    name: "MD5 Usage"
    description: "Detects MD5"
    languages: ["go"]
    file_globs: ["*.go"]
    pattern: 'md5\.New'
    classification: "legacy-broken"
    algorithm: "MD5"
    severity: "critical"
    recommendation: "Replace with SHA-256"

  - id: "test-aes"
    name: "AES Usage"
    description: "Detects AES"
    languages: ["go"]
    file_globs: ["*.go"]
    pattern: 'aes\.NewCipher'
    classification: "quantum-safer-candidate"
    algorithm: "AES"
    severity: "info"
    recommendation: "Use 256-bit keys"
`)

	engine := NewEngine()
	if err := engine.LoadFromYAML(sampleYAML); err != nil {
		t.Fatalf("failed to load rules from YAML: %v", err)
	}

	if len(engine.Rules()) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(engine.Rules()))
	}

	// Test Go code scan with positive matches
	goSource := []byte(`package main

import "crypto/rsa"
import "crypto/md5"
import "crypto/aes"

func main() {
    // Line 8: RSA
    key, _ := rsa.GenerateKey(nil, 2048)
    _ = key

    // Line 12: MD5
    h := md5.New()
    _ = h

    // Line 16: AES
    c, _ := aes.NewCipher([]byte("12345678901234567890123456789012"))
    _ = c
}
`)

	findings := engine.ScanContent("main.go", goSource)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Verify classifications and line numbers
	findingMap := make(map[string]Finding)
	for _, f := range findings {
		findingMap[f.RuleID] = f
	}

	rsaFinding, ok := findingMap["test-rsa"]
	if !ok {
		t.Fatal("missing test-rsa finding")
	}
	if rsaFinding.Classification != RiskQuantumVulnerable {
		t.Errorf("expected classification %s, got %s", RiskQuantumVulnerable, rsaFinding.Classification)
	}
	if rsaFinding.LineNumber != 9 {
		t.Errorf("expected line number 9, got %d", rsaFinding.LineNumber)
	}

	md5Finding, ok := findingMap["test-md5"]
	if !ok {
		t.Fatal("missing test-md5 finding")
	}
	if md5Finding.Classification != RiskLegacyBroken {
		t.Errorf("expected classification %s, got %s", RiskLegacyBroken, md5Finding.Classification)
	}
	if md5Finding.LineNumber != 13 {
		t.Errorf("expected line number 13, got %d", md5Finding.LineNumber)
	}

	aesFinding, ok := findingMap["test-aes"]
	if !ok {
		t.Fatal("missing test-aes finding")
	}
	if aesFinding.Classification != RiskQuantumSaferCandidate {
		t.Errorf("expected classification %s, got %s", RiskQuantumSaferCandidate, aesFinding.Classification)
	}

	// Test negative match (clean code)
	cleanSource := []byte(`package main
func add(a, b int) int {
    return a + b
}
`)
	cleanFindings := engine.ScanContent("clean.go", cleanSource)
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings on clean code, got %d", len(cleanFindings))
	}

	// Test file extension filtering (python file should not match go rules)
	pySource := []byte(`key = rsa.GenerateKey()`)
	pyFindings := engine.ScanContent("test.py", pySource)
	if len(pyFindings) != 0 {
		t.Errorf("expected 0 findings for python file with go-only rules, got %d", len(pyFindings))
	}
}

func TestEngineInvalidRules(t *testing.T) {
	badRegexYAML := []byte(`
rules:
  - id: "bad-regex"
    pattern: "[invalid(regex"
`)
	engine := NewEngine()
	if err := engine.LoadFromYAML(badRegexYAML); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}

	missingIDYAML := []byte(`
rules:
  - id: ""
    pattern: "some_pattern"
`)
	if err := engine.LoadFromYAML(missingIDYAML); err == nil {
		t.Fatal("expected error for missing rule ID, got nil")
	}
}

func TestEngineScanFileAndLanguages(t *testing.T) {
	configYAML := []byte(`
rules:
  - id: "cfg-weak"
    name: "Weak SSL"
    languages: ["configs"]
    file_globs: ["*.conf", "sshd_config"]
    pattern: 'SSLv3'
    classification: "legacy-broken"
    algorithm: "SSLv3"
  - id: "py-crypto"
    name: "Python Crypto"
    languages: ["python"]
    pattern: 'Crypto\.Cipher'
    classification: "quantum-vulnerable"
  - id: "java-crypto"
    name: "Java Crypto"
    languages: ["java"]
    pattern: 'Cipher\.getInstance'
    classification: "quantum-vulnerable"
  - id: "js-crypto"
    name: "JS Crypto"
    languages: ["javascript"]
    pattern: 'crypto\.createCipher'
    classification: "legacy-broken"
`)

	engine := NewEngine()
	if err := engine.LoadFromYAML(configYAML); err != nil {
		t.Fatalf("failed to load config rules: %v", err)
	}

	// Test ScanFile with real temp file
	tmpFile, err := os.CreateTemp("", "nginx-*.conf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("ssl_protocols SSLv3;\n"); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	findings, err := engine.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in conf file, got %d", len(findings))
	}

	// Test non-existent file
	_, err = engine.ScanFile("non_existent_file.go")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	// Test Python matching
	pyFindings := engine.ScanContent("app.py", []byte("import Crypto.Cipher\n"))
	if len(pyFindings) != 1 {
		t.Errorf("expected 1 python finding, got %d", len(pyFindings))
	}

	// Test Java matching
	javaFindings := engine.ScanContent("App.java", []byte("Cipher.getInstance(\"RSA\");\n"))
	if len(javaFindings) != 1 {
		t.Errorf("expected 1 java finding, got %d", len(javaFindings))
	}

	// Test JS matching
	jsFindings := engine.ScanContent("index.js", []byte("const c = crypto.createCipher();\n"))
	if len(jsFindings) != 1 {
		t.Errorf("expected 1 js finding, got %d", len(jsFindings))
	}
}
