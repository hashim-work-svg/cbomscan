package main

import (
	"testing"
)

func TestIsCertExt(t *testing.T) {
	tests := []struct {
		ext      string
		expected bool
	}{
		{".crt", true},
		{".pem", true},
		{".der", true},
		{".cer", true},
		{".go", false},
		{".py", false},
		{".txt", false},
	}

	for _, tt := range tests {
		if got := isCertExt(tt.ext); got != tt.expected {
			t.Errorf("isCertExt(%q) = %v; want %v", tt.ext, got, tt.expected)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short string failed: got %q", got)
	}
	if got := truncate("very long string exceeding length", 10); got != "very lo..." {
		t.Errorf("truncate long string failed: got %q", got)
	}
}

func TestInitializeRuleEngine(t *testing.T) {
	engine, err := initializeRuleEngine()
	if err != nil {
		t.Fatalf("initializeRuleEngine failed: %v", err)
	}
	if len(engine.Rules()) == 0 {
		t.Errorf("expected embedded rules to be loaded, got 0")
	}
}
