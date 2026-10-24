// Package rules implements data-driven cryptographic pattern matching,
// classification, and risk evaluation across source code and configuration files.
package rules

import (
	"fmt"
	"regexp"
)

// RiskClassification classifies a cryptographic finding by post-quantum and algorithmic longevity.
type RiskClassification string

const (
	// RiskQuantumVulnerable denotes public-key cryptography vulnerable to Shor's algorithm (RSA, ECC, DH).
	RiskQuantumVulnerable RiskClassification = "quantum-vulnerable"
	// RiskLegacyBroken denotes obsolete or cryptanalytically broken algorithms (MD5, SHA-1, DES, RC4).
	RiskLegacyBroken RiskClassification = "legacy-broken"
	// RiskQuantumSaferCandidate denotes symmetric algorithms >= 128-bit security or NIST PQC standards (AES-256, SHA-256+, ML-KEM, ML-DSA).
	RiskQuantumSaferCandidate RiskClassification = "quantum-safer-candidate"
	// RiskUnknown denotes unclassified or ambiguous cryptographic usage.
	RiskUnknown RiskClassification = "unknown"
)

// Rule defines a single pattern to identify cryptographic primitives.
type Rule struct {
	ID             string             `yaml:"id" json:"id"`
	Name           string             `yaml:"name" json:"name"`
	Description    string             `yaml:"description" json:"description"`
	Languages      []string           `yaml:"languages" json:"languages"`
	FileGlobs      []string           `yaml:"file_globs" json:"file_globs"`
	Pattern        string             `yaml:"pattern" json:"pattern"`
	Classification RiskClassification `yaml:"classification" json:"classification"`
	Algorithm      string             `yaml:"algorithm" json:"algorithm"`
	Severity       string             `yaml:"severity" json:"severity"`
	Recommendation string             `yaml:"recommendation" json:"recommendation"`

	CompiledRegex *regexp.Regexp `yaml:"-" json:"-"`
}

// Finding represents an identified cryptographic instance in a source file or configuration.
type Finding struct {
	RuleID         string             `json:"rule_id"`
	Algorithm      string             `json:"algorithm"`
	Classification RiskClassification `json:"classification"`
	Severity       string             `json:"severity"`
	FilePath       string             `json:"file_path"`
	LineNumber     int                `json:"line_number"`
	LineContent    string             `json:"line_content"`
	MatchedText    string             `json:"matched_text"`
	Recommendation string             `json:"recommendation"`
}

// RuleFile represents a collection of rules serialized in a YAML file.
type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

// ErrInvalidRule is returned when a rule definition has missing required fields or invalid regex.
var ErrInvalidRule = fmt.Errorf("invalid rule definition")
