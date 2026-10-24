// Package score implements the post-quantum cryptographic migration priority scoring engine.
package score

import (
	"math"
	"path/filepath"
	"strings"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

// Tier represents the priority tier for cryptographic migration.
type Tier string

const (
	TierCritical Tier = "CRITICAL"
	TierHigh     Tier = "HIGH"
	TierMedium   Tier = "MEDIUM"
	TierLow      Tier = "LOW"
)

// ScoredFinding wraps a Finding with its computed priority score and tier.
type ScoredFinding struct {
	Finding    rules.Finding
	Score      int
	Tier       Tier
	Multiplier float64
	Formula    string
}

// ScoredCertificate wraps a CertificateAnalysis with its computed priority score and tier.
type ScoredCertificate struct {
	Analysis   certs.CertificateAnalysis
	Score      int
	Tier       Tier
	Multiplier float64
	ExpiryAdd  int
	Formula    string
}

// CalculateFindingScore calculates the 0-100 migration priority score for a code or config finding.
func CalculateFindingScore(f rules.Finding) ScoredFinding {
	base := getBaseWeight(f.Classification)
	multiplier := getContextMultiplier(f.FilePath)

	raw := float64(base) * multiplier
	finalScore := int(math.Round(raw))
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	return ScoredFinding{
		Finding:    f,
		Score:      finalScore,
		Tier:       classifyTier(finalScore),
		Multiplier: multiplier,
	}
}

// CalculateCertificateScore calculates the 0-100 migration priority score for an X.509 certificate.
func CalculateCertificateScore(c certs.CertificateAnalysis) ScoredCertificate {
	base := getBaseWeight(c.Classification)
	multiplier := getContextMultiplier(c.FilePath)
	expiryAdd := getExpiryFactor(c.IsExpired, c.DaysUntilExpiry)

	raw := (float64(base) * multiplier) + float64(expiryAdd)
	finalScore := int(math.Round(raw))
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	return ScoredCertificate{
		Analysis:   c,
		Score:      finalScore,
		Tier:       classifyTier(finalScore),
		Multiplier: multiplier,
		ExpiryAdd:  expiryAdd,
	}
}

func getBaseWeight(classification rules.RiskClassification) int {
	switch classification {
	case rules.RiskLegacyBroken:
		return 85
	case rules.RiskQuantumVulnerable:
		return 50
	case rules.RiskQuantumSaferCandidate:
		return 10
	default:
		return 25
	}
}

func getContextMultiplier(path string) float64 {
	cleanPath := strings.ToLower(filepath.ToSlash(path))

	// Test files have lower remediation priority
	testKeywords := []string{"test", "tests", "mock", "mocks", "fixture", "fixtures", "stub", "stubs"}
	for _, kw := range testKeywords {
		if hasPathToken(cleanPath, kw) {
			return 0.5
		}
	}

	// Payment/financial paths have highest exposure
	paymentKeywords := []string{"payment", "payments", "billing", "card", "cards", "stripe", "checkout"}
	for _, kw := range paymentKeywords {
		if hasPathToken(cleanPath, kw) {
			return 1.4
		}
	}

	// Authentication and security paths
	authKeywords := []string{"auth", "login", "oauth", "token", "tokens", "session", "sessions", "jwt"}
	for _, kw := range authKeywords {
		if hasPathToken(cleanPath, kw) {
			return 1.3
		}
	}

	pkiKeywords := []string{"pki", "cert", "certs", "tls", "ssl", "vault", "kms"}
	for _, kw := range pkiKeywords {
		if hasPathToken(cleanPath, kw) {
			return 1.3
		}
	}

	return 1.0
}

func hasPathToken(path, token string) bool {
	// Token boundary match on path segments to avoid false positives (e.g. "card" in "discard")
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\' || r == '_' || r == '-' || r == '.'
	})
	for _, p := range parts {
		if p == token {
			return true
		}
	}
	return false
}

func getExpiryFactor(isExpired bool, daysUntilExpiry int) int {
	if isExpired || daysUntilExpiry <= 0 {
		return 25
	}
	if daysUntilExpiry <= 30 {
		return 20
	}
	if daysUntilExpiry <= 90 {
		return 10
	}
	return 0
}

func classifyTier(score int) Tier {
	switch {
	case score >= 85:
		return TierCritical
	case score >= 60:
		return TierHigh
	case score >= 35:
		return TierMedium
	default:
		return TierLow
	}
}
