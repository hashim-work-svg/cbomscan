package score

import (
	"testing"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

func TestCalculateFindingScore(t *testing.T) {
	tests := []struct {
		name           string
		classification rules.RiskClassification
		filePath       string
		expectedScore  int
		expectedTier   Tier
	}{
		{
			name:           "Legacy broken in standard file",
			classification: rules.RiskLegacyBroken,
			filePath:       "pkg/crypto/hash.go",
			expectedScore:  85,
			expectedTier:   TierCritical,
		},
		{
			name:           "Legacy broken in auth path",
			classification: rules.RiskLegacyBroken,
			filePath:       "internal/auth/login.go",
			expectedScore:  100, // 85 * 1.3 = 110.5 capped at 100
			expectedTier:   TierCritical,
		},
		{
			name:           "Legacy broken in payment path",
			classification: rules.RiskLegacyBroken,
			filePath:       "services/payment/checkout.go",
			expectedScore:  100, // 85 * 1.4 = 119 capped at 100
			expectedTier:   TierCritical,
		},
		{
			name:           "Legacy broken in test path",
			classification: rules.RiskLegacyBroken,
			filePath:       "internal/crypto/hash_test.go",
			expectedScore:  43, // 85 * 0.5 = 42.5 rounds to 43
			expectedTier:   TierMedium,
		},
		{
			name:           "Quantum vulnerable in standard file",
			classification: rules.RiskQuantumVulnerable,
			filePath:       "pkg/signer/rsa.go",
			expectedScore:  50,
			expectedTier:   TierMedium,
		},
		{
			name:           "Quantum vulnerable in auth path",
			classification: rules.RiskQuantumVulnerable,
			filePath:       "pkg/auth/jwt.go",
			expectedScore:  65, // 50 * 1.3 = 65
			expectedTier:   TierHigh,
		},
		{
			name:           "Quantum safer candidate in payment path",
			classification: rules.RiskQuantumSaferCandidate,
			filePath:       "pkg/billing/aes.go",
			expectedScore:  14, // 10 * 1.4 = 14
			expectedTier:   TierLow,
		},
		{
			name:           "Word boundary check - 'discard' should not trigger 'card'",
			classification: rules.RiskQuantumVulnerable,
			filePath:       "pkg/buffer/discard_writer.go",
			expectedScore:  50, // 1.0x, not 1.4x
			expectedTier:   TierMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rules.Finding{
				Classification: tt.classification,
				FilePath:       tt.filePath,
			}
			scored := CalculateFindingScore(f)
			if scored.Score != tt.expectedScore {
				t.Errorf("expected score %d, got %d", tt.expectedScore, scored.Score)
			}
			if scored.Tier != tt.expectedTier {
				t.Errorf("expected tier %s, got %s", tt.expectedTier, scored.Tier)
			}
		})
	}
}

func TestCalculateCertificateScore(t *testing.T) {
	tests := []struct {
		name            string
		classification  rules.RiskClassification
		filePath        string
		isExpired       bool
		daysUntilExpiry int
		expectedScore   int
		expectedTier    Tier
	}{
		{
			name:            "Expired certificate",
			classification:  rules.RiskQuantumVulnerable,
			filePath:        "certs/server.crt",
			isExpired:       true,
			daysUntilExpiry: -5,
			expectedScore:   90, // (50 * 1.3) + 25 = 65 + 25 = 90
			expectedTier:    TierCritical,
		},
		{
			name:            "Expiring in 20 days",
			classification:  rules.RiskQuantumVulnerable,
			filePath:        "certs/gateway.pem",
			isExpired:       false,
			daysUntilExpiry: 20,
			expectedScore:   85, // 65 + 20 = 85
			expectedTier:    TierCritical,
		},
		{
			name:            "Expiring in 60 days",
			classification:  rules.RiskQuantumVulnerable,
			filePath:        "certs/api.pem",
			isExpired:       false,
			daysUntilExpiry: 60,
			expectedScore:   75, // 65 + 10 = 75
			expectedTier:    TierHigh,
		},
		{
			name:            "Valid > 90 days in test folder",
			classification:  rules.RiskQuantumVulnerable,
			filePath:        "fixtures/test_cert.pem",
			isExpired:       false,
			daysUntilExpiry: 120,
			expectedScore:   25, // 50 * 0.5 + 0 = 25
			expectedTier:    TierLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := certs.CertificateAnalysis{
				Classification:  tt.classification,
				FilePath:        tt.filePath,
				IsExpired:       tt.isExpired,
				DaysUntilExpiry: tt.daysUntilExpiry,
			}
			scored := CalculateCertificateScore(c)
			if scored.Score != tt.expectedScore {
				t.Errorf("expected score %d, got %d", tt.expectedScore, scored.Score)
			}
			if scored.Tier != tt.expectedTier {
				t.Errorf("expected tier %s, got %s", tt.expectedTier, scored.Tier)
			}
		})
	}
}
