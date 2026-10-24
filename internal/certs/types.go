// Package certs implements X.509 certificate parsing, metadata extraction,
// and post-quantum cryptographic risk analysis for PEM and DER encoded certificates.
package certs

import (
	"fmt"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/rules"
)

// CertificateAnalysis captures cryptographic characteristics and quantum risk of an X.509 certificate.
type CertificateAnalysis struct {
	FilePath           string                   `json:"file_path"`
	Subject            string                   `json:"subject"`
	Issuer             string                   `json:"issuer"`
	SerialNumber       string                   `json:"serial_number"`
	KeyType            string                   `json:"key_type"`
	KeySizeBits        int                      `json:"key_size_bits"`
	Curve              string                   `json:"curve,omitempty"`
	SignatureAlgorithm string                   `json:"signature_algorithm"`
	NotBefore          time.Time                `json:"not_before"`
	NotAfter           time.Time                `json:"not_after"`
	DaysUntilExpiry    int                      `json:"days_until_expiry"`
	IsExpired          bool                     `json:"is_expired"`
	Classification     rules.RiskClassification `json:"classification"`
	RiskReasons        []string                 `json:"risk_reasons"`
	Recommendation     string                   `json:"recommendation"`
}

// ErrNoCertificateFound is returned when a scanned file contains no valid X.509 certificates.
var ErrNoCertificateFound = fmt.Errorf("no x.509 certificates found")
