// Package demo provides a zero-install interactive demonstration for cbomscan.
package demo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/report"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
	"github.com/hashim-work-svg/cbomscan/internal/score"
)

//go:embed embedded/*
var DemoFS embed.FS

// Run executes the cbomscan demo workflow against synthetic embedded files.
func Run(engine *rules.Engine, format string, out io.Writer) error {
	var totalFindings []rules.Finding
	var totalCerts []certs.CertificateAnalysis

	// 1. Scan embedded sample Go code
	sampleGo, err := DemoFS.ReadFile("embedded/sample.go")
	if err == nil {
		findings := engine.ScanContent("services/payment/processor.go", sampleGo)
		totalFindings = append(totalFindings, findings...)
	}

	// 2. Scan embedded nginx config
	sampleNginx, err := DemoFS.ReadFile("embedded/nginx.conf")
	if err == nil {
		findings := engine.ScanContent("configs/gateway/nginx.conf", sampleNginx)
		totalFindings = append(totalFindings, findings...)
	}

	// 3. Generate a synthetic expired RSA-1024 certificate for demonstration
	demoCert := generateDemoCert()
	totalCerts = append(totalCerts, demoCert)

	// 4. Calculate Migration Priority Scores
	scoredFindings := make([]score.ScoredFinding, 0, len(totalFindings))
	for _, f := range totalFindings {
		scoredFindings = append(scoredFindings, score.CalculateFindingScore(f))
	}

	scoredCerts := make([]score.ScoredCertificate, 0, len(totalCerts))
	for _, c := range totalCerts {
		scoredCerts = append(scoredCerts, score.CalculateCertificateScore(c))
	}

	// 5. Output in requested format
	switch format {
	case "md", "markdown":
		md := report.GenerateMarkdown(scoredFindings, scoredCerts)
		_, err := fmt.Fprint(out, md)
		return err
	case "csv":
		csvBytes, err := report.GenerateCSV(scoredFindings, scoredCerts)
		if err != nil {
			return err
		}
		_, err = out.Write(csvBytes)
		return err
	default:
		// Terminal table format
		fmt.Fprintln(out, "=== CBOM-Scan Zero-Install Demonstration ===")
		fmt.Fprintln(out, "Auditing embedded synthetic microservice repository...")
		fmt.Fprintln(out)

		fmt.Fprintf(out, "=== Cryptographic Code & Config Findings (%d) ===\n", len(scoredFindings))
		fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5s %-32s\n", "RULE ID", "ALGORITHM", "CLASSIFICATION", "TIER", "SCORE", "LOCATION")
		fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5s %-32s\n", "-------", "---------", "--------------", "----", "-----", "--------")
		for _, sf := range scoredFindings {
			loc := fmt.Sprintf("%s:%d", sf.Finding.FilePath, sf.Finding.LineNumber)
			fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5d %-32s\n",
				truncate(sf.Finding.RuleID, 20),
				truncate(sf.Finding.Algorithm, 9),
				sf.Finding.Classification,
				sf.Tier,
				sf.Score,
				truncate(loc, 30),
			)
		}

		fmt.Fprintf(out, "\n=== X.509 Certificate Inventory (%d) ===\n", len(scoredCerts))
		fmt.Fprintf(out, "%-30s %-8s %-9s %-8s %-5s %-20s %s\n", "CERTIFICATE", "TYPE", "BITS", "TIER", "SCORE", "EXPIRY", "CLASSIFICATION")
		fmt.Fprintf(out, "%-30s %-8s %-9s %-8s %-5s %-20s %s\n", "-----------", "----", "----", "----", "-----", "------", "--------------")
		for _, sc := range scoredCerts {
			expiry := fmt.Sprintf("%dd remaining", sc.Analysis.DaysUntilExpiry)
			if sc.Analysis.IsExpired {
				expiry = "EXPIRED"
			}
			fmt.Fprintf(out, "%-30s %-8s %-9d %-8s %-5d %-20s %s\n",
				truncate(sc.Analysis.FilePath, 28),
				sc.Analysis.KeyType,
				sc.Analysis.KeySizeBits,
				sc.Tier,
				sc.Score,
				expiry,
				sc.Analysis.Classification,
			)
		}
		fmt.Fprintln(out)
		return nil
	}
}

func generateDemoCert() certs.CertificateAnalysis {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "legacy-gateway.demo.internal",
			Organization: []string{"Acme Demo Corp"},
		},
		NotBefore:             time.Now().Add(-400 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-35 * 24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	parsed, _ := x509.ParseCertificate(derBytes)

	now := time.Now().UTC()
	daysUntilExpiry := int((parsed.NotAfter.Sub(now) + 12*time.Hour) / (24 * time.Hour))
	return certs.CertificateAnalysis{
		FilePath:           "certs/gateway_legacy.crt",
		Subject:            parsed.Subject.String(),
		Issuer:             parsed.Issuer.String(),
		SerialNumber:       parsed.SerialNumber.String(),
		SignatureAlgorithm: parsed.SignatureAlgorithm.String(),
		NotBefore:          parsed.NotBefore,
		NotAfter:           parsed.NotAfter,
		DaysUntilExpiry:    daysUntilExpiry,
		IsExpired:          true,
		KeyType:            "RSA",
		KeySizeBits:        1024,
		Classification:     rules.RiskLegacyBroken,
		Recommendation:     "Replace deprecated RSA-1024 with RSA-3072 or post-quantum ML-DSA signature",
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
