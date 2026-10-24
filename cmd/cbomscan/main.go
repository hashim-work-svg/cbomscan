// Package main is the entry point for the cbomscan CLI.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
	rulesdata "github.com/hashim-work-svg/cbomscan/rules"
	"github.com/spf13/cobra"
)

var (
	// Version is injected during build time via ldflags.
	Version = "v0.1.0-dev"
	// Commit is injected during build time via ldflags.
	Commit = "none"
	// Date is injected during build time via ldflags.
	Date = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cbomscan",
		Short: "CBOM-Scan: Cryptographic Bill of Materials & Post-Quantum Risk Scanner",
		Long: `CBOM-Scan audits source code, configurations, and X.509 certificates to discover
cryptographic usage, classify quantum and legacy risks (quantum-vulnerable, legacy-broken,
quantum-safer-candidate), calculate migration priority scores, and export CycloneDX CBOMs.`,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print binary version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cbomscan %s (commit: %s, date: %s)\n", Version, Commit, Date)
		},
	}

	var scanTarget string
	scanCmd := &cobra.Command{
		Use:   "scan [directory-or-file]",
		Short: "Scan source code, configs, and certificates for cryptographic usage",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			engine, err := initializeRuleEngine()
			if err != nil {
				return fmt.Errorf("failed to initialize rules engine: %w", err)
			}

			fmt.Printf("Scanning target %q with %d cryptographic rules...\n\n", target, len(engine.Rules()))

			var totalFindings []rules.Finding
			var totalCerts []certs.CertificateAnalysis

			info, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("invalid scan target: %w", err)
			}

			if !info.IsDir() {
				// Single file scan
				ext := strings.ToLower(filepath.Ext(target))
				if ext == ".crt" || ext == ".pem" || ext == ".der" || ext == ".cer" {
					cAnalyses, cErr := certs.ParseCertificateFile(target)
					if cErr == nil {
						totalCerts = append(totalCerts, cAnalyses...)
					}
				}
				sFindings, sErr := engine.ScanFile(target)
				if sErr == nil {
					totalFindings = append(totalFindings, sFindings...)
				}
			} else {
				// Directory scan
				err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
					if walkErr != nil || d.IsDir() {
						return nil
					}
					// Ignore hidden or git directories
					if strings.Contains(path, ".git") || strings.Contains(path, "vendor") {
						return nil
					}

					ext := strings.ToLower(filepath.Ext(path))
					if ext == ".crt" || ext == ".pem" || ext == ".der" || ext == ".cer" {
						cAnalyses, cErr := certs.ParseCertificateFile(path)
						if cErr == nil {
							totalCerts = append(totalCerts, cAnalyses...)
						}
					}

					sFindings, sErr := engine.ScanFile(path)
					if sErr == nil && len(sFindings) > 0 {
						totalFindings = append(totalFindings, sFindings...)
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("walk directory failed: %w", err)
				}
			}

			displayResults(totalFindings, totalCerts)
			return nil
		},
	}
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", ".", "Target directory or certificate file to scan")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// initializeRuleEngine loads all embedded YAML rule files into the engine.
func initializeRuleEngine() (*rules.Engine, error) {
	engine := rules.NewEngine()
	entries, err := rulesdata.EmbeddedRules.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rules: %w", err)
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
			data, err := rulesdata.EmbeddedRules.ReadFile(entry.Name())
			if err != nil {
				return nil, fmt.Errorf("failed reading embedded rule file %s: %w", entry.Name(), err)
			}
			if err := engine.LoadFromYAML(data); err != nil {
				return nil, fmt.Errorf("error loading rule file %s: %w", entry.Name(), err)
			}
		}
	}

	return engine, nil
}

func displayResults(findings []rules.Finding, certAnalyses []certs.CertificateAnalysis) {
	fmt.Printf("=== Cryptographic Source & Config Findings (%d) ===\n", len(findings))
	if len(findings) > 0 {
		fmt.Printf("%-22s %-12s %-25s %-30s %s\n", "RULE ID", "ALGORITHM", "CLASSIFICATION", "LOCATION", "MATCH")
		fmt.Printf("%-22s %-12s %-25s %-30s %s\n", "-------", "---------", "--------------", "--------", "-----")
		for _, f := range findings {
			loc := fmt.Sprintf("%s:%d", filepath.Base(f.FilePath), f.LineNumber)
			fmt.Printf("%-22s %-12s %-25s %-30s %s\n",
				truncate(f.RuleID, 20),
				truncate(f.Algorithm, 10),
				f.Classification,
				truncate(loc, 28),
				truncate(f.MatchedText, 30),
			)
		}
		fmt.Println()
	}

	fmt.Printf("=== Certificate Findings (%d) ===\n", len(certAnalyses))
	if len(certAnalyses) > 0 {
		fmt.Printf("%-20s %-10s %-10s %-25s %-15s %s\n", "FILE", "KEY TYPE", "KEY SIZE", "CLASSIFICATION", "EXPIRY", "SUBJECT")
		fmt.Printf("%-20s %-10s %-10s %-25s %-15s %s\n", "----", "--------", "--------", "--------------", "------", "-------")
		for _, c := range certAnalyses {
			expiry := fmt.Sprintf("%dd", c.DaysUntilExpiry)
			if c.IsExpired {
				expiry = "EXPIRED"
			}
			fmt.Printf("%-20s %-10s %-10d %-25s %-15s %s\n",
				truncate(filepath.Base(c.FilePath), 18),
				c.KeyType,
				c.KeySizeBits,
				c.Classification,
				expiry,
				truncate(c.Subject, 30),
			)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
