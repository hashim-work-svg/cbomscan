// Package main is the entry point for the cbomscan CLI.
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashim-work-svg/cbomscan/internal/cbom"
	"github.com/hashim-work-svg/cbomscan/internal/certs"
	"github.com/hashim-work-svg/cbomscan/internal/demo"
	"github.com/hashim-work-svg/cbomscan/internal/report"
	"github.com/hashim-work-svg/cbomscan/internal/rules"
	"github.com/hashim-work-svg/cbomscan/internal/score"
	rulesdata "github.com/hashim-work-svg/cbomscan/rules"
	"github.com/spf13/cobra"
)

var (
	// Version is injected during build time via ldflags.
	Version = "v0.1.0"
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
quantum-safer-candidate), calculate migration priority scores, and export CycloneDX 1.6 CBOMs.`,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print binary version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cbomscan %s (commit: %s, date: %s)\n", Version, Commit, Date)
		},
	}

	var scanTarget string
	var outputFormat string
	var outputFile string
	var failOnTier string

	scanCmd := &cobra.Command{
		Use:   "scan [directory-or-file]",
		Short: "Scan source code, configs, and certificates for cryptographic usage",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			} else if scanTarget != "" {
				target = scanTarget
			}

			engine, err := initializeRuleEngine()
			if err != nil {
				return fmt.Errorf("failed to initialize rules engine: %w", err)
			}

			var totalFindings []rules.Finding
			var totalCerts []certs.CertificateAnalysis

			info, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("invalid scan target: %w", err)
			}

			if !info.IsDir() {
				// Single file scan
				ext := strings.ToLower(filepath.Ext(target))
				if isCertExt(ext) {
					cAnalyses, cErr := certs.ParseCertificateFile(target)
					if cErr == nil {
						totalCerts = append(totalCerts, cAnalyses...)
					} else {
						fmt.Fprintf(os.Stderr, "Warning: failed to parse certificate %s: %v\n", target, cErr)
					}
				}
				sFindings, sErr := engine.ScanFile(target)
				if sErr == nil {
					totalFindings = append(totalFindings, sFindings...)
				} else {
					fmt.Fprintf(os.Stderr, "Warning: failed to scan file %s: %v\n", target, sErr)
				}
			} else {
				// Directory scan
				err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						fmt.Fprintf(os.Stderr, "Warning: error accessing %s: %v\n", path, walkErr)
						return nil
					}
					if d.IsDir() {
						name := d.Name()
						// Accurately skip hidden VCS and dependency folders without skipping .github
						if name == ".git" || name == "node_modules" || name == "vendor" {
							return filepath.SkipDir
						}
						return nil
					}

					ext := strings.ToLower(filepath.Ext(path))
					if isCertExt(ext) {
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

			// Score findings and certificates
			scoredFindings := make([]score.ScoredFinding, 0, len(totalFindings))
			for _, f := range totalFindings {
				scoredFindings = append(scoredFindings, score.CalculateFindingScore(f))
			}

			scoredCerts := make([]score.ScoredCertificate, 0, len(totalCerts))
			for _, c := range totalCerts {
				scoredCerts = append(scoredCerts, score.CalculateCertificateScore(c))
			}

			// Format and render results
			outWriter := os.Stdout
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
				}
				defer f.Close()
				outWriter = f
			}

			switch strings.ToLower(outputFormat) {
			case "cbom":
				exporter := cbom.NewExporter(Version)
				doc, err := exporter.GenerateCBOM(scoredFindings, scoredCerts)
				if err != nil {
					return fmt.Errorf("failed to generate CBOM: %w", err)
				}
				jsonBytes, err := doc.ToJSON()
				if err != nil {
					return fmt.Errorf("failed to serialize CBOM JSON: %w", err)
				}
				fmt.Fprintln(outWriter, string(jsonBytes))

			case "json":
				data := map[string]interface{}{
					"findings":     scoredFindings,
					"certificates": scoredCerts,
				}
				jsonBytes, _ := json.MarshalIndent(data, "", "  ")
				fmt.Fprintln(outWriter, string(jsonBytes))

			case "md", "markdown":
				md := report.GenerateMarkdown(scoredFindings, scoredCerts)
				fmt.Fprint(outWriter, md)

			case "csv":
				csvBytes, err := report.GenerateCSV(scoredFindings, scoredCerts)
				if err != nil {
					return fmt.Errorf("failed to generate CSV: %w", err)
				}
				if _, err := outWriter.Write(csvBytes); err != nil {
					return fmt.Errorf("failed to write CSV: %w", err)
				}

			default:
				displayTable(scoredFindings, scoredCerts, outWriter)
			}

			// Check CI failure threshold
			if failOnTier != "" {
				if shouldFailOnThreshold(scoredFindings, scoredCerts, failOnTier) {
					return fmt.Errorf("scan failed: findings exceeded --fail-on threshold %q", failOnTier)
				}
			}

			return nil
		},
	}
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", ".", "Target directory or certificate file to scan")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format (table, cbom, json, md, csv)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")
	scanCmd.Flags().StringVar(&failOnTier, "fail-on", "", "Exit code 1 if findings exceed tier (critical, high, medium, low)")

	var demoFormat string
	demoCmd := &cobra.Command{
		Use:   "demo",
		Short: "Run an end-to-end demonstration using embedded synthetic project fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := initializeRuleEngine()
			if err != nil {
				return fmt.Errorf("failed to initialize rules: %w", err)
			}
			return demo.Run(engine, demoFormat, os.Stdout)
		},
	}
	demoCmd.Flags().StringVarP(&demoFormat, "format", "f", "table", "Demo output format (table, md, csv)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(demoCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func isCertExt(ext string) bool {
	return ext == ".crt" || ext == ".pem" || ext == ".der" || ext == ".cer"
}

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

func displayTable(findings []score.ScoredFinding, certAnalyses []score.ScoredCertificate, out *os.File) {
	fmt.Fprintf(out, "=== Cryptographic Source & Config Findings (%d) ===\n", len(findings))
	if len(findings) > 0 {
		fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5s %-30s %s\n", "RULE ID", "ALGORITHM", "CLASSIFICATION", "TIER", "SCORE", "LOCATION", "MATCH")
		fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5s %-30s %s\n", "-------", "---------", "--------------", "----", "-----", "--------", "-----")
		for _, sf := range findings {
			f := sf.Finding
			loc := fmt.Sprintf("%s:%d", filepath.Base(f.FilePath), f.LineNumber)
			fmt.Fprintf(out, "%-22s %-10s %-25s %-8s %-5d %-30s %s\n",
				truncate(f.RuleID, 20),
				truncate(f.Algorithm, 9),
				f.Classification,
				sf.Tier,
				sf.Score,
				truncate(loc, 28),
				truncate(f.MatchedText, 25),
			)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "=== Certificate Inventory (%d) ===\n", len(certAnalyses))
	if len(certAnalyses) > 0 {
		fmt.Fprintf(out, "%-20s %-8s %-9s %-8s %-5s %-25s %-12s %s\n", "FILE", "TYPE", "BITS", "TIER", "SCORE", "CLASSIFICATION", "EXPIRY", "SUBJECT")
		fmt.Fprintf(out, "%-20s %-8s %-9s %-8s %-5s %-25s %-12s %s\n", "----", "----", "----", "----", "-----", "--------------", "------", "-------")
		for _, sc := range certAnalyses {
			c := sc.Analysis
			expiry := fmt.Sprintf("%dd", c.DaysUntilExpiry)
			if c.IsExpired {
				expiry = "EXPIRED"
			}
			fmt.Fprintf(out, "%-20s %-8s %-9d %-8s %-5d %-25s %-12s %s\n",
				truncate(filepath.Base(c.FilePath), 18),
				c.KeyType,
				c.KeySizeBits,
				sc.Tier,
				sc.Score,
				c.Classification,
				expiry,
				truncate(c.Subject, 25),
			)
		}
	}
}

func shouldFailOnThreshold(findings []score.ScoredFinding, certs []score.ScoredCertificate, threshold string) bool {
	threshScore := 100
	switch strings.ToLower(threshold) {
	case "critical":
		threshScore = 85
	case "high":
		threshScore = 60
	case "medium":
		threshScore = 35
	case "low":
		threshScore = 0
	}

	for _, f := range findings {
		if f.Score >= threshScore {
			return true
		}
	}
	for _, c := range certs {
		if c.Score >= threshScore {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
