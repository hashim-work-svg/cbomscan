package rules

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Engine manages cryptographic rules and executes inspections across source files.
type Engine struct {
	rules []Rule
}

// NewEngine creates an empty rules engine.
func NewEngine() *Engine {
	return &Engine{
		rules: make([]Rule, 0),
	}
}

// LoadFromYAML deserializes and compiles rules from raw YAML content.
func (e *Engine) LoadFromYAML(yamlData []byte) error {
	var rf RuleFile
	if err := yaml.Unmarshal(yamlData, &rf); err != nil {
		return fmt.Errorf("failed to parse rule YAML: %w", err)
	}

	for i := range rf.Rules {
		r := &rf.Rules[i]
		if r.ID == "" || r.Pattern == "" {
			return fmt.Errorf("%w: rule must have id and pattern (got id=%q)", ErrInvalidRule, r.ID)
		}

		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("%w: invalid regex in rule %q: %v", ErrInvalidRule, r.ID, err)
		}
		r.CompiledRegex = compiled

		if r.Classification == "" {
			r.Classification = RiskUnknown
		}

		e.rules = append(e.rules, *r)
	}

	return nil
}

// Rules returns all currently registered rules.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// ScanContent scans in-memory byte content for a given file path against registered rules.
func (e *Engine) ScanContent(filePath string, content []byte) []Finding {
	var findings []Finding
	ext := strings.ToLower(filepath.Ext(filePath))
	base := strings.ToLower(filepath.Base(filePath))

	// Pre-filter rules applicable to this file
	applicableRules := make([]*Rule, 0, len(e.rules))
	for i := range e.rules {
		r := &e.rules[i]
		if e.matchesTarget(r, ext, base) {
			applicableRules = append(applicableRules, r)
		}
	}

	if len(applicableRules) == 0 {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024) // Allow lines up to 2MB

	seen := make(map[string]bool)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		for _, r := range applicableRules {
			if loc := r.CompiledRegex.FindStringIndex(line); loc != nil {
				matched := line[loc[0]:loc[1]]
				dedupeKey := fmt.Sprintf("%s:%d:%s", r.ID, lineNum, matched)
				if seen[dedupeKey] {
					continue
				}
				seen[dedupeKey] = true

				findings = append(findings, Finding{
					RuleID:         r.ID,
					Algorithm:      r.Algorithm,
					Classification: r.Classification,
					Severity:       r.Severity,
					FilePath:       filePath,
					LineNumber:     lineNum,
					LineContent:    trimmedLine,
					MatchedText:    matched,
					Recommendation: r.Recommendation,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		// Log or retain error note without terminating partial findings
		fmt.Fprintf(os.Stderr, "Warning: scan encountered error reading %s: %v\n", filePath, err)
	}

	return findings
}

// ScanFile reads a file from disk with a safety size limit and scans its content.
func (e *Engine) ScanFile(filePath string) ([]Finding, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %q: %w", filePath, err)
	}
	// File size guard: prevent reading unbounded binary/log files into memory (10MB limit)
	if info.Size() > 10*1024*1024 {
		return nil, fmt.Errorf("file %q exceeds maximum scan size limit of 10MB (%d bytes)", filePath, info.Size())
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", filePath, err)
	}
	return e.ScanContent(filePath, data), nil
}

// matchesTarget checks if a rule's languages or file globs apply to the file.
func (e *Engine) matchesTarget(r *Rule, ext, base string) bool {
	// If rule has no filters, it applies generally
	if len(r.Languages) == 0 && len(r.FileGlobs) == 0 {
		return true
	}

	// Check file extension / language mapping
	for _, lang := range r.Languages {
		switch strings.ToLower(lang) {
		case "go", "golang":
			if ext == ".go" {
				return true
			}
		case "python", "py":
			if ext == ".py" {
				return true
			}
		case "java":
			if ext == ".java" {
				return true
			}
		case "javascript", "js", "typescript", "ts":
			if ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx" || ext == ".mjs" {
				return true
			}
		case "configs", "config":
			if ext == ".conf" || ext == ".cfg" || ext == ".ini" || ext == ".yaml" || ext == ".yml" || base == "sshd_config" || base == "nginx.conf" {
				return true
			}
		}
	}

	// Check glob patterns
	for _, glob := range r.FileGlobs {
		matched, err := filepath.Match(strings.ToLower(glob), base)
		if err == nil && matched {
			return true
		}
	}

	return false
}
