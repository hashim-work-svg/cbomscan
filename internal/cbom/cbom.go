// Package cbom generates CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON documents.
package cbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashim-work-svg/cbomscan/internal/score"
)

// CycloneDXDocument represents a CycloneDX 1.6 Bill of Materials document with cryptographic assets.
type CycloneDXDocument struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata captures document creation time and scanning tool identity.
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     Tools  `json:"tools"`
}

// Tools contains tool definitions.
type Tools struct {
	Components []ToolComponent `json:"components"`
}

// ToolComponent identifies the scanning tool.
type ToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component represents a CycloneDX 1.6 cryptographic-asset component.
type Component struct {
	BOMRef           string            `json:"bom-ref"`
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

// CryptoProperties represents cryptographic asset properties under CycloneDX 1.6.
type CryptoProperties struct {
	AssetType             string                 `json:"assetType"` // algorithm, certificate, protocol
	AlgorithmProperties   *AlgorithmProperties   `json:"algorithmProperties,omitempty"`
	CertificateProperties *CertificateProperties `json:"certificateProperties,omitempty"`
}

// AlgorithmProperties details specific cryptographic primitive characteristics.
type AlgorithmProperties struct {
	Name                   string   `json:"name"`
	Primitive              string   `json:"primitive,omitempty"` // hash, block-cipher, signature, key-exchange
	Curve                  string   `json:"curve,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
}

// CertificateProperties details X.509 certificate metadata.
type CertificateProperties struct {
	SubjectName        string `json:"subjectName,omitempty"`
	IssuerName         string `json:"issuerName,omitempty"`
	NotBefore          string `json:"notBefore,omitempty"`
	NotAfter           string `json:"notAfter,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}

// Evidence captures occurrences and locations of cryptographic components.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

// Occurrence identifies the exact file location of a cryptographic asset.
type Occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

// Property represents a generic key-value metadata attribute.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Exporter builds CycloneDX 1.6 CBOM documents.
type Exporter struct {
	toolVersion string
}

// NewExporter initializes a CBOM exporter with tool version information.
func NewExporter(toolVersion string) *Exporter {
	if toolVersion == "" {
		toolVersion = "v0.1.0"
	}
	return &Exporter{toolVersion: toolVersion}
}

// GenerateCBOM converts scored findings and certificates into a CycloneDX 1.6 CBOM document.
func (e *Exporter) GenerateCBOM(findings []score.ScoredFinding, certs []score.ScoredCertificate) (*CycloneDXDocument, error) {
	doc := &CycloneDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", generateUUID()),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: Tools{
				Components: []ToolComponent{
					{
						Type:    "application",
						Name:    "cbomscan",
						Version: e.toolVersion,
					},
				},
			},
		},
		Components: make([]Component, 0, len(findings)+len(certs)),
	}

	idx := 1
	for _, sf := range findings {
		f := sf.Finding
		bomRef := fmt.Sprintf("crypto-asset-%04d", idx)
		idx++

		comp := Component{
			BOMRef:      bomRef,
			Type:        "cryptographic-asset",
			Name:        f.Algorithm,
			Description: fmt.Sprintf("Cryptographic algorithm finding from rule %s", f.RuleID),
			CryptoProperties: &CryptoProperties{
				AssetType: determineAssetType(f.Algorithm),
				AlgorithmProperties: &AlgorithmProperties{
					Name:      f.Algorithm,
					Primitive: mapPrimitive(f.Algorithm),
				},
			},
			Evidence: &Evidence{
				Occurrences: []Occurrence{
					{
						Location: f.FilePath,
						Line:     f.LineNumber,
					},
				},
			},
			Properties: []Property{
				{Name: "cbomscan:classification", Value: string(f.Classification)},
				{Name: "cbomscan:severity", Value: f.Severity},
				{Name: "cbomscan:priority-score", Value: strconv.Itoa(sf.Score)},
				{Name: "cbomscan:priority-tier", Value: string(sf.Tier)},
				{Name: "cbomscan:matched-text", Value: f.MatchedText},
				{Name: "cbomscan:recommendation", Value: f.Recommendation},
			},
		}

		doc.Components = append(doc.Components, comp)
	}

	for _, sc := range certs {
		c := sc.Analysis
		bomRef := fmt.Sprintf("crypto-cert-%04d", idx)
		idx++

		comp := Component{
			BOMRef:      bomRef,
			Type:        "cryptographic-asset",
			Name:        fmt.Sprintf("%s-%d", c.KeyType, c.KeySizeBits),
			Description: fmt.Sprintf("X.509 Certificate subject: %s", c.Subject),
			CryptoProperties: &CryptoProperties{
				AssetType: "certificate",
				AlgorithmProperties: &AlgorithmProperties{
					Name:                   c.KeyType,
					Primitive:              "signature",
					Curve:                  c.Curve,
					ParameterSetIdentifier: fmt.Sprintf("%d", c.KeySizeBits),
				},
				CertificateProperties: &CertificateProperties{
					SubjectName:        c.Subject,
					IssuerName:         c.Issuer,
					NotBefore:          c.NotBefore.Format(time.RFC3339),
					NotAfter:           c.NotAfter.Format(time.RFC3339),
					SignatureAlgorithm: c.SignatureAlgorithm,
				},
			},
			Evidence: &Evidence{
				Occurrences: []Occurrence{
					{
						Location: c.FilePath,
					},
				},
			},
			Properties: []Property{
				{Name: "cbomscan:classification", Value: string(c.Classification)},
				{Name: "cbomscan:priority-score", Value: strconv.Itoa(sc.Score)},
				{Name: "cbomscan:priority-tier", Value: string(sc.Tier)},
				{Name: "cbomscan:days-until-expiry", Value: strconv.Itoa(c.DaysUntilExpiry)},
				{Name: "cbomscan:is-expired", Value: strconv.FormatBool(c.IsExpired)},
				{Name: "cbomscan:recommendation", Value: c.Recommendation},
			},
		}

		doc.Components = append(doc.Components, comp)
	}

	return doc, nil
}

// ToJSON serializes the CycloneDX document into indented JSON format.
func (d *CycloneDXDocument) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func determineAssetType(algorithm string) string {
	algoLower := strings.ToLower(algorithm)
	if strings.Contains(algoLower, "tls") || strings.Contains(algoLower, "ssl") {
		return "protocol"
	}
	return "algorithm"
}

func mapPrimitive(algo string) string {
	algoLower := strings.ToLower(algo)
	switch {
	case strings.Contains(algoLower, "md5") || strings.Contains(algoLower, "sha"):
		return "hash"
	case strings.Contains(algoLower, "aes") || strings.Contains(algoLower, "des") || strings.Contains(algoLower, "rc4"):
		return "block-cipher"
	case strings.Contains(algoLower, "rsa") || strings.Contains(algoLower, "ecdsa") || strings.Contains(algoLower, "ed25519") || strings.Contains(algoLower, "mldsa"):
		return "signature"
	case strings.Contains(algoLower, "ecdh") || strings.Contains(algoLower, "dh") || strings.Contains(algoLower, "mlkem"):
		return "key-exchange"
	default:
		return "algorithm"
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
