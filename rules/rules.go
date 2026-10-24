// Package rulesdata embeds the YAML rule definition files.
package rulesdata

import "embed"

// EmbeddedRules contains all embedded YAML rule files.
//
//go:embed *.yaml
var EmbeddedRules embed.FS
