// Package rules bundles the stable rule set into the binary.
package rules

import "embed"

//go:embed *.yaml
var FS embed.FS
