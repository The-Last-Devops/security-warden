// Package appdir names where Security Warden keeps its data and which port
// it uses. A development build (no version) uses its own folder, port and
// service name, so it never collides with an installed release.
package appdir

import (
	"os"
	"path/filepath"
)

// Dev is set at startup for development builds.
var Dev bool

// Name is the folder and service name: security-warden or security-warden-dev.
func Name() string {
	if Dev {
		return "security-warden-dev"
	}
	return "security-warden"
}

// Port is the fixed web port: 7348 for releases, 7349 for development.
func Port() int {
	if Dev {
		return 7349
	}
	return 7348
}

// Dir is the data folder inside the user's config folder.
func Dir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, Name())
}

// File is a path inside Dir.
func File(name string) string { return filepath.Join(Dir(), name) }
