package source

import (
	"path/filepath"
	"strings"
)

// This file holds the deny-list of privacy-protected folders, so it is the
// one file allowed to name them (see TestNoPromptingCommands).

// privacyProtected: folders where reading makes macOS ask for permission.
func privacyProtected(p string) bool {
	h := home()
	for _, rel := range []string{"Documents", "Desktop", "Downloads", "Library", "Pictures", "Movies", "Music"} {
		d := filepath.Join(h, rel)
		if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
