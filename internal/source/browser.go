package source

import (
	"context"
	"encoding/json"
	"path/filepath"
)

// browserSettings reads each Chromium profile's protections: Safe Browsing
// and extension developer mode.
func browserSettings(ctx context.Context) ([]Item, error) {
	var items []Item
	for _, r := range chromiumRoots() {
		profiles, _ := filepath.Glob(filepath.Join(r.dir, "*", "Preferences"))
		for _, prefPath := range profiles {
			profile := filepath.Base(filepath.Dir(prefPath))
			if profile == "System Profile" || profile == "Guest Profile" {
				continue
			}
			b, err := readSmallN(prefPath, 32<<20)
			if err != nil {
				continue
			}
			var p struct {
				SafeBrowsing struct {
					Enabled *bool `json:"enabled"`
				} `json:"safebrowsing"`
				Extensions struct {
					UI struct {
						DeveloperMode bool `json:"developer_mode"`
					} `json:"ui"`
				} `json:"extensions"`
			}
			if json.Unmarshal(b, &p) != nil {
				continue
			}
			items = append(items, Item{"browser": r.browser, "profile": profile,
				"safe_browsing_off": p.SafeBrowsing.Enabled != nil && !*p.SafeBrowsing.Enabled,
				"developer_mode":    p.Extensions.UI.DeveloperMode})
		}
	}
	return items, nil
}
