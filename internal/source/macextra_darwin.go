package source

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"
)

// macExtra adds macOS settings found by the research pass. All reads are
// silent and need no root.
func macExtra(ctx context.Context, it Item) {
	it["quarantine"] = userDefaultsBool(ctx, "com.apple.LaunchServices", "LSQuarantine", true)
	it["library_validation_disabled"] = defaultsBool(ctx, "/Library/Preferences/com.apple.security.libraryvalidation", "DisableLibraryValidation", false)
	it["security_data_updates"] = defaultsBool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall", true)

	autoLogin := false
	if out, err := run(ctx, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"); err == nil && strings.TrimSpace(out) != "" {
		autoLogin = true
	}
	if _, err := os.Stat("/etc/kcpassword"); err == nil {
		autoLogin = true
	}
	it["auto_login"] = autoLogin

	if out, err := run(ctx, "defaults", "read", "com.apple.sharingd", "DiscoverableMode"); err == nil {
		it["airdrop"] = strings.TrimSpace(out)
	}
	if out, err := run(ctx, "xprotect", "version"); err == nil {
		if m := regexp.MustCompile(`Installed:\s*(\d{4}-\d{2}-\d{2})`).FindStringSubmatch(out); m != nil {
			if t, err := time.Parse("2006-01-02", m[1]); err == nil {
				it["xprotect_age_days"] = int(time.Since(t).Hours() / 24)
			}
		}
	}
	if out, err := run(ctx, "launchctl", "getenv", "DYLD_INSERT_LIBRARIES"); err == nil {
		it["dyld_insert"] = strings.TrimSpace(out) != ""
	}
}

func userDefaultsBool(ctx context.Context, domain, key string, def bool) bool {
	return defaultsBool(ctx, domain, key, def)
}
