package source

import (
	"context"
	"os"
	"path/filepath"
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
	mscpExtra(ctx, it)
}

var (
	hotCornerOff = regexp.MustCompile(`"?wvous-(tl|tr|bl|br)-corner"?\s*=\s*6;`)
	mediaShare   = regexp.MustCompile(`"(home|public)-sharing-enabled"\s*=\s*1;`)
)

// mscpExtra reads settings the macOS Security Compliance Project
// (usnistgov/macos_security) checks, from the user's own preferences and
// world-readable system files only.
func mscpExtra(ctx context.Context, it Item) {
	// Bluetooth Sharing lets nearby devices browse and send files.
	if out, err := run(ctx, "defaults", "-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"); err == nil {
		it["bluetooth_sharing"] = strings.TrimSpace(out) == "1"
	} else {
		it["bluetooth_sharing"] = false
	}
	// Hot corner action 6 is "Disable Screen Saver": the Mac never locks
	// while the pointer sits there.
	if out, err := run(ctx, "defaults", "read", "com.apple.dock"); err == nil {
		it["hot_corner_no_lock"] = hotCornerOff.MatchString(out)
	}
	// Media sharing: the Music/TV library shared on the local network.
	if out, err := run(ctx, "defaults", "read", "com.apple.amp.mediasharingd"); err == nil {
		it["media_sharing"] = mediaShare.MatchString(out)
	} else {
		it["media_sharing"] = false
	}
	// Content caching serves Apple downloads to other devices nearby.
	it["content_caching"] = defaultsBool(ctx, "/Library/Preferences/com.apple.AssetCache.plist", "Activated", false)
	// A password hint shown at the login window after failed tries. Only
	// whether a hint exists is kept, never the hint.
	it["password_hint_shown"] = false
	if out, err := run(ctx, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"); err == nil && atoi(strings.TrimSpace(out)) > 0 {
		u := os.Getenv("USER")
		if u == "" {
			u = filepath.Base(home())
		}
		if u != "" && u != "/" && u != "." {
			if h, err := run(ctx, "dscl", ".", "-read", "/Users/"+u, "AuthenticationHint"); err == nil {
				_, hint, _ := strings.Cut(h, ":")
				it["password_hint_shown"] = strings.TrimSpace(hint) != ""
			}
		}
	}
}

func userDefaultsBool(ctx context.Context, domain, key string, def bool) bool {
	return defaultsBool(ctx, domain, key, def)
}
