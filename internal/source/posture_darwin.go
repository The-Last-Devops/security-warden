package source

import (
	"context"
	"regexp"
	"strings"
)

var fwState = regexp.MustCompile(`State = (\d)`)

// posture reads macOS security settings. A field is left out when it cannot
// be read, so rules use has(item.x) before testing it.
func posture(ctx context.Context) ([]Item, error) {
	it := Item{"os": "macos"}

	if out, err := run(ctx, "fdesetup", "status"); err == nil {
		// "Encryption in progress" is neither on nor off yet: leave it out.
		if strings.Contains(out, "FileVault is On") {
			it["filevault"] = true
		} else if strings.Contains(out, "FileVault is Off") {
			it["filevault"] = false
		}
	}
	const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if out, err := run(ctx, fw, "--getglobalstate"); err == nil {
		// State = 1 is on, 2 is "block all incoming" (also on), 0 is off.
		if m := fwState.FindStringSubmatch(out); m != nil {
			it["firewall"] = m[1] != "0"
		}
	}
	if out, err := run(ctx, fw, "--getstealthmode"); err == nil {
		it["stealth_mode"] = onOff(out)
	}
	if out, err := run(ctx, "csrutil", "status"); err == nil {
		it["sip"] = strings.Contains(out, "status: enabled")
	}
	if out, err := runCombined(ctx, "spctl", "--status"); err == nil || out != "" {
		it["gatekeeper"] = strings.Contains(out, "assessments enabled")
	}
	// A missing key means the macOS default, which is on.
	it["auto_update_check"] = defaultsBool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled", true)
	it["auto_security_updates"] = defaultsBool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall", true)
	it["guest_account"] = defaultsBool(ctx, "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", false)

	if out, err := runCombined(ctx, "sysadminctl", "-screenLock", "status"); err == nil || out != "" {
		if strings.Contains(out, "screenLock is off") {
			it["screen_lock"] = false
		} else if strings.Contains(out, "screenLock delay") {
			it["screen_lock"] = true
		}
	}
	if out, err := run(ctx, "sw_vers", "-productVersion"); err == nil {
		major, _, _ := strings.Cut(strings.TrimSpace(out), ".")
		if n := atoi(major); n > 0 {
			it["os_major"] = n
			it["os_version"] = strings.TrimSpace(out)
		}
	}
	macExtra(ctx, it)
	return []Item{it}, nil
}

// onOff parses "Firewall is enabled" / "stealth mode is on" style output.
func onOff(out string) bool {
	s := strings.ToLower(out)
	if strings.Contains(s, "disabled") || strings.Contains(s, " is off") {
		return false
	}
	return strings.Contains(s, "enabled") || strings.Contains(s, " is on")
}

func defaultsBool(ctx context.Context, domain, key string, def bool) bool {
	out, err := run(ctx, "defaults", "read", domain, key)
	if err != nil {
		return def
	}
	switch strings.TrimSpace(out) {
	case "1", "true", "YES":
		return true
	case "0", "false", "NO":
		return false
	}
	return def
}
