package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// linuxPackageUpdates counts the distribution packages that have a newer
// version, from the package manager's local cache only: nothing is
// refreshed and nothing goes out on the network, so the answer is only as
// fresh as the last "apt update" or dnf metadata refresh (cache_days says
// how old). It returns nil when there is no apt or dnf, or no cache yet.
func linuxPackageUpdates(ctx context.Context) []Item {
	if _, err := exec.LookPath("apt"); err == nil {
		if it, ok := aptUpdates(ctx); ok {
			return []Item{it}
		}
		return nil
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		if it, ok := dnfUpdates(ctx); ok {
			return []Item{it}
		}
	}
	return nil
}

// aptListsDir holds the package lists "apt update" downloads.
const aptListsDir = "/var/lib/apt/lists"

func aptUpdates(ctx context.Context) (Item, bool) {
	lists, _ := filepath.Glob(filepath.Join(aptListsDir, "*_Packages*"))
	if len(lists) == 0 {
		return nil, false // never updated: an empty answer would mislead
	}
	out, err := runC(ctx, 30*time.Second, "apt", "list", "--upgradable")
	if err != nil {
		return nil, false
	}
	total, security := parseAptUpgradable(out)
	return packagesItem("apt", total, security, cacheDays(lists...)), true
}

// parseAptUpgradable reads `apt list --upgradable`. Lines look like
// "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: ...]";
// a package from a *-security pocket is a security update.
func parseAptUpgradable(out string) (total, security int) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(f[0], "/") || !strings.Contains(line, "[upgradable") {
			continue
		}
		total++
		_, pockets, _ := strings.Cut(f[0], "/")
		for _, p := range strings.Split(pockets, ",") {
			if strings.HasSuffix(p, "-security") {
				security++
				break
			}
		}
	}
	return total, security
}

func dnfUpdates(ctx context.Context) (Item, bool) {
	// --cacheonly: never refresh metadata. As a regular user it reads the
	// system cache; with no cache at all dnf fails and we report nothing.
	out, code := dnfRun(ctx, "check-update", "--cacheonly")
	if code != 0 && code != 100 {
		return nil, false
	}
	total := parseDnfCheckUpdate(out)
	security := -1 // unknown unless the advisory metadata is cached too
	if out, code := dnfRun(ctx, "check-update", "--cacheonly", "--security"); code == 0 || code == 100 {
		security = parseDnfCheckUpdate(out)
	}
	var caches []string
	for _, d := range []string{"/var/cache/libdnf5", "/var/cache/dnf"} {
		if _, err := os.Stat(d); err == nil {
			caches = append(caches, d)
		}
	}
	return packagesItem("dnf", total, security, cacheDays(caches...)), true
}

// dnfRun returns stdout and the exit code (100 means "updates available").
func dnfRun(ctx context.Context, args ...string) (string, int) {
	out, err := runC(ctx, 45*time.Second, "dnf", append([]string{"-q"}, args...)...)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out, ee.ExitCode()
	}
	if err != nil {
		return out, -1
	}
	return out, 0
}

// parseDnfCheckUpdate counts "name.arch version repo" lines of
// `dnf check-update` (dnf 4 and dnf 5), stopping at the obsoletes section.
func parseDnfCheckUpdate(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(line, " ") || !strings.Contains(f[0], ".") {
			continue
		}
		n++
	}
	return n
}

// upgradeCommand is what the fix text tells the user to run (with sudo,
// in their own terminal: the scan itself never installs anything).
var upgradeCommand = map[string]string{
	"apt": "sudo apt update && sudo apt upgrade",
	"dnf": "sudo dnf upgrade --refresh",
}

// packagesItem: security is -1 when unknown (no cached advisories).
func packagesItem(manager string, total, security, days int) Item {
	return Item{
		"kind":            "packages",
		"manager":         manager,
		"total":           total,
		"security":        security,
		"cache_days":      days,
		"upgrade_command": upgradeCommand[manager],
	}
}

// cacheDays is how many days ago the newest of these files changed, or -1.
func cacheDays(paths ...string) int {
	var newest time.Time
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	if newest.IsZero() {
		return -1
	}
	return int(time.Since(newest).Hours() / 24)
}

// runC runs a command with LC_ALL=C and a timeout, returning stdout only.
func runC(ctx context.Context, d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	b, err := cmd.Output()
	return string(b), err
}
