package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// posture reads Linux security settings. Fields that cannot be read are
// left out; rules guard them with has(item.x).
func posture(ctx context.Context) ([]Item, error) {
	it := Item{"os": "linux", "container": inContainer()}

	if _, err := exec.LookPath("lsblk"); err == nil {
		if out, err := run(ctx, "lsblk", "-nlo", "TYPE,MOUNTPOINT"); err == nil {
			it["disk_encrypted"] = rootEncrypted(out)
		}
	}
	if fw, ok := linuxFirewall(ctx); ok {
		it["firewall"] = fw
	}
	if au, ok := linuxAutoUpdates(ctx); ok {
		it["auto_updates"] = au
	}
	it["lsm"] = linuxLSM()

	if cfg, ok := sshdConfig(); ok {
		it["sshd_installed"] = true
		it["sshd_permit_root_login"] = strings.ToLower(cfg["permitrootlogin"])
		it["sshd_password_auth"] = strings.ToLower(cfg["passwordauthentication"]) != "no"
	} else {
		it["sshd_installed"] = false
	}

	if _, err := exec.LookPath("gsettings"); err == nil && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		if out, err := run(ctx, "gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"); err == nil {
			it["screen_lock"] = strings.TrimSpace(out) == "true"
		}
	}
	return []Item{it}, nil
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	b, _ := os.ReadFile("/proc/1/cgroup")
	return strings.Contains(string(b), "docker") || strings.Contains(string(b), "kubepods")
}

// rootEncrypted: lsblk lists a "crypt" device for LUKS. Any crypt device
// counts; a precise check would follow / through the device tree.
func rootEncrypted(lsblk string) bool {
	for _, line := range strings.Split(lsblk, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "crypt" {
			return true
		}
	}
	return false
}

func systemdActive(ctx context.Context, unit string) bool {
	out, _ := run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

func systemdEnabled(ctx context.Context, unit string) bool {
	out, _ := run(ctx, "systemctl", "is-enabled", unit)
	return strings.TrimSpace(out) == "enabled"
}

// linuxFirewall checks ufw, firewalld and nftables. ok is false when there
// is no way to tell (no systemd, no config).
func linuxFirewall(ctx context.Context) (on, ok bool) {
	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		if regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*yes`).Match(b) {
			return true, true
		}
		ok = true
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, ok
	}
	for _, u := range []string{"firewalld", "nftables", "iptables", "netfilter-persistent"} {
		if systemdActive(ctx, u) {
			return true, true
		}
	}
	return false, true
}

func linuxAutoUpdates(ctx context.Context) (on, ok bool) {
	files, _ := filepath.Glob("/etc/apt/apt.conf.d/*")
	if len(files) > 0 {
		re := regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"1"`)
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil && re.Match(b) {
				return true, true
			}
		}
		return false, true
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		for _, u := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"} {
			if systemdEnabled(ctx, u) {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

// linuxLSM names the mandatory access control in force.
func linuxLSM() string {
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return "selinux"
		}
		return "selinux-permissive"
	}
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(string(b)) == "Y" {
		return "apparmor"
	}
	return "none"
}

// sshdConfig reads sshd_config and its drop-ins. Like sshd, the first value
// of a keyword wins, and Include files are read where they appear.
func sshdConfig() (map[string]string, bool) {
	const main = "/etc/ssh/sshd_config"
	if _, err := os.Stat(main); err != nil {
		return nil, false
	}
	cfg := map[string]string{}
	var read func(path string, depth int)
	read = func(path string, depth int) {
		b, err := os.ReadFile(path)
		if err != nil || depth > 4 {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			key := strings.ToLower(f[0])
			if key == "match" {
				return // Match blocks apply to some connections only
			}
			if key == "include" {
				for _, pat := range f[1:] {
					if !filepath.IsAbs(pat) {
						pat = filepath.Join("/etc/ssh", pat)
					}
					ms, _ := filepath.Glob(pat)
					for _, m := range ms {
						read(m, depth+1)
					}
				}
				continue
			}
			if _, set := cfg[key]; !set {
				cfg[key] = f[1]
			}
		}
	}
	read(main, 0)
	if cfg["permitrootlogin"] == "" {
		cfg["permitrootlogin"] = "prohibit-password" // OpenSSH default
	}
	return cfg, true
}
