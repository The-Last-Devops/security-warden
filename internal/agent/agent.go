// Package agent installs security-warden as a per-user background service
// that runs "security-warden watch": a LaunchAgent on macOS, a systemd user
// unit on Linux. No admin rights are needed and nothing runs as root.
package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const label = "org.the-last-devops.security-warden"

// Paths returns where the service definition and its log live.
func Paths() (unit, log string) {
	h, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(h, "Library/LaunchAgents", label+".plist"), filepath.Join(h, "Library/Logs/security-warden.log")
	default:
		return filepath.Join(h, ".config/systemd/user/security-warden.service"), filepath.Join(h, ".local/state/security-warden/watch.log")
	}
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Plist renders the LaunchAgent for bin.
func Plist(bin, lang, logPath string) string {
	args := []string{bin, "watch"}
	if lang != "" {
		args = append(args, "--lang", lang)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		b.WriteString("\t\t<string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ProcessType</key><string>Background</string>
	<key>LowPriorityIO</key><true/>
	<key>Nice</key><integer>10</integer>
	<key>StandardOutPath</key><string>` + xmlEscape(logPath) + `</string>
	<key>StandardErrorPath</key><string>` + xmlEscape(logPath) + `</string>
</dict>
</plist>
`)
	return b.String()
}

// Unit renders the systemd user unit for bin.
func Unit(bin, lang string) string {
	cmd := strconv.Quote(bin) + " watch"
	if lang != "" {
		cmd += " --lang " + lang
	}
	return `[Unit]
Description=security-warden: watch this machine for new open doors and secrets

[Service]
ExecStart=` + cmd + `
Restart=on-failure
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=default.target
`
}

// Install writes the service and starts it.
func Install(lang string) (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return "", err
	}
	// The agent runs this file at every login; refuse one others can replace.
	if fi, err := os.Stat(bin); err == nil && fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s is writable by other users; install security-warden somewhere only you or root can write", bin)
	}
	unit, logPath := Paths()
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		if err := writeFresh(unit, Plist(bin, lang, logPath)); err != nil {
			return "", err
		}
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run() // not loaded yet is fine
		if out, err := exec.Command("launchctl", "bootstrap", domain, unit).CombinedOutput(); err != nil {
			return "", fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
		}
	case "linux":
		if err := writeFresh(unit, Unit(bin, lang)); err != nil {
			return "", err
		}
		for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", "--now", "security-warden.service"}} {
			if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
				return "", fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
			}
		}
	default:
		return "", fmt.Errorf("background agent is not supported on %s yet", runtime.GOOS)
	}
	return unit, nil
}

// writeFresh replaces path with content without following a symlink that
// might already sit there.
func writeFresh(path, content string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Uninstall stops the service and removes its definition.
func Uninstall() error {
	unit, _ := Paths()
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), label)).Run()
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "security-warden.service").Run()
	}
	if err := os.Remove(unit); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Installed reports whether the service definition exists.
func Installed() bool {
	unit, _ := Paths()
	_, err := os.Stat(unit)
	return err == nil
}
