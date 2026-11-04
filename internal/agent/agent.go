// Package agent installs security-warden as a per-user background service
// that runs "security-warden serve --background" (web UI + periodic scans): a LaunchAgent on macOS, a systemd user
// unit on Linux. No admin rights are needed and nothing runs as root.
package agent

import (
	"fmt"
	"github.com/The-Last-Devops/security-warden/internal/appdir"
	"github.com/The-Last-Devops/security-warden/internal/update"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func label() string { return "org.the-last-devops." + appdir.Name() }

func unitName() string { return appdir.Name() + ".service" }

// Paths returns where the service definition and its log live.
func Paths() (unit, log string) {
	h, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(h, "Library/LaunchAgents", label()+".plist"), filepath.Join(h, "Library/Logs/"+appdir.Name()+".log")
	default:
		return filepath.Join(h, ".config/systemd/user/"+unitName()), filepath.Join(h, ".local/state/"+appdir.Name()+"/watch.log")
	}
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// AppBundleID is Security Warden.app's (packaging/macos/Info.plist). The
// plist names it so Login Items shows the agent under the app's name and
// icon; macOS honors that only for a binary signed by the app's team.
const AppBundleID = "org.the-last-devops.security-warden.app"

// Plist renders the LaunchAgent for bin.
func Plist(bin, lang, logPath string) string {
	args := []string{bin, "serve", "--background"}
	if lang != "" {
		args = append(args, "--lang", lang)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + label() + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		b.WriteString("\t\t<string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>AssociatedBundleIdentifiers</key><array><string>` + AppBundleID + `</string></array>
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
	cmd := strconv.Quote(bin) + " serve --background"
	if lang != "" {
		cmd += " --lang " + lang
	}
	return `[Unit]
Description=Security Warden: web UI on localhost:7348 and background checks

[Service]
ExecStart=` + cmd + `
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=default.target
`
}

// Install writes the service and starts it.
func Install(lang string) (string, error) {
	// For Homebrew, the opt path survives upgrades; Cellar/<version> does not.
	bin, err := update.StableExecutable()
	if err != nil {
		return "", err
	}
	// The agent runs this file at every login; refuse one others can replace.
	// Windows has no Unix permission bits (Go reports 0666 for any writable
	// file), so the check only means something elsewhere.
	if fi, err := os.Stat(bin); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
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
		// A rewritten login item makes macOS show "Background Items Added"
		// again, so leave an identical one alone.
		if plist := Plist(bin, lang, logPath); !sameFile(unit, plist) {
			if err := writeFresh(unit, plist); err != nil {
				return "", err
			}
		}
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		_ = exec.Command("launchctl", "bootout", domain+"/"+label()).Run() // not loaded yet is fine
		if out, err := exec.Command("launchctl", "bootstrap", domain, unit).CombinedOutput(); err != nil {
			return "", fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
		}
	case "linux":
		if err := writeFresh(unit, Unit(bin, lang)); err != nil {
			return "", err
		}
		for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", "--now", unitName()}} {
			if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
				return "", fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
			}
		}
	default:
		// No launchd or systemd (Windows): start a detached process and
		// remember its pid. It does not restart at login yet.
		return startDetached(bin, lang)
	}
	return unit, nil
}

func pidFile() string { return appdir.File("service.pid") }

func startDetached(bin, lang string) (string, error) {
	args := []string{"serve", "--background"}
	if lang != "" {
		args = append(args, "--lang", lang)
	}
	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	p := pidFile()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return "", err
	}
	_ = cmd.Process.Release()
	return p, nil
}

func stopDetached() error {
	b, err := os.ReadFile(pidFile())
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err == nil {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
	}
	return os.Remove(pidFile())
}

// sameFile reports whether path is a regular file (not a symlink) holding
// exactly content.
func sameFile(path, content string) bool {
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && string(b) == content
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

// Stop stops the service so Install can start a new version. On macOS the
// login item stays (removing and adding it back shows "Background Items
// Added" again); elsewhere it is the same as Uninstall.
func Stop() error {
	if runtime.GOOS == "darwin" {
		return exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), label())).Run()
	}
	return Uninstall()
}

// Uninstall stops the service and removes its definition.
func Uninstall() error {
	unit, _ := Paths()
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), label())).Run()
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", unitName()).Run()
	default:
		return stopDetached()
	}
	if err := os.Remove(unit); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Installed reports whether the service definition exists.
func Installed() bool {
	unit, _ := Paths()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		unit = pidFile()
	}
	_, err := os.Stat(unit)
	return err == nil
}
