package web

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// OpenBrowser opens url in a normal browser tab. The URL is one argument,
// never passed through a shell.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// appArgs makes a Chromium browser show url as its own window: no tabs, no
// address bar, a sensible size.
func appArgs(url string) []string {
	return []string{"--app=" + url, "--window-size=1280,860", "--new-window"}
}

// OpenApp opens url in its own app-style window with Chrome, Edge, Brave
// or Chromium when one is installed, and falls back to a browser tab.
func OpenApp(url string) error {
	switch runtime.GOOS {
	case "darwin":
		for _, app := range []string{"Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium", "Arc"} {
			if _, err := os.Stat(filepath.Join("/Applications", app+".app")); err == nil {
				return exec.Command("open", append([]string{"-na", app, "--args"}, appArgs(url)...)...).Start()
			}
		}
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
			for _, rel := range []string{`Microsoft\Edge\Application\msedge.exe`, `Google\Chrome\Application\chrome.exe`} {
				p := filepath.Join(base, rel)
				if base != "" {
					if _, err := os.Stat(p); err == nil {
						return exec.Command(p, appArgs(url)...).Start()
					}
				}
			}
		}
	default:
		for _, b := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
			if p, err := exec.LookPath(b); err == nil {
				return exec.Command(p, appArgs(url)...).Start()
			}
		}
	}
	return OpenBrowser(url)
}

// AppPath is the installed macOS app (Security Warden.app), or "".
func AppPath() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{"/Applications/Security Warden.app", filepath.Join(home, "Applications", "Security Warden.app")} {
		if _, err := os.Stat(filepath.Join(p, "Contents", "MacOS")); err == nil {
			return p
		}
	}
	return ""
}

// OpenUI shows Security Warden on this machine: the macOS app when it is
// installed (one window; it signs itself in through this binary, see
// `security-warden app-url`), else the default browser, signed in with a
// one-time ticket.
func OpenUI(port int) error {
	if app := AppPath(); app != "" {
		args := []string{"-a", app}
		// The app asks the binary that opened it for its sign-in ticket, so
		// a development build opens the development server.
		if exe, err := os.Executable(); err == nil {
			args = append(args, "--env", "SW_CLI="+exe)
		}
		if exec.Command("open", args...).Run() == nil {
			return nil
		}
	}
	return OpenBrowser(SignedInURL(port))
}

// TicketURL is SignedInURL, but fails instead of falling back to the plain
// address (the app has no other way to sign in).
func TicketURL(port int) (string, error) {
	u := SignedInURL(port)
	if !strings.Contains(u, "/login?ticket=") {
		return "", fmt.Errorf("no sign-in ticket from the server on port %d", port)
	}
	return u, nil
}

// AppHint says how to get the macOS app when it is missing: "brew" (a
// Homebrew install: the cask), "dmg" (the release disk image), or "" (not
// macOS, or already installed).
func AppHint() string {
	if runtime.GOOS != "darwin" || AppPath() != "" {
		return ""
	}
	exe, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if strings.Contains(exe, "/Cellar/") {
		return "brew"
	}
	return "dmg"
}
