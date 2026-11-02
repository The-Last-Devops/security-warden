package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
