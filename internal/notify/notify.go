// Package notify shows desktop notifications. Text is passed as program
// arguments, never spliced into a script, so a finding's title cannot
// inject AppleScript or shell code.
package notify

import (
	"os/exec"
	"runtime"
)

// Send shows a notification and reports whether a notifier was available.
func Send(title, subtitle, body string) bool {
	switch runtime.GOOS {
	case "darwin":
		script := []string{
			"-e", "on run argv",
			"-e", "display notification (item 3 of argv) with title (item 1 of argv) subtitle (item 2 of argv)",
			"-e", "end run",
		}
		return exec.Command("osascript", append(script, title, subtitle, body)...).Run() == nil
	case "linux":
		if p, err := exec.LookPath("notify-send"); err == nil {
			return exec.Command(p, "--app-name=security-warden", title+": "+subtitle, body).Run() == nil
		}
	}
	return false
}
