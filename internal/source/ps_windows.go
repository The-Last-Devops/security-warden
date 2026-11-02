package source

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// createNoWindow keeps a console from flashing up when the background
// service runs a scan.
const createNoWindow = 0x08000000

// runPS runs a read-only PowerShell script (Windows PowerShell 5.1, which
// every supported Windows has) without profiles or prompts, and returns
// stdout. Statements end with ";", so the script is passed on one line.
func runPS(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	line := strings.ReplaceAll(psPrelude+script, "\n", " ")
	cmd := exec.CommandContext(ctx, systemExe(`WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-NoLogo", "-Command", line)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	b, err := cmd.Output()
	return string(b), err
}
