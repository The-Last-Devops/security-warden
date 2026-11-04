package source

import (
	"strings"
	"testing"
)

func TestTunnelStopCmd(t *testing.T) {
	cases := map[string]string{
		"ngrok":       "sudo ngrok service stop` · `sudo ngrok service uninstall` · `kill 42",
		"cloudflared": "sudo cloudflared service uninstall` · `cloudflared service uninstall` · `kill 42",
		"bore":        "kill 42",
	}
	for tool, want := range cases {
		if got := tunnelStopCmd(tool, 42); got != want {
			t.Errorf("%s: got %q, want %q", tool, got, want)
		}
	}
	// Every tunnel the collector knows gets a stop command, and none of
	// them deletes anything.
	for tool, kind := range remoteToolKinds {
		if kind != "tunnel" || strings.HasPrefix(tool, "code-tunnel") {
			continue
		}
		got := tunnelStopCmd(tool, 7)
		if got == "" {
			t.Errorf("%s: no stop command", tool)
		}
		for _, bad := range []string{"rm ", "-rf", "chmod", "delete"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: stop command %q contains %q", tool, got, bad)
			}
		}
	}
}

func TestCodeTunnelRunsTunnel(t *testing.T) {
	cases := map[string]bool{
		// Seen on macOS with VS Code 1.144: Remote Tunnel Access, and the agent host.
		"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code-tunnel tunnel --accept-server-license-terms --log info --name mbp --parent-process-id 62028": true,
		"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code-tunnel --cli-data-dir /Users/a/.vscode/cli agent host":                                       false,
		"/usr/share/code/bin/code-tunnel tunnel service internal-run":                                                                                                      true,
		`C:\Program Files\Microsoft VS Code\bin\code-tunnel.exe serve-web --port 8000`:                                                                                     false,
		"/opt/code-insiders/bin/code-tunnel-insiders tunnel --name x":                                                                                                      true,
		"": false,
	}
	for args, want := range cases {
		if got := codeTunnelRunsTunnel(args); got != want {
			t.Errorf("%q: got %v, want %v", args, got, want)
		}
	}
}
