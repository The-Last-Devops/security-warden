package source

import (
	"strings"
	"testing"
)

func TestTunnelStopCmd(t *testing.T) {
	cases := map[string]string{
		"code-tunnel": "code tunnel service uninstall · code tunnel kill · code tunnel unregister",
		"ngrok":       "sudo ngrok service stop · sudo ngrok service uninstall · kill 42",
		"cloudflared": "sudo cloudflared service uninstall · cloudflared service uninstall · kill 42",
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
		if kind != "tunnel" {
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
