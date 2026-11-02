package source

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

func tailscaleBinary() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	const app = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	if _, err := os.Stat(app); err == nil {
		return app
	}
	return ""
}

// tailscale reports how this machine is exposed to its tailnet.
func tailscale(ctx context.Context) ([]Item, error) {
	bin := tailscaleBinary()
	if bin == "" {
		return nil, Skip{"skip.tailscale"}
	}
	var status struct {
		BackendState   string
		CurrentTailnet *struct{ Name string }
	}
	out, err := run(ctx, bin, "status", "--json")
	if err != nil || json.Unmarshal([]byte(out), &status) != nil {
		return nil, Skip{"skip.tailscale"}
	}
	if status.BackendState != "Running" {
		return nil, Skip{"skip.tailscale_stopped"}
	}

	var prefs struct {
		RunSSH          bool
		ShieldsUp       bool
		AdvertiseRoutes []string
		ExitNodeID      string
		RunWebClient    bool
	}
	havePrefs := false
	if out, err := run(ctx, bin, "debug", "prefs"); err == nil {
		havePrefs = json.Unmarshal([]byte(out), &prefs) == nil
	}

	var routes []string
	exitNode := false
	for _, r := range prefs.AdvertiseRoutes {
		if r == "0.0.0.0/0" || r == "::/0" {
			exitNode = true
		} else {
			routes = append(routes, r)
		}
	}

	// serve/funnel: any config means something on this machine is published.
	var serve struct {
		TCP         map[string]any
		Web         map[string]any
		AllowFunnel map[string]bool
	}
	if out, err := run(ctx, bin, "serve", "status", "--json"); err == nil {
		_ = json.Unmarshal([]byte(out), &serve)
	}
	funnel := false
	for _, on := range serve.AllowFunnel {
		funnel = funnel || on
	}

	tailnet := ""
	if status.CurrentTailnet != nil {
		tailnet = status.CurrentTailnet.Name
	}
	it := Item{
		"tailnet": tailnet,
		"serve":   len(serve.TCP)+len(serve.Web) > 0,
		"funnel":  funnel,
	}
	// Unknown is not "off": leave the fields out so rules skip them.
	if havePrefs {
		it["ssh"] = prefs.RunSSH
		it["shields_up"] = prefs.ShieldsUp
		it["exit_node"] = exitNode
		it["subnet_routes"] = strings.Join(routes, ", ")
		it["advertises_subnets"] = len(routes) > 0
		it["web_client"] = prefs.RunWebClient
	}
	return []Item{it}, nil
}
