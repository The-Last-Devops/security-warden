package source

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// listeningPorts lists TCP ports that processes listen on. Without root only
// the current user's processes are visible; remoteServices covers the
// system-owned remote access ports. Several sources need the list, so lsof
// runs once.
func listeningPorts(ctx context.Context) ([]Item, error) {
	return lsofOnce()
}

var lsofOnce = sync.OnceValues(load_lsofOnce)

func load_lsofOnce() ([]Item, error) {
	return readListeners(context.Background())
}

func readListeners(ctx context.Context) ([]Item, error) {
	if runtime.GOOS == "linux" {
		return procListeners()
	}
	if runtime.GOOS == "windows" {
		return windowsListeners(ctx)
	}
	out, err := run(ctx, "lsof", "-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN", "-F", "pcLn")
	if err != nil && out == "" {
		// lsof exits 1 when nothing listens; only a missing lsof is a skip.
		if _, lerr := exec.LookPath("lsof"); lerr != nil {
			return nil, Skip{"skip.lsof"}
		}
		return nil, nil
	}
	paths := processPaths()
	seen := map[string]bool{}
	var items []Item
	var pid int
	var cmd, user string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			pid = atoi(v)
		case 'c':
			cmd = v
		case 'L':
			user = v
		case 'n':
			host, port, ok := splitHostPort(v)
			if !ok {
				continue
			}
			loopback := isLoopback(host)
			key := fmt.Sprintf("%d|%d|%t", pid, port, loopback)
			if seen[key] {
				continue // same port on IPv4 and IPv6
			}
			seen[key] = true
			path := paths[pid]
			service := ""
			if s, ok := identify(path); ok {
				service = s.product
			}
			items = append(items, Item{
				"service":        service,
				"process":        cmd,
				"pid":            pid,
				"user":           user,
				"path":           path,
				"address":        host,
				"port":           port,
				"loopback":       loopback,
				"all_interfaces": host == "*" || host == "0.0.0.0" || host == "::",
				"reachable":      !loopback,
				"system_binary":  systemBinary(path),
			})
		}
	}
	return items, nil
}

func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	host := strings.Trim(s[:i], "[]")
	return host, port, true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// remoteServices probes well-known remote access ports on this machine.
// A TCP connect needs no privileges and also sees root-owned services.
func remoteServices(ctx context.Context) ([]Item, error) {
	services := []struct {
		name string
		port int
	}{
		{"ssh", 22},
		{"screen_sharing", 5900},
		{"apple_remote_desktop", 3283},
		{"rdp", 3389},
		{"smb", 445},
		{"remote_apple_events", 3031},
	}
	var items []Item
	for _, s := range services {
		if runtime.GOOS == "windows" && s.name == "rdp" {
			continue // posture reads the real setting (windows-rdp-* rules)
		}
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
		open := err == nil
		if open {
			c.Close()
		}
		items = append(items, Item{"service": s.name, "port": s.port, "open": open})
	}
	return items, nil
}

// remoteToolKinds maps a process name to the kind of remote tool it is.
var remoteToolKinds = map[string]string{
	"ngrok":                      "tunnel",
	"cloudflared":                "tunnel",
	"frpc":                       "tunnel",
	"bore":                       "tunnel",
	"code-tunnel":                "tunnel",
	"code-tunnel-insiders":       "tunnel",
	"localtunnel":                "tunnel",
	"zrok":                       "tunnel",
	"AnyDesk":                    "remote_desktop",
	"TeamViewer":                 "remote_desktop",
	"rustdesk":                   "remote_desktop",
	"RustDesk":                   "remote_desktop",
	"parsecd":                    "remote_desktop",
	"chrome-remote-desktop-host": "remote_desktop",
}

// remoteTools finds running tunnels and remote desktop apps.
func remoteTools(ctx context.Context) ([]Item, error) {
	seen := map[string]bool{}
	var items []Item
	for pid, path := range processPaths() {
		name := strings.TrimSuffix(winBase(path), ".exe")
		kind, ok := remoteToolKinds[name]
		if !ok || seen[name] {
			continue
		}
		// VS Code's code-tunnel helper also runs its agent host and
		// serve-web: only the tunnel subcommand opens a tunnel. Such a
		// tunnel is VS Code's Remote Tunnel Access, turned off in VS Code
		// (rule vscode-tunnel-access), not with a `code` command, which is
		// often not on the PATH.
		managed := ""
		if strings.HasPrefix(name, "code-tunnel") {
			if args, err := processArgs(ctx, pid); err == nil && !codeTunnelRunsTunnel(args) {
				continue
			}
			managed = "vscode"
		}
		seen[name] = true
		it := Item{"tool": name, "kind": kind, "pid": pid, "path": path, "managed": managed}
		if kind == "tunnel" && managed == "" {
			it["stop_cmd"] = tunnelStopCmd(name, pid)
		}
		items = append(items, it)
	}
	return items, nil
}

// codeTunnelRuns reports whether a code-tunnel command line runs a tunnel:
// "…/code-tunnel tunnel --name x" yes, "…/code-tunnel --cli-data-dir d
// agent host" no. The program path may hold spaces, so the words are read
// after the program name.
func codeTunnelRunsTunnel(args string) bool {
	i := strings.LastIndex(args, "code-tunnel")
	if i < 0 {
		return false
	}
	words := strings.Fields(args[i:])
	for _, w := range words[1:] {
		if w == "tunnel" {
			return true
		}
	}
	return false
}

// processArgs is the command line of one process (for telling apart what
// one program is doing). When it cannot be read, callers assume the worst.
func processArgs(ctx context.Context, pid int) (string, error) {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		return strings.ReplaceAll(string(b), "\x00", " "), err
	case "windows":
		return runPS(ctx, fmt.Sprintf(`(Get-CimInstance Win32_Process -Filter "ProcessId=%d").CommandLine`, pid))
	}
	return run(ctx, "ps", "-o", "args=", "-p", strconv.Itoa(pid))
}

// tunnelStops are the commands that stop a tunnel tool and keep it from
// starting again, in order. Each is safe to run when nothing is running or
// installed (it only prints an error). Checked against each tool's --help:
// ngrok service (3.39), cloudflared service (2026.10). Tools without a
// service mode just get kill <pid>. VS Code tunnels have their own rule.
var tunnelStops = map[string][]string{
	"ngrok":       {"sudo ngrok service stop", "sudo ngrok service uninstall"},
	"cloudflared": {"sudo cloudflared service uninstall", "cloudflared service uninstall"},
}

// tunnelStopCmd lists the stop commands for a tunnel tool, separated by
// " · ". The values are fixed text plus a pid, never anything the machine
// can choose, so they are safe to copy into a terminal.
func tunnelStopCmd(tool string, pid int) string {
	cmds := append(append([]string(nil), tunnelStops[tool]...), fmt.Sprintf("kill %d", pid))
	// The rule wraps {stop_cmd} in backticks; closing and reopening them
	// here gives each command its own code span (and copy button).
	return strings.Join(cmds, "` · `")
}
