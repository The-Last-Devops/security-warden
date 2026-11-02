package source

import (
	"context"
	"fmt"
	"net"
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

var lsofOnce = sync.OnceValues(func() ([]Item, error) {
	return readListeners(context.Background())
})

func readListeners(ctx context.Context) ([]Item, error) {
	if runtime.GOOS == "linux" {
		return procListeners()
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
	}
	var items []Item
	for _, s := range services {
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

// remoteTools finds running tunnels and remote desktop apps.
func remoteTools(ctx context.Context) ([]Item, error) {
	known := map[string]string{
		"ngrok":       "tunnel",
		"cloudflared": "tunnel",
		"frpc":        "tunnel",
		"bore":        "tunnel",
		"code-tunnel": "tunnel",
		"localtunnel": "tunnel",
		"zrok":        "tunnel",
		"AnyDesk":     "remote_desktop",
		"TeamViewer":  "remote_desktop",
		"rustdesk":    "remote_desktop",
		"RustDesk":    "remote_desktop",
		"parsecd":     "remote_desktop",
		"chrome-remote-desktop-host": "remote_desktop",
	}
	seen := map[string]bool{}
	var items []Item
	for pid, path := range processPaths() {
		name := path[strings.LastIndex(path, "/")+1:]
		kind, ok := known[name]
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		items = append(items, Item{"tool": name, "kind": kind, "pid": pid, "path": path})
	}
	return items, nil
}
