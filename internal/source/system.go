package source

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// networkConfig reports system proxies and /etc/hosts overrides.
func networkConfig(ctx context.Context) ([]Item, error) {
	var items []Item
	if runtime.GOOS == "darwin" {
		if out, err := run(ctx, "scutil", "--proxy"); err == nil {
			items = append(items, parseScutilProxy(out)...)
		}
	} else {
		for _, k := range []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"} {
			if v := os.Getenv(k); v != "" {
				items = append(items, proxyItem("env", v, 0))
				break
			}
		}
	}
	if b, err := os.ReadFile("/etc/hosts"); err == nil {
		items = append(items, parseHosts(string(b))...)
	}
	return items, nil
}

func parseScutilProxy(out string) []Item {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " : "); ok {
			kv[k] = v
		}
	}
	var items []Item
	for _, p := range []struct{ typ, enable, host, port string }{
		{"http", "HTTPEnable", "HTTPProxy", "HTTPPort"},
		{"https", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"},
		{"socks", "SOCKSEnable", "SOCKSProxy", "SOCKSPort"},
	} {
		if kv[p.enable] == "1" && kv[p.host] != "" {
			port, _ := strconv.Atoi(kv[p.port])
			items = append(items, proxyItem(p.typ, kv[p.host], port))
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" && kv["ProxyAutoConfigURLString"] != "" {
		it := proxyItem("pac", kv["ProxyAutoConfigURLString"], 0)
		items = append(items, it)
	}
	return items
}

func proxyItem(typ, hostOrURL string, port int) Item {
	host, scheme := hostOrURL, ""
	if i := strings.Index(hostOrURL, "://"); i >= 0 {
		scheme = hostOrURL[:i]
		host = hostOrURL[i+3:]
		host, _, _ = strings.Cut(host, "/")
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:] // drop credentials
		}
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	return Item{"kind": "proxy", "type": typ, "host": host, "port": port, "scheme": scheme, "loopback": isLoopback(h) || h == "localhost"}
}

// Domains whose redirection would break updates, logins or package installs.
var highValueHosts = regexp.MustCompile(`(^|\.)(apple\.com|icloud\.com|github\.com|githubusercontent\.com|google\.com|googleapis\.com|microsoft\.com|npmjs\.org|npmjs\.com|pypi\.org|pythonhosted\.org|docker\.io|docker\.com|amazonaws\.com|okta\.com|1password\.com|brew\.sh|homebrew\.bintray\.com|ghcr\.io|crates\.io|rubygems\.org|golang\.org|proxy\.golang\.org)$`)

func parseHosts(s string) []Item {
	var items []Item
	for _, line := range strings.Split(s, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := f[0]
		blocks := ip == "0.0.0.0" || ip == "::" || strings.HasPrefix(ip, "127.") || ip == "::1"
		for _, name := range f[1:] {
			n := strings.ToLower(name)
			if n == "localhost" || n == "broadcasthost" || strings.HasSuffix(n, ".local") || strings.HasSuffix(n, ".localhost") ||
				strings.HasSuffix(n, ".test") || strings.HasSuffix(n, ".internal") || strings.HasSuffix(n, ".lan") || !strings.Contains(n, ".") {
				continue
			}
			items = append(items, Item{"kind": "hosts", "name": n, "ip": ip, "blocks": blocks, "high_value": highValueHosts.MatchString(n)})
		}
	}
	return items
}

// privilege looks at sudo rules and the directories in PATH.
func privilege(ctx context.Context) ([]Item, error) {
	var items []Item
	// -n never prompts; it fails when a password would be needed.
	if out, err := run(ctx, "sudo", "-n", "-l"); err == nil {
		items = append(items, Item{
			"kind":          "sudo",
			"nopasswd_any":  strings.Contains(out, "NOPASSWD"),
			"nopasswd_all":  regexp.MustCompile(`NOPASSWD:\s*ALL\b`).MatchString(out),
			"sudoers_files": 0,
		})
	}
	seenSys := false
	seenDir := map[string]bool{}
	for i, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "/usr/bin" {
			seenSys = true
		}
		if seenDir[dir] {
			continue
		}
		seenDir[dir] = true
		it := Item{"kind": "path", "dir": dir, "index": i, "before_system": !seenSys,
			"relative": dir == "" || dir == "." || !filepath.IsAbs(dir), "exists": false,
			"world_writable": false, "group_writable_foreign": false,
			// A missing folder only matters if someone else could create it:
			// its closest existing parent is writable by others.
			"creatable_by_others": false}
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			it["exists"] = true
			m := fi.Mode()
			it["world_writable"] = m.Perm()&0o002 != 0 && m&os.ModeSticky == 0
			if _, gid, ok := owner(fi); ok {
				// Group-writable is only a problem for a group other than
				// admin/wheel/the user's own (Homebrew is admin-writable).
				it["group_writable_foreign"] = m.Perm()&0o020 != 0 && gid != 0 && gid != 80 && int(gid) != os.Getgid()
			}
		}
		if exists, _ := it["exists"].(bool); !exists && filepath.IsAbs(dir) {
			for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
				if fi, err := os.Stat(p); err == nil {
					it["creatable_by_others"] = fi.Mode().Perm()&0o002 != 0 && fi.Mode()&os.ModeSticky == 0
					break
				}
				if p == "/" || p == "." {
					break
				}
			}
		}
		items = append(items, it)
	}
	return items, nil
}
