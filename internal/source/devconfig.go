package source

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	rcPipeShell = regexp.MustCompile(`(curl|wget)[^|#\n]*\|\s*(sudo\s+)?(ba|z)?sh\b`)
	rcEvalNet   = regexp.MustCompile(`eval\s+"?\$\((curl|wget)`)
	rcExport    = regexp.MustCompile(`^\s*export\s+([A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*)=(.*)$`)
	rcInsecure  = regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED=["']?0|PYTHONHTTPSVERIFY=["']?0|GIT_SSL_NO_VERIFY=["']?(1|true)|strict-ssl\s+false|--insecure-skip-tls-verify|HOMEBREW_NO_VERIFY_ATTESTATIONS`)
	rcSkipPerms = regexp.MustCompile(`--dangerously-skip-permissions|--yolo\b|--dangerously-bypass-approvals-and-sandbox`)
	rcAnyExport = regexp.MustCompile(`^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=`)
)

// literalValue reports whether an assignment value is a hard-coded string
// rather than a lookup ($VAR, $(cmd), `cmd`).
func literalValue(v string) bool {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if len(v) < 8 {
		return false
	}
	return !strings.ContainsAny(v, "$`")
}

// shellRC flags risky lines in shell startup files. It keeps the file, line
// number and variable name, never the value.
func shellRC(ctx context.Context) ([]Item, error) {
	files := []string{".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"}
	var items []Item
	for _, rel := range files {
		path := filepath.Join(home(), rel)
		b, err := readSmall(path)
		if err != nil {
			continue
		}
		// Known token formats, by line: the gitleaks rule id of the first.
		tokens := map[int]string{}
		text := string(b)
		for _, h := range scanSecrets(text) {
			n := strings.Count(text[:h.Start], "\n")
			if _, ok := tokens[n]; !ok {
				tokens[n] = h.ID
			}
		}
		for i, line := range strings.Split(text, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "#") {
				continue
			}
			add := func(kind, name string) {
				items = append(items, Item{"kind": kind, "file": path, "line_no": i + 1, "var_name": name, "secret_kind": tokens[i]})
			}
			switch {
			case rcPipeShell.MatchString(t) || rcEvalNet.MatchString(t):
				add("pipe_to_shell", "")
			case rcInsecure.MatchString(t):
				add("insecure_flag", "")
			case rcSkipPerms.MatchString(t):
				add("agent_skip_permissions", "")
			}
			if m := rcExport.FindStringSubmatch(t); m != nil && literalValue(m[3]) {
				add("exported_secret", m[1])
			} else if tokens[i] != "" {
				// A known token format, whatever the variable is called.
				if m := rcAnyExport.FindStringSubmatch(t); m != nil {
					add("exported_secret", m[1])
				} else {
					add("token_in_line", "")
				}
			}
		}
	}
	return items, nil
}

// sshClientConfig flags dangerous defaults in ~/.ssh/config (and includes):
// settings under "Host *" apply to every server you connect to.
func sshClientConfig(ctx context.Context) ([]Item, error) {
	var items []Item
	var read func(path string, depth int)
	read = func(path string, depth int) {
		b, err := readSmall(path)
		if err != nil || depth > 3 {
			return
		}
		host := "*"
		for i, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(strings.ReplaceAll(line, "=", " "))
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			key := strings.ToLower(f[0])
			val := strings.ToLower(f[1])
			switch key {
			case "host":
				host = strings.Join(f[1:], " ")
			case "match":
				host = "match " + strings.Join(f[1:], " ")
			case "include":
				for _, pat := range f[1:] {
					if strings.HasPrefix(pat, "~/") {
						pat = filepath.Join(home(), pat[2:])
					} else if !filepath.IsAbs(pat) {
						pat = filepath.Join(home(), ".ssh", pat)
					}
					ms, _ := filepath.Glob(pat)
					for _, m := range ms {
						read(m, depth+1)
					}
				}
			case "forwardagent", "stricthostkeychecking", "userknownhostsfile", "forwardx11trusted",
				"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes":
				items = append(items, Item{
					"file": path, "line_no": i + 1, "host": host, "all_hosts": host == "*",
					"key": key, "value": val,
					"weak_algorithm": regexp.MustCompile(`ssh-dss|group1-sha1|3des|arcfour|hmac-md5|\+ssh-rsa`).MatchString(val),
				})
			}
		}
	}
	read(filepath.Join(home(), ".ssh", "config"), 0)
	return items, nil
}

// gitConfig reads the global git settings that weaken security.
func gitConfig(ctx context.Context) ([]Item, error) {
	if !gitAvailable() {
		return nil, Skip{"skip.git"}
	}
	out, err := run(ctx, "git", "config", "--global", "--list")
	if err != nil && out == "" {
		return nil, nil // no global config
	}
	it := Item{"credential_store": false, "ssl_verify_off": false, "safe_directory_all": false,
		"hooks_path": "", "insteadof_downgrade": false, "file_protocol_always": false}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		switch {
		case k == "credential.helper" && strings.HasPrefix(v, "store"):
			it["credential_store"] = true
		case (k == "http.sslverify" || strings.HasSuffix(k, ".sslverify")) && strings.EqualFold(v, "false"):
			it["ssl_verify_off"] = true
		case k == "safe.directory" && v == "*":
			it["safe_directory_all"] = true
		case k == "core.hookspath":
			it["hooks_path"] = v
		case strings.HasPrefix(k, "url.") && strings.HasSuffix(k, ".insteadof"):
			target := strings.TrimSuffix(strings.TrimPrefix(k, "url."), ".insteadof")
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "git://") {
				it["insteadof_downgrade"] = true
			}
		case k == "protocol.file.allow" && v == "always":
			it["file_protocol_always"] = true
		}
	}
	return []Item{it}, nil
}

// pkgConfig reads package manager settings (files only, no network calls).
func pkgConfig(ctx context.Context) ([]Item, error) {
	var items []Item
	npmFiles := []string{filepath.Join(home(), ".npmrc"), filepath.Join(home(), ".yarnrc"), "/opt/homebrew/etc/npmrc", "/usr/local/etc/npmrc"}
	for _, f := range npmFiles {
		b, err := readSmall(f)
		if err != nil {
			continue
		}
		s := string(b)
		it := Item{"tool": "npm", "file": f,
			"strict_ssl_off": regexp.MustCompile(`(?m)^\s*strict-ssl\s*=\s*false`).MatchString(s),
			"http_registry":  regexp.MustCompile(`(?m)^\s*(@[^:]+:)?registry\s*=\s*http://`).MatchString(s),
			"trusted_host":   false, "extra_index": false}
		items = append(items, it)
	}
	if b, err := readSmall(filepath.Join(home(), ".yarnrc.yml")); err == nil {
		s := string(b)
		items = append(items, Item{"tool": "yarn", "file": filepath.Join(home(), ".yarnrc.yml"),
			"strict_ssl_off": regexp.MustCompile(`(?m)^\s*enableStrictSsl:\s*false`).MatchString(s),
			"http_registry":  regexp.MustCompile(`(?m)^\s*npmRegistryServer:\s*["']?http://`).MatchString(s),
			"trusted_host":   false, "extra_index": false})
	}
	for _, f := range []string{
		filepath.Join(home(), ".config/pip/pip.conf"), filepath.Join(home(), ".pip/pip.conf"),
		filepath.Join(home(), "Library/Application Support/pip/pip.conf"), "/etc/pip.conf",
	} {
		b, err := readSmall(f)
		if err != nil {
			continue
		}
		s := string(b)
		items = append(items, Item{"tool": "pip", "file": f,
			"strict_ssl_off": false,
			"http_registry":  regexp.MustCompile(`(?m)^\s*(extra-)?index-url\s*=\s*http://`).MatchString(s),
			"trusted_host":   regexp.MustCompile(`(?m)^\s*trusted-host\s*=`).MatchString(s),
			"extra_index":    regexp.MustCompile(`(?m)^\s*extra-index-url\s*=`).MatchString(s)})
	}
	if b, err := readSmall(filepath.Join(home(), ".condarc")); err == nil {
		items = append(items, Item{"tool": "conda", "file": filepath.Join(home(), ".condarc"),
			"strict_ssl_off": regexp.MustCompile(`(?m)^\s*ssl_verify:\s*(false|no)`).MatchString(string(b)),
			"http_registry":  false, "trusted_host": false, "extra_index": false})
	}
	return items, nil
}

// dockerDaemonConfig reads Docker's settings and daemon.json. Docker
// Desktop's own settings on macOS live in its app group container, which
// macOS guards with a prompt, so instead we look for what that setting does:
// the Docker API answering without TLS on localhost:2375.
func dockerDaemonConfig(ctx context.Context) ([]Item, error) {
	it := Item{"expose_tcp_no_tls": false, "insecure_registries": 0, "found": false}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:2375", 300*time.Millisecond); err == nil {
		c.Close()
		it["found"] = true
		it["expose_tcp_no_tls"] = true
	}
	for _, f := range []string{
		filepath.Join(home(), ".docker/desktop/settings-store.json"),
		filepath.Join(os.Getenv("APPDATA"), "Docker/settings-store.json"),
	} {
		b, err := readSmall(f)
		if err != nil {
			continue
		}
		it["found"] = true
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			for _, k := range []string{"ExposeDockerAPIOnTCP2375", "exposeDockerAPIOnTCP2375"} {
				if v, _ := m[k].(bool); v {
					it["expose_tcp_no_tls"] = true
				}
			}
		}
	}
	for _, f := range []string{filepath.Join(home(), ".docker/daemon.json"), "/etc/docker/daemon.json"} {
		b, err := readSmall(f)
		if err != nil {
			continue
		}
		it["found"] = true
		var d struct {
			Hosts              []string `json:"hosts"`
			TLSVerify          bool     `json:"tlsverify"`
			InsecureRegistries []string `json:"insecure-registries"`
		}
		if json.Unmarshal(b, &d) == nil {
			for _, h := range d.Hosts {
				if strings.HasPrefix(h, "tcp://") && !d.TLSVerify {
					it["expose_tcp_no_tls"] = true
				}
			}
			it["insecure_registries"] = len(d.InsecureRegistries)
		}
	}
	if found, _ := it["found"].(bool); !found {
		return nil, nil
	}
	return []Item{it}, nil
}
