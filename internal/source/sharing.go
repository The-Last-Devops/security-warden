package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func portOpen(ctx context.Context, port int) bool {
	d := net.Dialer{Timeout: 400 * time.Millisecond}
	c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// sharing reports macOS sharing services: SMB share points (and whether
// guests may use them), Internet Sharing and printer sharing.
func sharing(ctx context.Context) ([]Item, error) {
	if runtime.GOOS != "darwin" {
		return nil, Skip{"skip.platform"}
	}
	var items []Item
	smbOn := portOpen(ctx, 445)
	if out, err := run(ctx, "sharing", "-l"); err == nil || out != "" {
		for _, block := range strings.Split(out, "\nname:")[1:] {
			name := strings.TrimSpace(strings.SplitN(block, "\n", 2)[0])
			path := ""
			if m := regexp.MustCompile(`(?m)^path:\s*(.+)$`).FindStringSubmatch(block); m != nil {
				path = strings.TrimSpace(m[1])
			}
			smb := regexp.MustCompile(`(?s)smb:\s*\{(.*?)\}`).FindStringSubmatch(block)
			if smb == nil {
				continue
			}
			shared := regexp.MustCompile(`shared:\s*1`).MatchString(smb[1])
			guest := regexp.MustCompile(`guest access:\s*1`).MatchString(smb[1])
			readOnly := regexp.MustCompile(`read-only:\s*1`).MatchString(smb[1])
			items = append(items, Item{"kind": "smb_share", "name": name, "path": path,
				"service_on": smbOn, "shared": shared, "guest": guest, "read_only": readOnly})
		}
	}
	if out, err := run(ctx, "cupsctl"); err == nil {
		items = append(items, Item{"kind": "printer", "name": "", "path": "", "service_on": strings.Contains(out, "_share_printers=1"),
			"shared": strings.Contains(out, "_share_printers=1"), "guest": false, "read_only": false})
	}
	if out, err := run(ctx, "defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"); err == nil {
		on := regexp.MustCompile(`Enabled\s*=\s*1`).MatchString(out)
		items = append(items, Item{"kind": "internet_sharing", "name": "", "path": "", "service_on": on, "shared": on, "guest": false, "read_only": false})
	}
	return items, nil
}

// authorizedKeys counts the keys that may log in to this account over SSH.
func authorizedKeys(ctx context.Context) ([]Item, error) {
	var items []Item
	sshOn := portOpen(ctx, 22)
	for _, rel := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
		p := filepath.Join(home(), rel)
		b, err := readSmall(p)
		if err != nil {
			continue
		}
		n, weak, restricted := 0, 0, 0
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			n++
			if strings.Contains(line, "ssh-dss ") {
				weak++
			}
			if strings.HasPrefix(line, "command=") || strings.HasPrefix(line, "from=") || strings.HasPrefix(line, "restrict") {
				restricted++
			}
		}
		it := Item{"path": p, "count": n, "weak": weak, "restricted": restricted, "ssh_on": sshOn}
		if fi, err := os.Stat(p); err == nil {
			modeFields(it, fi)
		}
		items = append(items, it)
	}
	return items, nil
}

// browserExtensions lists enabled Chromium-family extensions with powerful
// permissions. Safari is skipped: its data is privacy-protected.
func browserExtensions(ctx context.Context) ([]Item, error) {
	var roots []struct{ browser, dir string }
	h := home()
	switch runtime.GOOS {
	case "darwin":
		for _, b := range []struct{ name, rel string }{
			{"Chrome", "Library/Application Support/Google/Chrome"},
			{"Brave", "Library/Application Support/BraveSoftware/Brave-Browser"},
			{"Edge", "Library/Application Support/Microsoft Edge"},
			{"Arc", "Library/Application Support/Arc/User Data"},
			{"Chromium", "Library/Application Support/Chromium"},
			{"Vivaldi", "Library/Application Support/Vivaldi"},
		} {
			roots = append(roots, struct{ browser, dir string }{b.name, filepath.Join(h, b.rel)})
		}
	case "linux":
		for _, b := range []struct{ name, rel string }{
			{"Chrome", ".config/google-chrome"}, {"Chromium", ".config/chromium"},
			{"Brave", ".config/BraveSoftware/Brave-Browser"}, {"Edge", ".config/microsoft-edge"},
		} {
			roots = append(roots, struct{ browser, dir string }{b.name, filepath.Join(h, b.rel)})
		}
	}
	var items []Item
	for _, r := range roots {
		profiles, _ := filepath.Glob(filepath.Join(r.dir, "*", "Preferences"))
		for _, prefPath := range profiles {
			profile := filepath.Dir(prefPath)
			b, err := readSmallN(prefPath, 32<<20)
			if err != nil {
				continue
			}
			var prefs struct {
				Extensions struct {
					Settings map[string]struct {
						Location       int    `json:"location"`
						State          *int   `json:"state"`
						DisableReasons any    `json:"disable_reasons"`
						FromWebstore   bool   `json:"from_webstore"`
						Path           string `json:"path"`
					} `json:"settings"`
				} `json:"extensions"`
			}
			if json.Unmarshal(b, &prefs) != nil {
				continue
			}
			for id, s := range prefs.Extensions.Settings {
				if s.Location == 5 || s.Location == 10 { // component / built-in
					continue
				}
				if s.State != nil && *s.State == 0 {
					continue
				}
				if dr, ok := s.DisableReasons.(float64); ok && dr != 0 {
					continue
				}
				if l, ok := s.DisableReasons.([]any); ok && len(l) > 0 {
					continue
				}
				manifest := ""
				if s.Location == 4 && filepath.IsAbs(s.Path) {
					manifest = filepath.Join(s.Path, "manifest.json")
				} else {
					ms, _ := filepath.Glob(filepath.Join(profile, "Extensions", id, "*", "manifest.json"))
					if len(ms) > 0 {
						manifest = ms[len(ms)-1]
					}
				}
				mb, err := readSmall(manifest)
				if err != nil {
					continue
				}
				var m struct {
					Name            string   `json:"name"`
					Permissions     []any    `json:"permissions"`
					HostPermissions []string `json:"host_permissions"`
					ContentScripts  []struct {
						Matches []string `json:"matches"`
					} `json:"content_scripts"`
				}
				if json.Unmarshal(mb, &m) != nil {
					continue
				}
				perms := map[string]bool{}
				allURLs := false
				hosts := append([]string{}, m.HostPermissions...)
				for _, p := range m.Permissions {
					if ps, ok := p.(string); ok {
						perms[ps] = true
						hosts = append(hosts, ps)
					}
				}
				for _, cs := range m.ContentScripts {
					hosts = append(hosts, cs.Matches...)
				}
				for _, h := range hosts {
					if h == "<all_urls>" || h == "*://*/*" || h == "http://*/*" || h == "https://*/*" {
						allURLs = true
					}
				}
				name := m.Name
				if strings.HasPrefix(name, "__MSG_") {
					name = localizedName(filepath.Dir(manifest), name)
				}
				items = append(items, Item{
					"browser": r.browser, "profile": filepath.Base(profile), "id": id, "name": name,
					"unpacked": s.Location == 4, "from_webstore": s.FromWebstore,
					"all_urls":             allURLs,
					"debugger":             perms["debugger"],
					"proxy":                perms["proxy"],
					"native":               perms["nativeMessaging"],
					"cookies":              perms["cookies"],
					"web_request_blocking": perms["webRequestBlocking"],
				})
			}
		}
	}
	return items, nil
}

func localizedName(dir, msg string) string {
	key := strings.TrimSuffix(strings.TrimPrefix(msg, "__MSG_"), "__")
	for _, loc := range []string{"en", "en_US", "vi"} {
		b, err := readSmall(filepath.Join(dir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &msgs) == nil {
			for k, v := range msgs {
				if strings.EqualFold(k, key) {
					return v.Message
				}
			}
		}
	}
	return key
}

var codeRoots = []string{"Code", "code", "src", "dev", "Projects", "projects", "work", "workspace", "repos", "git", "go/src", "Developer"}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "target": true, ".next": true, ".cache": true, "Pods": true, ".terraform": true, "__pycache__": true}

var envName = regexp.MustCompile(`^(\.env(\..+)?|.+\.env|.+\.tfstate|.+\.tfvars|.+\.pem|.+\.key|.+\.p12|.+\.pfx|id_rsa|id_ed25519|id_ecdsa|service-account.*\.json|.+-sa-key\.json)$`)
var envTemplate = regexp.MustCompile(`\.(example|sample|template|dist|defaults|schema|test)$|\.example\.|\.sample\.`)

// devFiles walks the usual code folders (never Documents, Desktop or other
// protected folders) for secret files inside Git repos, and asks Git whether
// each one is committed or ignored. Bounded in depth, entries and time.
func devFiles(ctx context.Context) ([]Item, error) {
	if !gitAvailable() {
		return nil, Skip{"skip.git"}
	}
	var roots []string
	if extra := os.Getenv("SW_CODE_DIRS"); extra != "" {
		roots = append(roots, filepath.SplitList(extra)...)
	}
	for _, r := range codeRoots {
		roots = append(roots, filepath.Join(home(), r))
	}
	seenRoot := map[string]bool{}
	deadline := time.Now().Add(8 * time.Second)
	entries := 0
	truncated := false
	type cand struct{ path, rel, kind string }
	byRepo := map[string][]cand{}
	for _, root := range roots {
		// Walk the real folder (a symlinked ~/Code is still scanned), once,
		// and never inside folders macOS protects with a privacy prompt.
		real, err := filepath.EvalSymlinks(root)
		if err != nil || seenRoot[strings.ToLower(real)] || privacyProtected(real) {
			continue
		}
		seenRoot[strings.ToLower(real)] = true
		baseDepth := strings.Count(real, string(filepath.Separator))
		filepath.WalkDir(real, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			entries++
			if entries > 200000 || time.Now().After(deadline) {
				truncated = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || strings.Count(path, string(filepath.Separator))-baseDepth > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !d.Type().IsRegular() || !envName.MatchString(name) || envTemplate.MatchString(name) {
				return nil
			}
			kind := "env"
			switch {
			case strings.HasSuffix(name, ".tfstate"), strings.HasSuffix(name, ".tfvars"):
				kind = "terraform"
			case strings.HasSuffix(name, ".json"):
				kind = "service_account"
			case strings.Contains(name, "id_") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") ||
				strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx"):
				kind = "key"
			}
			if kind == "key" || kind == "service_account" {
				if b, err := readSmallN(path, 16<<10); err != nil || !(strings.Contains(string(b), "PRIVATE KEY") || strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx")) {
					return nil // certificates and public keys are fine
				}
			}
			repo := repoRoot(filepath.Dir(path))
			if repo == "" {
				return nil
			}
			rel, _ := filepath.Rel(repo, path)
			byRepo[repo] = append(byRepo[repo], cand{path, rel, kind})
			return nil
		})
	}
	var items []Item
	for repo, cs := range byRepo {
		var rels []string
		for _, c := range cs {
			rels = append(rels, c.rel)
		}
		tracked, ignored := gitStatus(ctx, repo, rels)
		for _, c := range cs {
			items = append(items, Item{"path": c.path, "repo": repo, "repo_name": filepath.Base(repo), "file": c.rel,
				"kind": c.kind, "tracked": tracked[c.rel], "ignored": ignored[c.rel]})
		}
	}
	if truncated {
		items = append(items, Item{"path": "", "repo": "", "repo_name": "", "file": "", "kind": "truncated", "tracked": false, "ignored": true})
	}
	return items, nil
}

func repoRoot(dir string) string {
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if d == home() {
			break
		}
	}
	return ""
}
