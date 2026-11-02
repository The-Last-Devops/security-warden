package source

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func readSmallN(path string, n int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }

// cloudConfig looks at kubeconfig contexts and cloud CLI credentials:
// how they authenticate, never the secrets themselves.
func cloudConfig(ctx context.Context) ([]Item, error) {
	h := home()
	var items []Item

	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = filepath.Join(h, ".kube", "config")
	}
	for _, f := range filepath.SplitList(kc) {
		b, err := readSmall(f)
		if err != nil {
			continue
		}
		s := string(b)
		cur := ""
		if m := regexp.MustCompile(`(?m)^current-context:\s*"?([^"\n]+)`).FindStringSubmatch(s); m != nil {
			cur = strings.TrimSpace(m[1])
		}
		items = append(items, Item{
			"kind": "kubeconfig", "file": f,
			"insecure_skip_tls": regexp.MustCompile(`(?m)^\s*insecure-skip-tls-verify:\s*true`).MatchString(s),
			"static_token":      regexp.MustCompile(`(?m)^\s*token:\s*\S`).MatchString(s),
			"current_context":   cur,
			"current_is_prod":   regexp.MustCompile(`(?i)(^|[-_./])(prod|production|prd|live)([-_./]|$)`).MatchString(cur),
			"sa_type":           "",
		})
	}

	adc := filepath.Join(h, ".config/gcloud/application_default_credentials.json")
	if b, err := readSmall(adc); err == nil {
		var v struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(b, &v)
		items = append(items, Item{"kind": "gcloud_adc", "file": adc, "sa_type": v.Type,
			"insecure_skip_tls": false, "static_token": false, "current_context": "", "current_is_prod": false})
	}

	// Long-lived service-account keys left in the usual places.
	for _, dir := range []string{h, filepath.Join(h, ".config"), filepath.Join(h, "keys"), filepath.Join(h, ".gcp")} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			b, err := readSmallN(f, 8<<10)
			if err != nil {
				continue
			}
			s := string(b)
			if strings.Contains(s, `"type": "service_account"`) && strings.Contains(s, `"private_key"`) {
				items = append(items, Item{"kind": "gcp_sa_key", "file": f, "sa_type": "service_account",
					"insecure_skip_tls": false, "static_token": false, "current_context": "", "current_is_prod": false})
			}
		}
	}

	for _, f := range []struct{ kind, rel string }{
		{"azure_sp", ".azure/service_principal_entries.json"},
		{"vault_token", ".vault-token"},
		{"doctl", ".config/doctl/config.yaml"},
		{"supabase", ".supabase/access-token"},
	} {
		p := filepath.Join(h, f.rel)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
			items = append(items, Item{"kind": f.kind, "file": p, "sa_type": "",
				"insecure_skip_tls": false, "static_token": true, "current_context": "", "current_is_prod": false})
		}
	}
	return items, nil
}

var historyKinds = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}`)},
	{"ai_key", regexp.MustCompile(`sk-(ant-|proj-)?[A-Za-z0-9_-]{30,}`)},
	{"slack_token", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"password_flag", regexp.MustCompile(`--password[= ]\S{4,}|\b(mysql|mariadb|mysqldump|mysqladmin)\b[^\n]*\s-p[^\s-]\S{3,}|PGPASSWORD=\S{4,}|MYSQL_PWD=\S{4,}|sshpass -p\s*\S{4,}`)},
	{"bearer", regexp.MustCompile(`Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}`)},
	{"url_with_password", regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^:/\s@]+:[^@\s/]{4,}@`)},
}

// shellHistory counts secrets in shell and REPL history files. Only counts
// per kind are kept.
func shellHistory(ctx context.Context) ([]Item, error) {
	var items []Item
	for _, rel := range []string{".zsh_history", ".bash_history", ".local/share/fish/fish_history",
		".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".rediscli_history"} {
		path := filepath.Join(home(), rel)
		b, err := readSmallN(path, 32<<20)
		if err != nil {
			continue
		}
		s := string(b)
		for _, k := range historyKinds {
			if n := len(k.re.FindAllStringIndex(s, -1)); n > 0 {
				items = append(items, Item{"file": path, "kind": k.kind, "count": n})
			}
		}
	}
	return items, nil
}
