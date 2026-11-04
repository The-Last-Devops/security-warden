package feedback

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

var env = Env{Home: "/Users/janedoe", User: "janedoe", FullName: "Jane Marigold", Host: "Janes-MacBook-Pro.local",
	CodeRoots: append(append([]string(nil), codeRoots...), "/srv/checkouts")}

// secrets that must never survive, in any text.
var forbidden = []string{"/Users/janedoe", "janedoe", "JaneDoe", "Janes-MacBook-Pro", "Marigold", "jane@example.com",
	"acme-billing", "secret-project", "10.20.30.40", "fe80::1c2b:3d4e:5f60:7a8b", "ghp_", "AKIAIOSFODNN7EXAMPLE",
	"deadbeefcafebabe0011", "wJalrXUtnFEMI", "hunter2pass", "k8s-prod-eu", "Xy9kQ2mN7pL4vR8sT1wZ3bC6"}

func fakeToken(prefix string, n int) string {
	const alpha = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY"
	var b strings.Builder
	b.WriteString(prefix)
	for i := 0; i < n; i++ {
		b.WriteByte(alpha[(i*7+3)%len(alpha)])
	}
	return b.String()
}

func TestScrubRemovesIdentifyingDetails(t *testing.T) {
	s := NewScrubber(env)
	gh := fakeToken("ghp_", 36)
	in := strings.Join([]string{
		"Credential file readable by other users: /Users/janedoe/.aws/credentials",
		"quoted: '/Users/janedoe/Code/secret-project/my file.env'",
		"repo: ~/Code/acme-billing/config/prod/settings.json and ~/'Projects/acme billing/x'",
		"other home: /home/janedoe/.ssh/id_rsa and C:\\Users\\janedoe\\AppData",
		"user janedoe on Janes-MacBook-Pro.local (Janes-MacBook-Pro), JANEDOE, Jane Marigold",
		"mail jane@example.com, remote git@git.example.com:acme-billing/app.git, proxy http://janedoe:hunter2pass@proxy.example.com:3128",
		"addr 10.20.30.40:22 and fe80::1c2b:3d4e:5f60:7a8b and loopback 127.0.0.1, any 0.0.0.0:8080, ::1",
		"token " + gh + " aws AKIAIOSFODNN7EXAMPLE secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"hex deadbeefcafebabe0011 random Xy9kQ2mN7pL4vR8sT1wZ3bC6",
		"extra root /srv/checkouts/acme-billing/main.go",
	}, "\n")
	out := s.Scrub(in)
	for _, bad := range append(forbidden, gh) {
		if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
			t.Errorf("%q survived:\n%s", bad, out)
		}
	}
	for _, want := range []string{"~/.aws/credentials", "<repo>/…", "<repo>/…/*.json", "~/.ssh/id_rsa", "<user>", "<host>",
		"<email>", "<credentials>@", "<ip>", "127.0.0.1", "0.0.0.0:8080", "::1", "<hex>"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
}

func TestScrubKeepsOrdinaryText(t *testing.T) {
	s := NewScrubber(env)
	for _, in := range []string{
		"Credential file readable by other users: ~/.aws/credentials",
		"credential-file-readable-by-others",
		"Library with a serious known vulnerability: tar 6.1.13 → 7.5.21",
		"Run `chmod 600 ~/.aws/credentials` at 12:30:45",
		"openai.openai-chatgpt-adhoc · golang.org/x/crypto 0.57.0",
		"Time Machine is not backing up this Mac",
		"/opt/homebrew/Cellar/python@3.14/3.14.4_1/Resources/Python.app/Contents/MacOS/Python",
	} {
		if got := s.Scrub(in); got != in {
			t.Errorf("Scrub(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestScrubKeepsWellKnownFileNames(t *testing.T) {
	s := NewScrubber(env)
	for in, want := range map[string]string{
		"~/Code/acme-billing/.env":                  "<repo>/…/.env",
		"~/Code/acme-billing/web/package-lock.json": "<repo>/…/package-lock.json",
		"~/src/acme-billing/keys/id_ed25519":        "<repo>/…/id_ed25519",
		"~/work/acme-billing/certs/acme-prod.pem":   "<repo>/…/*.pem",
		"~/dev/acme-billing/acme-internal-notes":    "<repo>/…",
	} {
		if got := s.Scrub(in); got != want {
			t.Errorf("Scrub(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubFindingValues(t *testing.T) {
	f := engine.Finding{RuleID: "secret-file-committed", Severity: "high", Source: "dev_files",
		Title:   "Secret file committed to Git: acme-billing/config/.env",
		Explain: "Anyone with acme-billing can read it.", Fix: "Run `git -C /Users/janedoe/Code/team/acme-billing rm --cached config/.env`",
		Item: engine.Item{"repo": "/Users/janedoe/Code/team/acme-billing", "repo_name": "acme-billing", "file": "config/.env"}}
	d := FalsePositive(f, nil, Info{Version: "v1.3.0", Platform: "macos", Via: "cli"}, NewScrubber(env))
	for _, bad := range []string{"acme-billing", "janedoe", "team/"} {
		if strings.Contains(d.Preview, bad) || strings.Contains(d.URL, url.QueryEscape(bad)) {
			t.Errorf("%q survived:\n%s", bad, d.Preview)
		}
	}
	if !strings.Contains(d.Preview, "<repo>/…/.env") || !strings.Contains(d.Preview, "secret-file-committed") {
		t.Errorf("preview misses the place or rule:\n%s", d.Preview)
	}

	k := engine.Finding{RuleID: "kube-skip-tls", Severity: "high", Source: "kubeconfig",
		Title: "kubectl skips TLS checks for k8s-prod-eu", Explain: "x", Fix: "y",
		Item: engine.Item{"current_context": "k8s-prod-eu", "file": "/Users/janedoe/.kube/config"}}
	d = FalsePositive(k, nil, Info{Version: "v1", Platform: "linux", Via: "mcp"}, NewScrubber(env))
	if strings.Contains(d.Preview, "k8s-prod-eu") || !strings.Contains(d.Preview, "<name>") {
		t.Errorf("context name survived:\n%s", d.Preview)
	}
}

func TestFalsePositiveLink(t *testing.T) {
	f := engine.Finding{RuleID: "backup-none", Severity: "medium", Source: "backup", Title: "Time Machine is not backing up this Mac",
		Explain: "No backup.", Fix: "Turn it on.", Item: engine.Item{"tool": "Time Machine"}}
	d := FalsePositive(f, nil, Info{Version: "v1.3.0", Platform: "macos", Via: "web"}, NewScrubber(env))
	u, err := url.Parse(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "github.com" || u.Path != "/"+Repo+"/issues/new" {
		t.Fatalf("link goes to %s%s", u.Host, u.Path)
	}
	q := u.Query()
	if q.Get("template") != "bug.yml" || q.Get("title") != "False positive: backup-none" || q.Get("version") != "v1.3.0" ||
		q.Get("os") != "macOS" || q.Get("surface") != "Web UI" || !strings.Contains(q.Get("what"), "Rule: backup-none (medium, tier stable)") ||
		!strings.Contains(q.Get("output"), "No backup.") {
		t.Fatalf("query: %v", q)
	}
	// Every field the link fills in is in the preview, word for word.
	for _, k := range []string{"what", "version", "output"} {
		if !strings.Contains(d.Preview, q.Get(k)) {
			t.Errorf("preview misses %s", k)
		}
	}
	if d.Shortened {
		t.Error("short report marked shortened")
	}
}

func TestFieldIDsMatchTemplates(t *testing.T) {
	// The ids the links fill must exist in .github/ISSUE_TEMPLATE.
	ids := map[string][]string{"bug.yml": {"what", "version", "os", "surface", "output"}, "rule-request.yml": {"risk", "platforms"}}
	for file, want := range ids {
		b, err := readTemplate(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range want {
			if !strings.Contains(b, "id: "+id+"\n") {
				t.Errorf("%s has no field %s", file, id)
			}
		}
	}
}

func TestLongReportIsShortened(t *testing.T) {
	long := strings.Repeat("A very long explanation that goes on. ", 400)
	f := engine.Finding{RuleID: "x", Severity: "low", Source: "posture", Title: "t", Explain: long, Fix: long}
	d := FalsePositive(f, nil, Info{Version: "v1", Platform: "linux", Via: "cli"}, NewScrubber(env))
	if len(d.URL) > MaxURL || !d.Shortened || !strings.Contains(d.Preview, "shortened to fit") {
		t.Fatalf("url %d chars, shortened %v", len(d.URL), d.Shortened)
	}
	// The preview still says what the link holds.
	q, _ := url.ParseQuery(strings.SplitN(d.URL, "?", 2)[1])
	if !strings.Contains(d.Preview, q.Get("output")) {
		t.Error("preview and link differ after shortening")
	}
}

func TestIdea(t *testing.T) {
	d, err := Idea("Check ~/.npmrc for tokens\nlike the one in /Users/janedoe/.npmrc owned by jane@example.com", Info{Version: "v1", Platform: "windows", Via: "mcp"}, NewScrubber(env))
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(strings.SplitN(d.URL, "?", 2)[1])
	if q.Get("template") != "rule-request.yml" || q.Get("title") != "Rule: Check ~/.npmrc for tokens" || q.Get("platforms") != "Windows" {
		t.Fatalf("query %v", q)
	}
	if strings.Contains(d.Preview, "janedoe") || !strings.Contains(q.Get("risk"), "AI agent") {
		t.Errorf("preview:\n%s", d.Preview)
	}
	if _, err := Idea("   ", Info{}, NewScrubber(env)); err == nil {
		t.Error("empty idea accepted")
	}
	big, _ := Idea(strings.Repeat("é", MaxIdea), Info{}, NewScrubber(env))
	if len(big.URL) > MaxURL {
		t.Error("long idea not shortened")
	}
}

func TestDefaultEnvScrubsThisMachine(t *testing.T) {
	e := DefaultEnv()
	s := NewScrubber(e)
	for _, v := range []string{e.Home, e.User, e.Host} {
		if len(v) < 3 || v == "root" || v == "/" {
			continue
		}
		if out := s.Scrub("x " + v + " y"); strings.Contains(out, v) {
			t.Errorf("%q survived: %q", v, out)
		}
	}
}

func readTemplate(name string) (string, error) {
	b, err := os.ReadFile("../../.github/ISSUE_TEMPLATE/" + name)
	return string(b), err
}

func TestBugCarriesScrubbedLogNewestFirst(t *testing.T) {
	s := NewScrubber(Env{Home: "/Users/alice", User: "alice", Host: "alice-mbp", CodeRoots: []string{"Code"}})
	log := "2026-11-04 10:00:00 INFO  [scan] done in 5.0s, 36 sources, v1 darwin/arm64\n" +
		"2026-11-04 10:00:00 ERROR [posture] timed out after 60.0s\n" +
		"2026-11-04 10:00:00 ERROR [git_history] command: git -C /Users/alice/Code/acme-secret-project log (3.0s): signal: killed\n"
	d := Bug("Scan hangs at 89%", log, Info{Version: "v1", Platform: "macos", Via: "web"}, s)
	if d.Kind != "bug" || d.Title != "Bug: Scan hangs at 89%" || !strings.Contains(d.URL, "template=bug.yml") {
		t.Fatalf("draft = %+v", d)
	}
	for _, leak := range []string{"alice", "acme-secret-project"} {
		if strings.Contains(d.Preview, leak) || strings.Contains(d.URL, leak) {
			t.Fatalf("%q left in the report:\n%s", leak, d.Preview)
		}
	}
	if i, j := strings.Index(d.Preview, "[git_history]"), strings.Index(d.Preview, "[scan]"); i < 0 || j < 0 || i > j {
		t.Fatalf("errors not first:\n%s", d.Preview)
	}
	if e := Bug("", "", Info{Version: "v1", Platform: "linux", Via: "cli"}, s); e.Title != "Bug report" || strings.Contains(e.Preview, "Scan log") {
		t.Fatalf("empty draft = %+v", e)
	}
}

func TestPickLogErrorsFirstAndFoldsRepeats(t *testing.T) {
	log := "2026-11-04 10:00:00 INFO  [scan] done in 5.0s, 36 sources, v1 darwin/arm64\n" +
		"2026-11-04 10:00:00 WARN  [git_history] slow: 5.2s\n" +
		"2026-11-04 10:05:00 INFO  [scan] done in 61.0s, 36 sources, v1 darwin/arm64\n" +
		"2026-11-04 10:05:00 WARN  [git_history] slow: 5.8s\n" +
		"2026-11-04 10:05:00 ERROR [posture] timed out after 60.0s\n"
	got := pickLog(log)
	want := []string{
		"2026-11-04 10:05:00 ERROR [posture] timed out after 60.0s",
		"2026-11-04 10:05:00 WARN  [git_history] slow: 5.8s (×2)",
		"2026-11-04 10:05:00 INFO  [scan] done in 61.0s, 36 sources, v1 darwin/arm64 (×2)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("pickLog:\n%s", strings.Join(got, "\n"))
	}
}
