// Package feedback builds GitHub "new issue" links that people (or their AI
// agents) open themselves to report a wrong finding or suggest a new check.
// Security Warden never sends anything: it only fills in a link, after
// taking out what could identify the machine or its owner (home folder,
// user and host names, repositories, emails, addresses, tokens).
package feedback

import (
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/vulndb"
)

// Env is what identifies this machine and its owner.
type Env struct {
	Home     string
	User     string
	FullName string
	Host     string
	// CodeRoots are the code folders, relative to Home ("Code") or
	// absolute (from SW_CODE_DIRS).
	CodeRoots []string
}

// codeRoots mirrors the folders the code scan walks (internal/source).
var codeRoots = []string{"Code", "code", "src", "dev", "Projects", "projects", "work", "workspace", "repos", "git", "go/src", "Developer"}

// DefaultEnv reads the environment of this machine.
func DefaultEnv() Env {
	e := Env{CodeRoots: append([]string(nil), codeRoots...)}
	e.Home, _ = os.UserHomeDir()
	if u, err := user.Current(); err == nil {
		e.User = u.Username
		e.FullName = u.Name
	}
	if e.User == "" {
		e.User = os.Getenv("USER")
	}
	if i := strings.LastIndexAny(e.User, `\/`); i >= 0 { // DOMAIN\user on Windows
		e.User = e.User[i+1:]
	}
	e.Host, _ = os.Hostname()
	if extra := os.Getenv("SW_CODE_DIRS"); extra != "" {
		e.CodeRoots = append(e.CodeRoots, filepath.SplitList(extra)...)
	}
	return e
}

// Scrubber takes identifying details out of text.
type Scrubber struct {
	env    Env
	words  []replacement // user, name and host names, longest first
	values []replacement // values from a finding, longest first
	codeRe []*regexp.Regexp
}

// replacement replaces a whole word (or path) with a placeholder.
type replacement struct {
	from string
	re   *regexp.Regexp
	to   string
}

func word(v, to string) replacement {
	return replacement{v, regexp.MustCompile(`(?i)(^|[^\p{L}\p{N}_-])` + regexp.QuoteMeta(v) + `($|[^\p{L}\p{N}_-])`), to}
}

func (r replacement) apply(t string) string {
	if r.re == nil {
		return strings.ReplaceAll(t, r.from, r.to)
	}
	// Twice: two matches next to each other share the boundary between them.
	t = r.re.ReplaceAllString(t, "${1}"+r.to+"${2}")
	return r.re.ReplaceAllString(t, "${1}"+r.to+"${2}")
}

// NewScrubber prepares a scrubber for env.
func NewScrubber(env Env) *Scrubber {
	s := &Scrubber{env: env}
	type name struct{ v, to string }
	var names []name
	common := map[string]bool{"root": true, "admin": true, "administrator": true, "user": true, "runner": true, "localhost": true}
	add := func(n string, min int, to string) {
		n = strings.TrimSpace(n)
		if len([]rune(n)) >= min && !common[strings.ToLower(n)] {
			names = append(names, name{n, to})
		}
	}
	h := strings.TrimSuffix(env.Host, ".")
	add(h, 2, "<host>")
	add(strings.TrimSuffix(h, ".local"), 2, "<host>")
	if i := strings.IndexByte(h, '.'); i > 0 {
		add(h[:i], 2, "<host>")
	}
	add(env.User, 2, "<user>")
	add(env.FullName, 3, "<user>")
	for _, part := range strings.Fields(env.FullName) {
		add(part, 4, "<user>")
	}
	sort.SliceStable(names, func(i, j int) bool { return len(names[i].v) > len(names[j].v) })
	for _, n := range names {
		s.words = append(s.words, word(n.v, n.to))
	}
	var rel []string
	for _, r := range env.CodeRoots {
		if r == "" {
			continue
		}
		if filepath.IsAbs(r) || strings.HasPrefix(r, "/") {
			s.values = append(s.values, replacement{from: strings.TrimRight(r, `/\`), to: "<code>"})
			continue
		}
		rel = append(rel, regexp.QuoteMeta(r))
	}
	sort.Slice(rel, func(i, j int) bool { return len(rel[i]) > len(rel[j]) })
	if len(rel) > 0 {
		roots := "(?:" + strings.Join(rel, "|") + ")"
		// ~/'Code/a b/.env' (a quoted path, as report.Tilde writes it) and ~/Code/x/y.
		s.codeRe = append(s.codeRe,
			regexp.MustCompile(`~[/\\]'`+roots+`[/\\]([^']*)'`),
			regexp.MustCompile(`~[/\\]`+roots+`[/\\]([^\s'"`+"`"+`<>|,;()\[\]{}]+)`))
	}
	s.codeRe = append(s.codeRe, regexp.MustCompile(`<code>[/\\]([^\s'"`+"`"+`<>|,;()\[\]{}]+)`))
	sort.Slice(s.values, func(i, j int) bool { return len(s.values[i].from) > len(s.values[j].from) })
	return s
}

// With returns a copy that also replaces these values, e.g. a finding's
// repository path and name.
func (s *Scrubber) With(rs ...replacement) *Scrubber {
	c := *s
	c.values = append(append([]replacement(nil), s.values...), rs...)
	sort.SliceStable(c.values, func(i, j int) bool { return len(c.values[i].from) > len(c.values[j].from) })
	return &c
}

var (
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	winHomeRe   = regexp.MustCompile(`(?i)\b[a-z]:[\\/]Users[\\/][^\\/\s'"<>]+`)
	awsKeyRe    = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b`)
	gitRemoteRe = regexp.MustCompile(`(?i)(?:\b[a-z][a-z0-9+.-]*://[^\s'"]+|\b[\w.-]+@[\w.-]+:[^\s'"]+)\.git\b`)
	urlCredsRe  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@'"]+(?::[^/\s@'"]*)?@`)
	homesRe     = regexp.MustCompile(`(?i)(?:/Users/|/home/|[a-z]:\\Users\\|[a-z]:/Users/)[^/\\\s'"` + "`" + `<>]+`)
	repoRe      = regexp.MustCompile(`<repo>[/\\]([^\s'"` + "`" + `<>|,;()\[\]{}]+)`)
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re      = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?`)
	uuidRe      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	hexRe       = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{16,}\b`)
	tokenRe     = regexp.MustCompile(`[A-Za-z0-9_+=/-]{20,}`)
	dotfileRe   = regexp.MustCompile(`^\.[A-Za-z0-9._-]{1,40}$`)
	keyNameRe   = regexp.MustCompile(`^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$`)
	plainWord   = regexp.MustCompile(`^[A-Z]?[a-z]{2,}$`)
	extRe       = regexp.MustCompile(`\.(pem|key|p12|pfx|crt|tfstate|tfvars|env|json|ya?ml|toml|ini|conf|cfg|properties|sqlite|db)$`)
)

// Scrub returns text without what could identify the machine or its owner:
// tokens become <secret>/<token>, emails <email>, the home folder ~, paths
// in code folders and repository names <repo>/…, user and host names
// <user>/<host>, addresses <ip>, long hex <hex>.
func (s *Scrubber) Scrub(text string) string {
	// Control characters out, but keep the lines.
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(engine.Clean(strings.ReplaceAll(l, "\t", "    ")), `\t`, "    ")
	}
	t := strings.Join(lines, "\n")
	// Known token formats first, while the text is still whole.
	if sp := source.SecretSpans(t); len(sp) > 0 {
		sort.Slice(sp, func(i, j int) bool { return sp[i][0] > sp[j][0] })
		last := len(t) + 1
		for _, x := range sp {
			if x[1] > last { // overlaps the span already replaced
				continue
			}
			t = t[:x[0]] + "<secret>" + t[x[1]:]
			last = x[0]
		}
	}
	t = awsKeyRe.ReplaceAllString(t, "<secret>")
	t = gitRemoteRe.ReplaceAllString(t, "<git-remote>")
	t = urlCredsRe.ReplaceAllString(t, "${1}<credentials>@")
	t = emailRe.ReplaceAllString(t, "<email>")
	for _, v := range s.values {
		if v.from != "" {
			t = v.apply(t)
		}
	}
	t = winHomeRe.ReplaceAllString(t, "~")
	if h := strings.TrimRight(s.env.Home, `/\`); len(h) > 1 {
		for _, hh := range uniq(h, filepath.ToSlash(h), strings.ReplaceAll(h, "/", `\`)) {
			t = strings.ReplaceAll(t, "'"+hh+"/", "~/'")
			t = strings.ReplaceAll(t, "'"+hh+`\`, `~\'`)
			t = strings.ReplaceAll(t, hh, "~")
		}
	}
	t = homesRe.ReplaceAllString(t, "~")
	for _, re := range s.codeRe {
		t = re.ReplaceAllStringFunc(t, func(m string) string { return "<repo>/…" + kept(re.FindStringSubmatch(m)[1]) })
	}
	t = repoRe.ReplaceAllStringFunc(t, func(m string) string { return "<repo>/…" + kept(repoRe.FindStringSubmatch(m)[1]) })
	t = strings.ReplaceAll(t, "<repo>/…/…", "<repo>/…")
	for _, w := range s.words {
		t = w.apply(t)
	}
	t = ipv4Re.ReplaceAllStringFunc(t, func(ip string) string {
		if ip == "127.0.0.1" || ip == "0.0.0.0" {
			return ip
		}
		for _, p := range strings.Split(ip, ".") {
			if len(p) > 3 || p > "255" && len(p) == 3 {
				return ip
			}
		}
		return "<ip>"
	})
	t = ipv6Re.ReplaceAllStringFunc(t, func(m string) string {
		groups := strings.Split(strings.SplitN(m, "%", 2)[0], ":")
		filled := 0
		for _, g := range groups {
			if g != "" {
				filled++
			}
		}
		// ::1, :: and times like 12:30:45 stay; addresses and MACs go.
		if filled <= 1 || (!strings.Contains(m, "::") && len(groups) < 4) {
			return m
		}
		return "<ip>"
	})
	t = uuidRe.ReplaceAllString(t, "<hex>")
	t = hexRe.ReplaceAllString(t, "<hex>")
	t = tokenRe.ReplaceAllStringFunc(t, func(m string) string {
		if tokenShaped(m) {
			return "<token>"
		}
		return m
	})
	return t
}

func uniq(xs ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// kept is what may stay of a path inside a repository: a well-known file
// name (".env", "package-lock.json", "id_rsa"), else only its kind of file.
func kept(rest string) string {
	rest = strings.TrimRight(rest, `/\.:`)
	base := rest
	if i := strings.LastIndexAny(rest, `/\`); i >= 0 {
		base = rest[i+1:]
	}
	switch {
	case base == "", base == "…":
		return ""
	case dotfileRe.MatchString(base), keyNameRe.MatchString(base), vulndb.LockKind(base) != "":
		return "/" + base
	}
	if m := extRe.FindString(strings.ToLower(base)); m != "" {
		return "/*" + m
	}
	return ""
}

// tokenShaped: a long run with upper and lower case letters and digits and
// enough randomness, unlike words, ids and kebab-case names. A run with
// slashes is a path, not base64, when a part of it is a plain word
// ("4_1/Resources/Python").
func tokenShaped(s string) bool {
	if strings.Contains(s, "/") {
		for _, part := range strings.Split(s, "/") {
			if plainWord.MatchString(part) {
				return false
			}
		}
	}
	var up, low, dig bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			low = true
		case r >= '0' && r <= '9':
			dig = true
		}
	}
	return up && low && dig && entropy(s) >= 3.5
}

func entropy(s string) float64 {
	n := map[rune]float64{}
	for _, r := range s {
		n[r]++
	}
	var e float64
	l := float64(len([]rune(s)))
	for _, c := range n {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}

// privateFields are item fields whose values name something of the owner's:
// repositories, clusters, servers, hosts, profiles, accounts.
var privateFields = map[string]string{
	"repo": "<repo>", "repo_name": "<repo>", "project": "<repo>",
	"current_context": "<name>", "client_cert_context": "<name>", "tailnet": "<name>",
	"container": "<name>", "guest_name": "<name>", "user": "<user>", "server": "<name>",
	"profile": "<name>", "host": "<host>", "url_host": "<host>", "subnet_routes": "<ip>",
}

// generic values stay: they name nothing of the owner's.
var generic = map[string]bool{"default": true, "localhost": true, "github.com": true, "gitlab.com": true,
	"bitbucket.org": true, "origin": true, "root": true, "system profile": true, "guest": true}

// ForFinding is s plus the identifying values of a finding's item.
func (s *Scrubber) ForFinding(f engine.Finding) *Scrubber {
	var rs []replacement
	for k, ph := range privateFields {
		v, ok := f.Item[k].(string)
		v = strings.TrimSpace(v)
		if !ok || len(v) < 2 || generic[strings.ToLower(v)] || strings.HasPrefix(strings.ToLower(v), "profile ") {
			continue
		}
		rs = append(rs, word(v, ph))
		if k == "repo" {
			rs = append(rs, word(tildePath(s.env.Home, v), ph))
		}
	}
	return s.With(rs...)
}

// tildePath is v with the home folder shown as ~, as titles show paths.
func tildePath(home, v string) string {
	if home != "" && strings.HasPrefix(v, home) {
		return "~" + strings.TrimPrefix(v, home)
	}
	return v
}
