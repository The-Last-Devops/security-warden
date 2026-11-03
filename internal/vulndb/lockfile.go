package vulndb

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// Dep is one installed package version read from a lock file.
type Dep struct {
	Ecosystem string
	Name      string
	Version   string
}

// Lock file kinds; the kind picks the upgrade command.
const (
	KindNPM       = "npm"
	KindPNPM      = "pnpm"
	KindYarn      = "yarn"
	KindYarnBerry = "yarn-berry" // Yarn 2+, told apart by content (see Kind)
	KindPip       = "pip"
	KindPoetry    = "poetry"
	KindUV        = "uv"
	KindPipenv    = "pipenv"
	KindGo        = "go"
	KindCargo     = "cargo"
	KindBundler   = "bundler"
)

// LockKind tells whether a file name is a lock file we read, and which.
func LockKind(name string) string {
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		return KindNPM
	case "pnpm-lock.yaml":
		return KindPNPM
	case "yarn.lock":
		return KindYarn
	case "poetry.lock":
		return KindPoetry
	case "uv.lock":
		return KindUV
	case "Pipfile.lock":
		return KindPipenv
	case "go.mod":
		return KindGo
	case "Cargo.lock":
		return KindCargo
	case "Gemfile.lock":
		return KindBundler
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return KindPip
	}
	return ""
}

// Kind is LockKind refined by content: Yarn 2+ lock files start with
// __metadata and take other commands than Yarn 1.
func Kind(path string, b []byte) string {
	k := LockKind(filepath.Base(path))
	if k == KindYarn && bytes.Contains(b, []byte("\n__metadata:")) {
		return KindYarnBerry
	}
	return k
}

// EcosystemOf is the OSV ecosystem of a lock file kind.
func EcosystemOf(kind string) string {
	switch kind {
	case KindNPM, KindPNPM, KindYarn, KindYarnBerry:
		return "npm"
	case KindPip, KindPoetry, KindUV, KindPipenv:
		return "PyPI"
	case KindGo:
		return "Go"
	case KindCargo:
		return "crates.io"
	case KindBundler:
		return "RubyGems"
	}
	return ""
}

// safeToken: names and versions end up in commands we print, so anything
// that could be read as shell syntax is dropped.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9@/._+~-]+$`)

// ParseLock reads the packages of one lock file.
func ParseLock(path string, b []byte) []Dep {
	kind := Kind(path, b)
	eco := EcosystemOf(kind)
	var raw [][2]string
	switch kind {
	case KindNPM:
		raw = parseNPMLock(b)
	case KindPNPM:
		raw = parsePNPMLock(b)
	case KindYarn, KindYarnBerry:
		raw = parseYarnLock(b)
	case KindPip:
		raw = parseRequirements(b)
	case KindPoetry, KindUV:
		raw = parseTOMLPackages(b, false)
	case KindCargo:
		raw = parseTOMLPackages(b, true)
	case KindPipenv:
		raw = parsePipfileLock(b)
	case KindGo:
		raw = parseGoMod(b)
	case KindBundler:
		raw = parseGemfileLock(b)
	}
	seen := map[string]bool{}
	var out []Dep
	for _, r := range raw {
		name, ver := r[0], strings.TrimPrefix(r[1], "=")
		if name == "" || ver == "" || !safeToken.MatchString(name) || !safeToken.MatchString(ver) {
			continue
		}
		if eco == "Go" {
			ver = strings.TrimSuffix(strings.TrimPrefix(ver, "v"), "+incompatible")
		}
		k := name + "@" + ver
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, Dep{Ecosystem: eco, Name: name, Version: ver})
	}
	return out
}

// package-lock.json / npm-shrinkwrap.json, lockfileVersion 1 to 3.
func parseNPMLock(b []byte) [][2]string {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out [][2]string
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link {
				continue // the project itself, or a workspace link
			}
			name := key[i+len("node_modules/"):]
			if p.Name != "" {
				name = p.Name // an alias: "foo": "npm:bar@1"
			}
			out = append(out, [2]string{name, p.Version})
		}
		return out
	}
	// lockfileVersion 1: nested "dependencies".
	var walk func(deps map[string]json.RawMessage, depth int)
	walk = func(deps map[string]json.RawMessage, depth int) {
		if depth > 64 {
			return
		}
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			out = append(out, [2]string{name, d.Version})
			walk(d.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return out
}

// splitAt splits "name@version" at the last "@" that is not the first
// character (scoped packages start with one).
func splitAt(s string) (string, string) {
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return "", ""
	}
	return s[:i], s[i+1:]
}

// pnpm-lock.yaml: the keys of the top-level "packages:" map, in the forms
// of lockfile v5 (/name/1.0.0_peer), v6 (/name@1.0.0(peer)) and v9
// (name@1.0.0(peer)).
func parsePNPMLock(b []byte) [][2]string {
	var out [][2]string
	in := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line != "" && line[0] != ' ' && line[0] != '#' {
			in = strings.TrimSpace(line) == "packages:"
			continue
		}
		if !in || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") || !strings.HasSuffix(line, ":") {
			continue
		}
		key := strings.Trim(strings.TrimSuffix(strings.TrimSpace(line), ":"), `'"`)
		if i := strings.Index(key, "("); i > 0 {
			key = key[:i]
		}
		key = strings.TrimPrefix(key, "/")
		name, ver := splitAt(key)
		if name == "" { // v5: name/1.0.0 or @scope/name/1.0.0
			i := strings.LastIndex(key, "/")
			if i <= 0 {
				continue
			}
			name, ver = key[:i], key[i+1:]
		}
		if i := strings.Index(ver, "_"); i > 0 {
			ver = ver[:i]
		}
		out = append(out, [2]string{name, ver})
	}
	return out
}

// yarn.lock, classic (v1) and Berry: a header line naming the package,
// then an indented version line.
func parseYarnLock(b []byte) [][2]string {
	var out [][2]string
	name := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] != ' ' {
			name = ""
			spec := strings.TrimSuffix(strings.TrimSpace(line), ":")
			spec = strings.Trim(strings.SplitN(spec, ",", 2)[0], `"' `)
			if strings.HasPrefix(spec, "__metadata") || strings.Contains(spec, "@patch:") ||
				strings.Contains(spec, "@workspace:") || strings.Contains(spec, "@link:") || strings.Contains(spec, "@file:") {
				continue
			}
			n, _ := splitAt(strings.Replace(spec, "@npm:", "@", 1))
			name = n
			continue
		}
		t := strings.TrimSpace(line)
		if name != "" && (strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "version:")) {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "version:"), "version ")), `"'`)
			out = append(out, [2]string{name, v})
			name = ""
		}
	}
	return out
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.!+_-]+)\s*(?:;.*)?$`)

// requirements*.txt: only exact pins (name==1.2.3) say what is installed.
func parseRequirements(b []byte) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, " --hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		if m := reqLine.FindStringSubmatch(line); m != nil {
			out = append(out, [2]string{NormName("PyPI", m[1]), m[2]})
		}
	}
	return out
}

// poetry.lock, uv.lock and Cargo.lock: [[package]] tables with name and
// version. For Cargo, only crates from a registry (workspace members have
// no source).
func parseTOMLPackages(b []byte, needSource bool) [][2]string {
	var out [][2]string
	var name, ver string
	hasSource, inPkg := false, false
	flush := func() {
		if inPkg && name != "" && ver != "" && (!needSource || hasSource) {
			out = append(out, [2]string{name, ver})
		}
		name, ver, hasSource = "", "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			flush()
			inPkg = t == "[[package]]"
			continue
		}
		if !inPkg {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "name":
			name = v
		case "version":
			ver = v
		case "source":
			// uv writes source = { registry = "..." }, Cargo "registry+https://...".
			hasSource = strings.Contains(v, "registry")
		}
	}
	flush()
	if !needSource {
		for i := range out {
			out[i][0] = NormName("PyPI", out[i][0])
		}
	}
	return out
}

// Pipfile.lock: {"default": {"name": {"version": "==1.2.3"}}, "develop": {...}}.
func parsePipfileLock(b []byte) [][2]string {
	var lock map[string]json.RawMessage
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out [][2]string
	for _, sec := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(lock[sec], &pkgs) != nil {
			continue
		}
		for n, p := range pkgs {
			if strings.HasPrefix(p.Version, "==") {
				out = append(out, [2]string{NormName("PyPI", n), strings.TrimPrefix(p.Version, "==")})
			}
		}
	}
	return out
}

// go.mod: every required module (since Go 1.17 the indirect ones too),
// after replace directives.
func parseGoMod(b []byte) [][2]string {
	req := map[string]string{}
	var order []string
	type repl struct{ to, ver string }
	replace := map[string]repl{}
	block := ""
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == ")" {
			block = ""
			continue
		}
		if len(f) == 2 && f[1] == "(" {
			block = f[0]
			continue
		}
		kw := block
		if kw == "" {
			kw, f = f[0], f[1:]
		}
		switch kw {
		case "require":
			if len(f) >= 2 {
				if _, ok := req[f[0]]; !ok {
					order = append(order, f[0])
				}
				req[f[0]] = f[1]
			}
		case "replace":
			// old [ver] => new [ver]
			for i, x := range f {
				if x == "=>" && i+1 < len(f) {
					r := repl{to: f[i+1]}
					if i+2 < len(f) {
						r.ver = f[i+2]
					}
					replace[f[0]] = r
				}
			}
		}
	}
	var out [][2]string
	for _, m := range order {
		v := req[m]
		if r, ok := replace[m]; ok {
			if r.to != m || r.ver == "" {
				continue // replaced by a fork or a local folder: not this module
			}
			v = r.ver
		}
		out = append(out, [2]string{m, v})
	}
	return out
}

// Gemfile.lock: "    name (1.2.3)" lines under GEM > specs (platform
// suffixes like -x86_64-linux are dropped).
func parseGemfileLock(b []byte) [][2]string {
	var out [][2]string
	inGem := false
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" && line[0] != ' ' {
			inGem = strings.TrimSpace(line) == "GEM"
			continue
		}
		if !inGem || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(line), " (")
		if !ok {
			continue
		}
		ver := strings.TrimSuffix(rest, ")")
		if i := strings.Index(ver, "-"); i > 0 {
			ver = ver[:i]
		}
		out = append(out, [2]string{name, ver})
	}
	return out
}
