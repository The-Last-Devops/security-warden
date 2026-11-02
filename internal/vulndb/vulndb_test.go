package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCompareSemver(t *testing.T) {
	less := [][2]string{
		{"1.0.0", "1.0.1"}, {"1.9.0", "1.10.0"}, {"1.0.0-alpha", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-alpha.1"}, {"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-beta.2", "1.0.0-beta.11"}, {"1.0.0-rc.1", "1.0.0"}, {"v0.9.0", "1.0"},
		{"0.0.0-20210101000000-abcdef123456", "0.0.1"}, {"2.0.0", "18446744073709551616.0.0"},
	}
	for _, p := range less {
		if c, ok := Compare("npm", p[0], p[1]); !ok || c != -1 {
			t.Errorf("%s < %s: got %d %v", p[0], p[1], c, ok)
		}
		if c, _ := Compare("npm", p[1], p[0]); c != 1 {
			t.Errorf("%s > %s: got %d", p[1], p[0], c)
		}
	}
	if c, ok := Compare("Go", "1.2.3+build", "v1.2.3"); !ok || c != 0 {
		t.Error("build metadata must not count")
	}
	if _, ok := Compare("npm", "latest", "1.0.0"); ok {
		t.Error("garbage must not compare")
	}
}

func TestComparePEP440(t *testing.T) {
	// Each is lower than the next (PEP 440's own example order, plus forms).
	order := []string{"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456",
		"1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5",
		"1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1", "2!0.1"}
	for i := 0; i+1 < len(order); i++ {
		a, b := order[i], order[i+1]
		c, ok := Compare("PyPI", a, b)
		if a == "1.0" && b == "1.0+abc.5" {
			if !ok || c != 0 {
				t.Errorf("local version must compare equal: %d", c)
			}
			continue
		}
		if !ok || c != -1 {
			t.Errorf("%s < %s: got %d %v", a, b, c, ok)
		}
	}
	for _, p := range [][2]string{{"1.0", "1.0.0"}, {"1.0-1", "1.0.post1"}, {"1.0alpha1", "1.0a1"}, {"1.0c1", "1.0rc1"}, {"v2.0", "2.0"}} {
		if c, ok := Compare("PyPI", p[0], p[1]); !ok || c != 0 {
			t.Errorf("%s == %s: got %d %v", p[0], p[1], c, ok)
		}
	}
}

func TestCompareGem(t *testing.T) {
	order := []string{"1.0.0.a", "1.0.0.rc1", "1.0.0", "1.0.1", "1.10", "2"}
	for i := 0; i+1 < len(order); i++ {
		if c, ok := Compare("RubyGems", order[i], order[i+1]); !ok || c != -1 {
			t.Errorf("%s < %s: got %d %v", order[i], order[i+1], c, ok)
		}
	}
	if c, ok := Compare("RubyGems", "1.0", "1.0.0"); !ok || c != 0 {
		t.Error("trailing zeros")
	}
}

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": 5.9,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		if got := cvss3(v); got != want {
			t.Errorf("%s: got %v, want %v", v, got, want)
		}
	}
	if cvss3("CVSS:4.0/AV:N") != -1 || cvss3("junk") != -1 {
		t.Error("unknown vectors")
	}
}

const ghsaLodash = `{"id":"GHSA-35jh-r3h4-6jhm","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],
 "database_specific":{"severity":"HIGH"},
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
   "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`

const pysec = `{"id":"PYSEC-2023-1","modified":"2024-02-01T00:00:00Z","aliases":["CVE-2023-0001","GHSA-aaaa-bbbb-cccc"],
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}],
 "affected":[{"package":{"ecosystem":"PyPI","name":"Some_Package"},
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"2.3.1"},{"introduced":"3.0"},{"last_affected":"3.1"}]},
             {"type":"GIT","repo":"https://example.com/x","events":[{"introduced":"abc"}]}],
   "versions":["1.5"]}]}`

func TestConvertAndMatch(t *testing.T) {
	v, mod, err := convert("npm", []byte(ghsaLodash))
	if err != nil || v == nil || v.Severity != "HIGH" || mod.Year() != 2024 {
		t.Fatalf("convert: %+v %v %v", v, mod, err)
	}
	ix := &Index{Ecosystem: "npm", Vulns: map[string]*Vuln{v.ID: v}}
	ix.build()
	if h := ix.Match("lodash", "4.17.20"); len(h) != 1 || h[0].Fixed != "4.17.21" || DisplayID(h[0]) != "CVE-2021-23337" {
		t.Errorf("4.17.20: %+v", h)
	}
	if h := ix.Match("lodash", "4.17.21"); len(h) != 0 {
		t.Errorf("fixed version matched: %+v", h)
	}

	p, _, _ := convert("PyPI", []byte(pysec))
	if p == nil || p.Severity != "MODERATE" || len(p.Affected[0].Ranges) != 1 {
		t.Fatalf("pysec: %+v", p)
	}
	px := &Index{Ecosystem: "PyPI", Vulns: map[string]*Vuln{p.ID: p}}
	px.build()
	want := map[string]bool{"1.5": true, "1.9": false, "2.0": true, "2.3.0": true, "2.3.1": false, "2.9": false, "3.0.1": true, "3.1": true, "3.1.1": false}
	for ver, aff := range want {
		if got := len(px.Match("some-package", ver)) > 0; got != aff {
			t.Errorf("PyPI %s: affected=%v, want %v", ver, got, aff)
		}
	}
	if h := px.Match("SOME.package", "2.1"); len(h) != 1 || h[0].Fixed != "2.3.1" {
		t.Errorf("normalized name: %+v", h)
	}

	for _, rec := range []string{
		`{"id":"MAL-2024-1","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]}`,
		`{"id":"GHSA-x","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]}`,
		`{"id":"GHSA-y","affected":[{"package":{"ecosystem":"PyPI","name":"x"},"versions":["1.0.0"]}]}`,
	} {
		if v, _, err := convert("npm", []byte(rec)); v != nil || err != nil {
			t.Errorf("should be dropped: %s", rec)
		}
	}
}

func TestGroup(t *testing.T) {
	hits := []Hit{
		{ID: "GHSA-1", Aliases: []string{"CVE-1"}, Severity: "MODERATE", Fixed: "2.0"},
		{ID: "PYSEC-1", Aliases: []string{"CVE-1"}, Severity: "HIGH"},
		{ID: "GHSA-2", Severity: "LOW", Fixed: "1.5"},
	}
	g := Group(hits)
	if len(g) != 2 || g[0].Severity != "HIGH" || g[0].Fixed != "2.0" || DisplayID(g[0]) != "CVE-1" {
		t.Errorf("group: %+v", g)
	}
}

func TestLockfiles(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},
			"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"},"node_modules/al":{"name":"real","version":"2.0.0"},
			"node_modules/ws":{"link":true}}}`, []string{"lodash@4.17.20", "@scope/b@1.0.0", "real@2.0.0"}},
		{"package-lock.json", `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}`,
			[]string{"a@1.0.0", "b@2.0.0"}},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      x:\n        version: 1.0.0\npackages:\n  '@scope/a@1.2.3':\n    resolution: {}\n  b@2.0.0(react@18.0.0):\n    resolution: {}\nsnapshots:\n  c@3.0.0:\n    dependencies: {}\n",
			[]string{"@scope/a@1.2.3", "b@2.0.0"}},
		{"pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@babel/core/7.0.0_abc:\n    dev: true\n",
			[]string{"lodash@4.17.20", "@babel/core@7.0.0"}},
		{"yarn.lock", "# yarn lockfile v1\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.1.0\":\n  version \"7.12.13\"\n  resolved \"x\"\n\nlodash@^4.17.0:\n  version \"4.17.20\"\n",
			[]string{"@babel/code-frame@7.12.13", "lodash@4.17.20"}},
		{"yarn.lock", "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.20\n  resolution: \"lodash@npm:4.17.20\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n",
			[]string{"lodash@4.17.20"}},
		{"requirements-dev.txt", "Django==4.2.0 # web\nrequests[socks] == 2.31.0 ; python_version > '3'\nflask>=2\n-r base.txt\nNumPy==1.26.0 \\\n    --hash=sha256:abc\n",
			[]string{"django@4.2.0", "requests@2.31.0", "numpy@1.26.0"}},
		{"poetry.lock", "[[package]]\nname = \"Jinja2\"\nversion = \"3.1.2\"\n\n[package.dependencies]\nx = \"*\"\n\n[[package]]\nname = \"pyyaml\"\nversion = \"6.0\"\n",
			[]string{"jinja2@3.1.2", "pyyaml@6.0"}},
		{"Cargo.lock", "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
			[]string{"time@0.1.43"}},
		{"Pipfile.lock", `{"default":{"urllib3":{"version":"==1.26.4"}},"develop":{"pytest":{"version":"==7.0.0"}}}`,
			[]string{"urllib3@1.26.4", "pytest@7.0.0"}},
		{"go.mod", "module x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.10.0 // indirect\n\tgithub.com/a/b v1.2.3+incompatible\n\tgithub.com/c/d v1.0.0\n)\n\nrequire github.com/e/f v0.1.0\n\nreplace github.com/c/d => ../d\nreplace github.com/e/f v0.1.0 => github.com/e/f v0.1.1\n",
			[]string{"golang.org/x/net@0.10.0", "github.com/a/b@1.2.3", "github.com/e/f@0.1.1"}},
		{"Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n",
			[]string{"nokogiri@1.13.0", "rack@2.2.3"}},
		{"package-lock.json", `{"packages":{"node_modules/evil":{"version":"1.0.0; rm -rf ~"}}}`, nil},
	}
	for _, c := range cases {
		var got []string
		for _, d := range ParseLock("/p/"+c.name, []byte(c.body)) {
			got = append(got, d.Name+"@"+d.Version)
		}
		if !sameSet(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if Kind("/p/yarn.lock", []byte("# x\n\n__metadata:\n  version: 6\n")) != KindYarnBerry || LockKind("requirements.in") != "" {
		t.Error("kinds")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestCommands(t *testing.T) {
	cases := []struct {
		kind string
		role Role
		want string
	}{
		{KindNPM, Direct, "npm install lodash@4.17.21"},
		{KindNPM, DirectDev, "npm install -D lodash@4.17.21"},
		{KindNPM, Indirect, "npm update lodash"},
		{KindPNPM, Direct, "pnpm add lodash@4.17.21"},
		{KindYarnBerry, Indirect, "yarn up -R lodash"},
		{KindPip, Unknown, "pip install 'lodash>=4.17.21'"},
		{KindGo, Unknown, "go get lodash@v4.17.21 && go mod tidy"},
		{KindCargo, Unknown, "cargo update -p lodash --precise 4.17.21"},
	}
	for _, c := range cases {
		if got, why := Commands(c.kind, "lodash", "4.17.21", c.role); got != c.want || why == "" {
			t.Errorf("%s/%d: %q (why %q)", c.kind, c.role, got, why)
		}
	}
}

// TestUpdate builds an index from a fake OSV bucket, then applies an
// incremental update that reads modified_id.csv only down to what it has.
func TestUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range map[string]string{
		"GHSA-35jh-r3h4-6jhm.json": ghsaLodash,
		"MAL-2024-1.json":          `{"id":"MAL-2024-1"}`,
	} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()

	newer := strings.Replace(strings.Replace(ghsaLodash, "2024-01-01", "2024-03-01", 1), `"fixed":"4.17.21"`, `"fixed":"4.17.22"`, 1)
	var csvRead, recordsFetched int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != userAgent || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		switch r.URL.Path {
		case "/npm/all.zip":
			w.Write(zbuf.Bytes())
		case "/npm/modified_id.csv":
			csvRead++
			fmt.Fprint(w, "2024-03-02T00:00:00Z,MAL-2024-9\n2024-03-01T00:00:00Z,GHSA-35jh-r3h4-6jhm\n2023-12-31T00:00:00Z,GHSA-old\n")
		case "/npm/GHSA-35jh-r3h4-6jhm.json":
			recordsFetched++
			fmt.Fprint(w, newer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL + "/"
	defer func() { BaseURL = old }()
	r := Update(context.Background(), "npm")
	if r.Err != nil || !r.Full || r.Vulns != 1 || r.Bytes == 0 {
		t.Fatalf("full update: %+v", r)
	}
	r = Update(context.Background(), "npm")
	if r.Err != nil || r.Full || r.Changed != 1 || csvRead != 1 || recordsFetched != 1 {
		t.Fatalf("incremental update: %+v csv=%d fetched=%d", r, csvRead, recordsFetched)
	}
	ix := Load()["npm"]
	if ix == nil || !ix.Updated.Equal(time.Date(2024, 3, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("index: %+v", ix)
	}
	if h := ix.Match("lodash", "4.17.21"); len(h) != 1 || h[0].Fixed != "4.17.22" {
		t.Errorf("after incremental: %+v", h)
	}
	if fi, err := os.Stat(indexPath("npm")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("index file: %v %v", fi, err)
	}
}
