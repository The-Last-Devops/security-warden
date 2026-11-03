// Package vulndb matches project dependencies against a local copy of the
// OSV vulnerability data (https://osv.dev).
//
// The background service downloads the public OSV files for a few package
// ecosystems (a plain HTTPS GET; nothing about this machine is sent) and
// keeps a compact index: package name -> affected version ranges, fixed
// versions, ids and severity. A scan only reads that index, never the
// network.
package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/appdir"
)

// Ecosystems are the OSV ecosystems the index covers, with OSV's spelling.
var Ecosystems = []string{"npm", "PyPI", "Go", "crates.io", "RubyGems"}

// Dir is where the index files live.
func Dir() string { return appdir.File("vulndb") }

func indexPath(eco string) string { return filepath.Join(Dir(), eco+".json.gz") }

// Event is one boundary of an affected range: exactly one field is set.
type Event struct {
	Introduced   string `json:"i,omitempty"`
	Fixed        string `json:"f,omitempty"`
	LastAffected string `json:"l,omitempty"`
}

// Affected is one package a vulnerability affects.
type Affected struct {
	Package  string    `json:"p"`
	Ranges   [][]Event `json:"r,omitempty"`
	Versions []string  `json:"v,omitempty"`
}

// Vuln is the compact form of one OSV record.
type Vuln struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"a,omitempty"`
	Severity string     `json:"s,omitempty"` // CRITICAL, HIGH, MODERATE, LOW or ""
	Affected []Affected `json:"x"`
}

// Index is the local copy for one ecosystem.
type Index struct {
	Ecosystem string           `json:"ecosystem"`
	Updated   time.Time        `json:"updated"` // newest "modified" time included
	FullAt    time.Time        `json:"full_at"` // when the whole archive was last read
	Vulns     map[string]*Vuln `json:"vulns"`

	byPkg map[string][]ref
}

type ref struct {
	v *Vuln
	a int
}

// osvRecord is the part of the OSV schema we read.
type osvRecord struct {
	ID        string    `json:"id"`
	Modified  time.Time `json:"modified"`
	Withdrawn string    `json:"withdrawn"`
	Aliases   []string  `json:"aliases"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
		Versions         []string `json:"versions"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		EcosystemSpecific struct {
			Severity string `json:"severity"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// convert keeps what matching needs. It returns nil for records that do
// not apply (withdrawn, malicious-package reports, other ecosystems).
func convert(eco string, b []byte) (*Vuln, time.Time, error) {
	var r osvRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, time.Time{}, err
	}
	if r.ID == "" || r.Withdrawn != "" || strings.HasPrefix(r.ID, "MAL-") {
		return nil, r.Modified, nil
	}
	v := &Vuln{ID: r.ID, Severity: normSeverity(r.DatabaseSpecific.Severity)}
	for _, a := range r.Aliases {
		if strings.HasPrefix(a, "CVE-") || strings.HasPrefix(a, "GHSA-") {
			v.Aliases = append(v.Aliases, a)
		}
	}
	if v.Severity == "" {
		for _, s := range r.Severity {
			if s.Type == "CVSS_V3" {
				v.Severity = rating(cvss3(s.Score))
			}
		}
	}
	for _, a := range r.Affected {
		if a.Package.Ecosystem != eco || a.Package.Name == "" {
			continue
		}
		if v.Severity == "" {
			v.Severity = normSeverity(a.DatabaseSpecific.Severity + a.EcosystemSpecific.Severity)
		}
		out := Affected{Package: NormName(eco, a.Package.Name), Versions: a.Versions}
		for _, rg := range a.Ranges {
			if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
				continue
			}
			var evs []Event
			for _, e := range rg.Events {
				switch {
				case e.Introduced != "":
					evs = append(evs, Event{Introduced: e.Introduced})
				case e.Fixed != "":
					evs = append(evs, Event{Fixed: e.Fixed})
				case e.LastAffected != "":
					evs = append(evs, Event{LastAffected: e.LastAffected})
				}
			}
			if len(evs) > 0 {
				out.Ranges = append(out.Ranges, evs)
			}
		}
		if len(out.Ranges) > 0 || len(out.Versions) > 0 {
			v.Affected = append(v.Affected, out)
		}
	}
	if len(v.Affected) == 0 || (eco == "Go" && everyVersionNoFix(v)) {
		return nil, r.Modified, nil
	}
	return v, r.Modified, nil
}

// everyVersionNoFix: every range starts at 0 and never ends. In the Go
// database these are notices about unmaintained packages (for example
// x/crypto/openpgp), matched per module although only one package is meant,
// so they flag every project using the module.
func everyVersionNoFix(v *Vuln) bool {
	for _, a := range v.Affected {
		if len(a.Versions) > 0 {
			return false
		}
		for _, rg := range a.Ranges {
			for _, e := range rg {
				if e.Fixed != "" || e.LastAffected != "" || (e.Introduced != "" && e.Introduced != "0") {
					return false
				}
			}
		}
	}
	return true
}

func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MODERATE"
	case "LOW":
		return "LOW"
	}
	return ""
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// NormName puts a package name in the form both sides are compared in:
// PyPI names are case-insensitive and treat - _ . alike (PEP 503).
func NormName(eco, name string) string {
	if eco == "PyPI" {
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}

// Hit is one vulnerability affecting one installed version.
type Hit struct {
	ID       string
	Aliases  []string
	Severity string
	Fixed    string // lowest fixed version above the installed one, or ""
}

// Match lists the vulnerabilities affecting name at version.
func (ix *Index) Match(name, version string) []Hit {
	var hits []Hit
	for _, r := range ix.byPkg[NormName(ix.Ecosystem, name)] {
		a := r.v.Affected[r.a]
		affected, fixed := affects(ix.Ecosystem, a, version)
		if affected {
			hits = append(hits, Hit{ID: r.v.ID, Aliases: r.v.Aliases, Severity: r.v.Severity, Fixed: fixed})
		}
	}
	return hits
}

// affects follows the OSV rules: a version is affected when it is listed,
// or when, walking a range's events in version order, the last event at or
// below it is an "introduced" (a "last_affected" covers itself).
func affects(eco string, a Affected, version string) (bool, string) {
	for _, v := range a.Versions {
		if v == version {
			return true, nextFixed(eco, a, version)
		}
	}
	for _, evs := range a.Ranges {
		in := false
		sorted := sortEvents(eco, evs)
		for _, e := range sorted {
			switch {
			case e.Introduced != "":
				if e.Introduced == "0" {
					in = true
				} else if c, ok := Compare(eco, version, e.Introduced); ok && c >= 0 {
					in = true
				}
			case e.Fixed != "":
				if c, ok := Compare(eco, version, e.Fixed); ok && c >= 0 {
					in = false
				}
			case e.LastAffected != "":
				if c, ok := Compare(eco, version, e.LastAffected); ok && c > 0 {
					in = false
				}
			}
		}
		if in {
			return true, nextFixed(eco, a, version)
		}
	}
	return false, ""
}

func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		if e.Introduced == "0" {
			return ""
		}
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	}
	return e.LastAffected
}

func sortEvents(eco string, evs []Event) []Event {
	out := append([]Event(nil), evs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := eventVersion(out[i]), eventVersion(out[j])
		if a == "" || b == "" {
			return a == "" && b != ""
		}
		c, ok := Compare(eco, a, b)
		return ok && c < 0
	})
	return out
}

// nextFixed is the lowest fixed version above the installed one.
func nextFixed(eco string, a Affected, version string) string {
	best := ""
	for _, evs := range a.Ranges {
		for _, e := range evs {
			if e.Fixed == "" {
				continue
			}
			if c, ok := Compare(eco, e.Fixed, version); !ok || c <= 0 {
				continue
			}
			if best == "" {
				best = e.Fixed
			} else if c, ok := Compare(eco, e.Fixed, best); ok && c < 0 {
				best = e.Fixed
			}
		}
	}
	return best
}

func (ix *Index) build() {
	ix.byPkg = map[string][]ref{}
	for _, v := range ix.Vulns {
		for i, a := range v.Affected {
			ix.byPkg[a.Package] = append(ix.byPkg[a.Package], ref{v, i})
		}
	}
}

// Packages is how many packages the index knows vulnerabilities for.
func (ix *Index) Packages() int { return len(ix.byPkg) }

// Max sizes: the index is ours, but a damaged one must not eat memory.
const maxIndexBytes = 256 << 20

func readIndex(path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var ix Index
	if err := json.NewDecoder(io.LimitReader(zr, maxIndexBytes)).Decode(&ix); err != nil {
		return nil, err
	}
	if ix.Vulns == nil {
		return nil, errors.New("empty index")
	}
	ix.build()
	return &ix, nil
}

func writeIndex(ix *Index) (int64, error) {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return 0, err
	}
	path := indexPath(ix.Ecosystem)
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	zw := gzip.NewWriter(f)
	err = json.NewEncoder(zw).Encode(ix)
	if err2 := zw.Close(); err == nil {
		err = err2
	}
	if err2 := f.Close(); err == nil {
		err = err2
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	fi, err := os.Stat(tmp)
	if err != nil {
		return 0, err
	}
	return fi.Size(), os.Rename(tmp, path)
}

// cache keeps loaded indexes between scans of the background service, and
// reloads one when its file changes.
var cache = struct {
	sync.Mutex
	m map[string]cached
}{m: map[string]cached{}}

type cached struct {
	mod  time.Time
	size int64
	ix   *Index
}

// Load returns the index of every ecosystem that has one.
func Load() map[string]*Index {
	out := map[string]*Index{}
	cache.Lock()
	defer cache.Unlock()
	for _, eco := range Ecosystems {
		fi, err := os.Stat(indexPath(eco))
		if err != nil {
			delete(cache.m, eco)
			continue
		}
		if c, ok := cache.m[eco]; ok && c.mod.Equal(fi.ModTime()) && c.size == fi.Size() {
			out[eco] = c.ix
			continue
		}
		ix, err := readIndex(indexPath(eco))
		if err != nil || ix.Ecosystem != eco {
			continue
		}
		cache.m[eco] = cached{fi.ModTime(), fi.Size(), ix}
		out[eco] = ix
	}
	return out
}

// cvss3 computes a CVSS v3.x base score from its vector, or -1.
func cvss3(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return -1
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}
	pick := func(k string, vals map[string]float64) (float64, bool) {
		x, ok := vals[m[k]]
		return x, ok
	}
	changed := m["S"] == "C"
	av, ok1 := pick("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := pick("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prVals := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		prVals = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok3 := pick("PR", prVals)
	ui, ok4 := pick("UI", map[string]float64{"N": 0.85, "R": 0.62})
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := pick("C", cia)
	i, ok6 := pick("I", cia)
	a, ok7 := pick("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (m["S"] != "U" && !changed) {
		return -1
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	score := impact + expl
	if changed {
		score *= 1.08
	}
	return roundUp(math.Min(score, 10))
}

// roundUp is CVSS 3.1's Roundup: the smallest one-decimal number >= x.
func roundUp(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// SeverityRank orders severities; an unknown one counts as moderate.
func SeverityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "LOW":
		return 1
	}
	return 2
}

// SeverityLabel is the lower-case name of a rank.
func SeverityLabel(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 1:
		return "low"
	}
	return "moderate"
}

// DisplayID names a hit by its CVE when it has one, else its own id.
func DisplayID(h Hit) string {
	for _, a := range append([]string{h.ID}, h.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return h.ID
}

// Group merges hits that are one vulnerability published by several
// databases (a GHSA and a PYSEC record sharing a CVE): they share an id or
// an alias. The merged hit keeps the worst severity and a fix if any has one.
func Group(hits []Hit) []Hit {
	var out []Hit
	var keys []map[string]bool
	for _, h := range hits {
		ids := append([]string{h.ID}, h.Aliases...)
		at := -1
		for i, k := range keys {
			for _, id := range ids {
				if k[id] {
					at = i
				}
			}
		}
		if at < 0 {
			k := map[string]bool{}
			for _, id := range ids {
				k[id] = true
			}
			keys = append(keys, k)
			h.Aliases = append([]string(nil), h.Aliases...)
			out = append(out, h)
			continue
		}
		g := &out[at]
		for _, id := range ids {
			if !keys[at][id] {
				keys[at][id] = true
				g.Aliases = append(g.Aliases, id)
			}
		}
		if g.Severity == "" || h.Severity != "" && SeverityRank(h.Severity) > SeverityRank(g.Severity) {
			g.Severity = h.Severity
		}
		if g.Fixed == "" {
			g.Fixed = h.Fixed
		}
	}
	return out
}

func rating(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MODERATE"
	case score > 0:
		return "LOW"
	}
	return ""
}
