package source

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/vulndb"
)

// projectDeps matches the packages pinned in the lock files of the code
// folders against the local OSV index. It reads only local files: the index
// is downloaded by the background service (security-warden vulndb update),
// never during a scan. One item per repository, naming its worst package.
func projectDeps(ctx context.Context) ([]Item, error) {
	db := vulndb.Load()
	if len(db) == 0 {
		return nil, Skip{"skip.vulndb"}
	}
	w := codeWalk()
	haveRepo := map[string]bool{}
	for _, r := range w.repos {
		haveRepo[r] = true
	}
	deadline := time.Now().Add(20 * time.Second)
	byRepo := map[string][]vulnPkg{}
	seen := map[string]bool{}
	for _, lock := range w.locks {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		b, err := readSmallN(lock, 64<<20)
		if err != nil {
			continue
		}
		kind := vulndb.Kind(lock, b)
		ix := db[vulndb.EcosystemOf(kind)]
		if ix == nil {
			continue
		}
		dir := filepath.Dir(lock)
		repo := repoRoot(dir)
		if repo == "" {
			repo = dir
		}
		// A linked worktree (e.g. one per branch) mostly repeats its main
		// repo's lock files: report the main repo only.
		if main := worktreeMain(repo); main != "" && haveRepo[main] {
			continue
		}
		roles := npmRoles(kind, dir)
		for _, d := range vulndb.ParseLock(lock, b) {
			key := repo + "\x00" + d.Ecosystem + "\x00" + d.Name + "\x00" + d.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			groups := vulndb.Group(ix.Match(d.Name, d.Version))
			if len(groups) == 0 {
				continue
			}
			role := vulndb.Unknown
			if roles != nil {
				role = vulndb.Indirect
				if r, ok := roles[d.Name]; ok {
					role = r
				}
			}
			byRepo[repo] = append(byRepo[repo], vulnPkg{lock: lock, dir: dir, kind: kind, dep: d, groups: groups, role: role})
		}
	}
	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	var items []Item
	for _, repo := range repos {
		items = append(items, repoVulnItem(repo, byRepo[repo]))
	}
	return items, nil
}

// HasLockFiles tells the background service whether vulnerability data
// would be of any use here.
func HasLockFiles() bool { return len(codeWalk().locks) > 0 }

type vulnPkg struct {
	lock, dir, kind string
	dep             vulndb.Dep
	groups          []vulndb.Hit
	role            vulndb.Role
}

func (p vulnPkg) rank() int {
	r := 0
	for _, g := range p.groups {
		if n := vulndb.SeverityRank(g.Severity); n > r {
			r = n
		}
	}
	return r
}

func (p vulnPkg) fixed() string {
	best := ""
	for _, g := range p.groups {
		if g.Fixed == "" {
			continue
		}
		if best == "" {
			best = g.Fixed
		} else if c, ok := vulndb.Compare(p.dep.Ecosystem, g.Fixed, best); ok && c > 0 {
			best = g.Fixed
		}
	}
	return best
}

// repoVulnItem sums up one repository: its worst package (most severe,
// then one that has a fix, then the most advisories) and how many others.
func repoVulnItem(repo string, pkgs []vulnPkg) Item {
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.rank() != b.rank() {
			return a.rank() > b.rank()
		}
		if (a.fixed() != "") != (b.fixed() != "") {
			return a.fixed() != ""
		}
		if len(a.groups) != len(b.groups) {
			return len(a.groups) > len(b.groups)
		}
		return a.dep.Name < b.dep.Name
	})
	top := pkgs[0]
	var ids []string
	for _, g := range top.groups {
		ids = append(ids, vulndb.DisplayID(g))
	}
	sort.Strings(ids)
	more := 0
	if len(ids) > 3 {
		more = len(ids) - 3
		ids = append(ids[:3], fmt.Sprintf("+%d", more))
	}
	fixed := top.fixed()
	upgrade, why := vulndb.Commands(top.kind, top.dep.Name, fixed, top.role)
	lockRel, err := filepath.Rel(repo, top.lock)
	if err != nil {
		lockRel = filepath.Base(top.lock)
	}
	severe := false
	for _, p := range pkgs {
		if p.rank() >= vulndb.SeverityRank("HIGH") {
			severe = true
		}
	}
	return Item{
		"repo": repo, "repo_name": filepath.Base(repo), "project": top.dir, "lockfile": lockRel,
		"ecosystem": top.dep.Ecosystem, "package": top.dep.Name, "version": top.dep.Version,
		"fixed": fixed, "ids": strings.Join(ids, ", "), "more_ids": more,
		"severity": vulndb.SeverityLabel(top.rank()), "severe": severe,
		"packages": len(pkgs), "others": len(pkgs) - 1,
		"upgrade_cmd": upgrade, "why": why,
	}
}

// npmRoles reads package.json next to an npm-family lock file: which
// packages the project lists itself, and which only for development. nil
// for other ecosystems (their commands do not depend on it).
func npmRoles(kind, dir string) map[string]vulndb.Role {
	switch kind {
	case vulndb.KindNPM, vulndb.KindPNPM, vulndb.KindYarn, vulndb.KindYarnBerry:
	default:
		return nil
	}
	b, err := readSmallN(filepath.Join(dir, "package.json"), 4<<20)
	if err != nil {
		return nil
	}
	var pj struct {
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
	}
	if json.Unmarshal(b, &pj) != nil {
		return nil
	}
	roles := map[string]vulndb.Role{}
	for n := range pj.DevDependencies {
		roles[n] = vulndb.DirectDev
	}
	for _, m := range []map[string]any{pj.Dependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for n := range m {
			roles[n] = vulndb.Direct
		}
	}
	return roles
}
