package source

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// historyPathspecs narrow "git log" to names that can be secret files; the
// file names are then checked again with envName, exactly as dev_files does.
var historyPathspecs = []string{"*.env*", "*.tfstate", "*.tfvars", "*.pem", "*.key", "*.p12", "*.pfx",
	"*id_rsa", "*id_ed25519", "*id_ecdsa", "*service-account*.json", "*-sa-key.json"}

const (
	maxHistoryRepos = 300
	maxKeyChecks    = 20 // per repo: blobs read to tell a private key from a certificate
)

// gitHistory finds secret files that were committed in the past and deleted
// (or renamed) since: they are gone from the working tree but every clone
// still has them. One item per repo; only names, never contents.
func gitHistory(ctx context.Context) ([]Item, error) {
	if !gitAvailable() {
		return nil, Skip{"skip.git"}
	}
	repos := historyRepos(codeWalk().repos)
	if len(repos) > maxHistoryRepos {
		repos = repos[:maxHistoryRepos]
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	// A few repos at a time: one big history takes seconds of tree diffs.
	results := make([]Item, len(repos))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < max(1, min(4, runtime.NumCPU()/2)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = historyItem(ctx, repos[i])
			}
		}()
	}
	for i := range repos {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var items []Item
	for _, it := range results {
		if it != nil {
			items = append(items, it)
		}
	}
	return items, nil
}

// historyRepos drops linked worktrees whose main repository is also in the
// list: they share one history, so it would be reported twice.
func historyRepos(all []string) []string {
	repos := append([]string{}, all...)
	sort.Strings(repos)
	have := map[string]bool{}
	for _, r := range repos {
		have[r] = true
	}
	var out []string
	for _, r := range repos {
		if main := worktreeMain(r); main != "" && have[main] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// worktreeMain returns the main repository of a linked worktree (its .git
// is a file "gitdir: <main>/.git/worktrees/<name>"), else "".
func worktreeMain(repo string) string {
	b, err := readSmallN(filepath.Join(repo, ".git"), 4<<10)
	if err != nil {
		return ""
	}
	dir, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return ""
	}
	dir = filepath.Clean(strings.TrimSpace(dir))
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repo, dir)
	}
	wt := filepath.Dir(dir) // <main>/.git/worktrees
	if filepath.Base(wt) != "worktrees" || filepath.Base(filepath.Dir(wt)) != ".git" {
		return ""
	}
	return filepath.Dir(filepath.Dir(wt))
}

// historyCache keeps each repo's answer while its branches and tags stay
// the same, so the background service does not walk big histories every
// 30 minutes. File names only, in memory only.
var historyCache = struct {
	sync.Mutex
	m map[string]historyEntry
}{m: map[string]historyEntry{}}

type historyEntry struct {
	refs  string
	files []string
}

// refsState fingerprints a repo's refs (packed-refs and loose refs).
func refsState(repo string) string {
	gitDir := filepath.Join(repo, ".git")
	if main := worktreeMain(repo); main != "" {
		gitDir = filepath.Join(main, ".git")
	}
	var b strings.Builder
	n := 0
	for _, p := range []string{"packed-refs", "HEAD"} {
		if fi, err := os.Stat(filepath.Join(gitDir, p)); err == nil {
			fmt.Fprintf(&b, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	filepath.WalkDir(filepath.Join(gitDir, "refs"), func(p string, d os.DirEntry, err error) error {
		if err != nil || n > 5000 {
			return filepath.SkipAll
		}
		n++
		if fi, err := d.Info(); err == nil && !d.IsDir() {
			fmt.Fprintf(&b, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
		}
		return nil
	})
	return b.String()
}

func historyItem(ctx context.Context, repo string) Item {
	if ctx.Err() != nil {
		return nil
	}
	refs := refsState(repo)
	historyCache.Lock()
	e, ok := historyCache.m[repo]
	historyCache.Unlock()
	files := e.files
	if !ok || e.refs != refs || refs == "" {
		var complete bool
		files, complete = deletedSecretFiles(ctx, repo)
		if complete {
			historyCache.Lock()
			historyCache.m[repo] = historyEntry{refs, files}
			historyCache.Unlock()
		}
	}
	if len(files) == 0 {
		return nil
	}
	// Still tracked today: dev_files already reports those.
	tracked, _ := gitStatus(ctx, repo, files)
	var left []string
	for _, f := range files {
		if !tracked[f] {
			left = append(left, f)
		}
	}
	if len(left) == 0 {
		return nil
	}
	sort.Strings(left)
	shown := left
	if len(shown) > 3 {
		shown = shown[:3]
	}
	return Item{"repo": repo, "repo_name": filepath.Base(repo),
		"file": left[0], "kind": historyKind(path.Base(left[0])), "files": strings.Join(shown, ", "),
		"count": len(left), "others": len(left) - 1}
}

// deletedSecretFiles lists secret-looking paths that a commit on any
// branch or tag deleted. --no-renames makes a rename count as a deletion.
// complete is false when git failed or ran out of time (what it printed
// until then is still used, minus a possibly cut last name).
func deletedSecretFiles(ctx context.Context, repo string) (files []string, complete bool) {
	args := append([]string{"log", "--all", "--no-renames", "--diff-filter=D", "--name-only", "--format=", "-z", "--"}, historyPathspecs...)
	out, err := gitSafe(ctx, repo, nil, args...)
	names := strings.Split(string(out), "\x00")
	if err != nil {
		names = names[:len(names)-1]
	}
	seen := map[string]bool{}
	keyChecks := 0
	for _, f := range names {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		name := path.Base(f)
		if !envName.MatchString(name) || envTemplate.MatchString(name) || skippedHistoryPath(f) {
			continue
		}
		if k := historyKind(name); k == "key" || k == "service_account" {
			// Certificates and public keys are fine: read the deleted blob
			// (first 16 KB, kept in memory only) to see whether it was a
			// private key.
			if keyChecks >= maxKeyChecks || !wasPrivateKey(ctx, repo, f) {
				continue
			}
			keyChecks++
		}
		files = append(files, f)
	}
	return files, err == nil
}

// skippedHistoryPath: files under folders the code walk also skips
// (dependencies, build output) are someone else's test fixtures.
func skippedHistoryPath(f string) bool {
	for _, part := range strings.Split(f, "/") {
		if skipDirs[part] || part == "testdata" || part == "fixtures" {
			return true
		}
	}
	return false
}

func historyKind(name string) string {
	switch {
	case strings.HasSuffix(name, ".tfstate"), strings.HasSuffix(name, ".tfvars"):
		return "terraform"
	case strings.HasSuffix(name, ".json"):
		return "service_account"
	case strings.Contains(name, "id_") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx"):
		return "key"
	}
	return "env"
}

// wasPrivateKey looks at the file as it was just before its deletion.
func wasPrivateKey(ctx context.Context, repo, f string) bool {
	if strings.HasSuffix(f, ".p12") || strings.HasSuffix(f, ".pfx") {
		return true
	}
	out, err := gitSafe(ctx, repo, nil, "log", "--all", "--no-renames", "--diff-filter=D", "-1", "--format=%H", "--", f)
	commit := strings.TrimSpace(string(out))
	if err != nil || len(commit) < 7 || strings.ContainsAny(commit, " \n") {
		return false
	}
	blob, err := gitSafe(ctx, repo, nil, "cat-file", "-p", commit+"^:"+f)
	if err != nil {
		return false
	}
	if len(blob) > 16<<10 {
		blob = blob[:16<<10]
	}
	return strings.Contains(string(blob), "PRIVATE KEY")
}
