package source

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	remoteSection = regexp.MustCompile(`^\[remote\s+"([^"]*)"\]`)
	remoteURL     = regexp.MustCompile(`^url\s*=\s*(.+)$`)
	// scheme://userinfo@host — userinfo is checked by urlCredentials.
	urlUserinfo = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://([^/@]+)@([^/:?#]+)`)
	// A token used as the user name alone (https://ghp_xxx@github.com).
	tokenUser = regexp.MustCompile(`^(ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|glptt-|gldt-)`)
)

// urlCredentials tells whether a remote URL carries a password or token,
// and returns the host. "git@host:repo" and "https://user@host" do not.
func urlCredentials(url string) (host string, creds bool) {
	m := urlUserinfo.FindStringSubmatch(strings.Trim(strings.TrimSpace(url), `"`))
	if m == nil {
		return "", false
	}
	user, pass, hasPass := strings.Cut(m[1], ":")
	return m[2], (hasPass && pass != "") || tokenUser.MatchString(user)
}

// parseRemotes lists (remote, host) pairs whose URL carries credentials.
// The URL itself, with the token, never leaves this function.
func parseRemotes(config string) [][2]string {
	var out [][2]string
	remote := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			remote = ""
			if m := remoteSection.FindStringSubmatch(line); m != nil {
				remote = m[1]
			}
			continue
		}
		if remote == "" {
			continue
		}
		if m := remoteURL.FindStringSubmatch(line); m != nil {
			if host, ok := urlCredentials(m[1]); ok {
				out = append(out, [2]string{remote, host})
			}
		}
	}
	return out
}

// gitRemotes reads .git/config of every repo in the code folders and
// reports remotes whose URL has a password or token written into it.
func gitRemotes(ctx context.Context) ([]Item, error) {
	w := codeWalk()
	repos := append([]string{}, w.repos...)
	sort.Strings(repos)
	var items []Item
	for _, repo := range repos {
		b, err := readSmallN(filepath.Join(repo, ".git", "config"), 256<<10)
		if err != nil {
			continue
		}
		for _, r := range parseRemotes(string(b)) {
			items = append(items, Item{"repo": repo, "repo_name": filepath.Base(repo), "remote": r[0], "host": r[1], "has_credentials": true})
		}
	}
	return items, nil
}
