package source

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var (
	cronFetch = regexp.MustCompile(`\b(curl|wget|nc|ncat|python3? -c|osascript|base64 (-d|--decode))\b`)
	cronPipe  = regexp.MustCompile(`\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
	urlInLine = regexp.MustCompile(`https?://[^\s"'|>]+`)
)

// persistence lists things that start by themselves: the user's crontab and,
// on macOS, launchd agents and daemons. Only the program and a few flags are
// kept, never script bodies.
func persistence(ctx context.Context) ([]Item, error) {
	var items []Item
	items = append(items, cronItems(ctx)...)
	if runtime.GOOS == "darwin" {
		items = append(items, launchdItems(ctx)...)
	}
	if runtime.GOOS == "linux" {
		items = append(items, systemdUserItems()...)
	}
	return items, nil
}

func cronItems(ctx context.Context) []Item {
	out, err := run(ctx, "crontab", "-l")
	if err != nil {
		return nil
	}
	var items []Item
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(strings.SplitN(line, " ", 2)[0], "=") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 && !strings.HasPrefix(line, "@") {
			continue
		}
		cmdStart := 5
		if strings.HasPrefix(line, "@") {
			cmdStart = 1
		}
		host := ""
		if u := urlInLine.FindString(line); u != "" {
			if p, err := url.Parse(u); err == nil {
				host = p.Host // never the path or query, which may hold tokens
			}
		}
		items = append(items, Item{
			"kind":              "cron",
			"line_no":           i + 1,
			"command":           filepath.Base(f[cmdStart]),
			"url_host":          host,
			"fetches_network":   cronFetch.MatchString(line),
			"pipes_to_shell":    cronPipe.MatchString(line),
			"runs_every_minute": strings.HasPrefix(line, "* * * * *"),
		})
	}
	return items
}

type launchdPlist struct {
	Label            string
	Program          string
	ProgramArguments []string
	RunAtLoad        bool
}

func launchdItems(ctx context.Context) []Item {
	dirs := []struct{ dir, scope string }{
		{filepath.Join(home(), "Library/LaunchAgents"), "user"},
		{"/Library/LaunchAgents", "system-agent"},
		{"/Library/LaunchDaemons", "system-daemon"},
	}
	var items []Item
	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d.dir, "*.plist"))
		for _, f := range files {
			out, err := run(ctx, "plutil", "-convert", "json", "-o", "-", f)
			if err != nil {
				continue
			}
			var p launchdPlist
			if json.Unmarshal([]byte(out), &p) != nil {
				continue
			}
			prog := p.Program
			if prog == "" && len(p.ProgramArguments) > 0 {
				prog = p.ProgramArguments[0]
			}
			if p.Label == "" && prog == "" {
				continue // emptied plist, nothing runs
			}
			inline := false
			if base := filepath.Base(prog); (base == "sh" || base == "bash" || base == "zsh") && len(p.ProgramArguments) > 2 && p.ProgramArguments[1] == "-c" {
				inline = true
			}
			it := Item{
				"kind":                  "launchd",
				"scope":                 d.scope,
				"label":                 p.Label,
				"plist":                 f,
				"program":               prog,
				"apple":                 strings.HasPrefix(p.Label, "com.apple."),
				"run_at_load":           p.RunAtLoad,
				"inline_script":         inline,
				"program_in_tmp":        inTmp(prog),
				"program_exists":        false,
				"program_user_writable": false,
				"plist_writable":        writableByOthers(f, d.scope != "user"),
				"signed":                false,
				"team_id":               "",
			}
			if fi, err := os.Stat(prog); err == nil && filepath.IsAbs(prog) {
				it["program_exists"] = true
				it["program_user_writable"] = d.scope != "user" && writableByOthers(prog, true)
				if fi.Mode().IsRegular() {
					signed, team := codesignInfo(ctx, prog)
					it["signed"], it["team_id"] = signed, team
				}
			} else if !filepath.IsAbs(prog) {
				it["program_exists"] = true // resolved through PATH by launchd
			}
			items = append(items, it)
		}
	}
	return items
}

func inTmp(p string) bool {
	for _, t := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"} {
		if strings.HasPrefix(p, t) {
			return true
		}
	}
	return false
}

// writableByOthers: for root-run items, a file the user (or anyone but
// root) can write means a privilege escalation path.
func writableByOthers(path string, rootOwned bool) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	m := fi.Mode().Perm()
	if m&0o002 != 0 {
		return true
	}
	if !rootOwned {
		return false
	}
	if uid, _, ok := owner(fi); ok && uid != 0 {
		return true
	}
	return m&0o020 != 0 && groupHasUsers(fi)
}

func groupHasUsers(fi os.FileInfo) bool {
	_, gid, ok := owner(fi)
	// gid 0 (wheel) and 80 (admin on macOS) are expected for system files.
	return ok && gid != 0 && gid != 80
}

var teamRe = regexp.MustCompile(`(?m)^TeamIdentifier=(\S+)`)

// codesignInfo reads a binary's signature. codesign prints to stderr and
// never prompts. A file we cannot read (root-only helpers) counts as signed:
// only an explicit "not signed" is reported.
func codesignInfo(ctx context.Context, path string) (signed bool, team string) {
	out, _ := runCombined(ctx, "codesign", "-dv", "--verbose=2", path)
	if strings.Contains(out, "is not signed at all") {
		return false, ""
	}
	if m := teamRe.FindStringSubmatch(out); m != nil && m[1] != "not set" {
		team = m[1]
	}
	return true, team
}

// systemdUserItems lists the user's own systemd units and autostart entries.
func systemdUserItems() []Item {
	var items []Item
	for _, pat := range []string{
		filepath.Join(home(), ".config/systemd/user/*.service"),
		filepath.Join(home(), ".config/autostart/*.desktop"),
	} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			b, err := readSmall(f)
			if err != nil {
				continue
			}
			prog := ""
			for _, line := range strings.Split(string(b), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && (k == "ExecStart" || k == "Exec") {
					if fs := strings.Fields(v); len(fs) > 0 {
						prog = strings.TrimLeft(fs[0], "-@+!")
					}
					break
				}
			}
			_, err = os.Stat(prog)
			items = append(items, Item{
				"kind": "launchd", "scope": "user", "label": filepath.Base(f), "plist": f,
				"program": prog, "apple": false, "run_at_load": true, "inline_script": false,
				"program_in_tmp": inTmp(prog), "program_exists": err == nil || !filepath.IsAbs(prog),
				"program_user_writable": false, "plist_writable": writableByOthers(f, false),
				"signed": true, "team_id": "",
			})
		}
	}
	return items
}
