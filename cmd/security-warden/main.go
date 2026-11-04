// Command security-warden checks a work machine for open doors and
// secrets lying around. It only reads; it changes nothing and sends nothing
// about the machine (the only download is public OSV vulnerability data).
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/The-Last-Devops/security-warden/internal/appdir"
	"github.com/The-Last-Devops/security-warden/internal/update"
	"github.com/The-Last-Devops/security-warden/internal/web"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/rules"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Development builds keep their own port, data folder and service, so
	// they never collide with an installed release.
	if version == "dev" {
		appdir.Dev = true
		web.DefaultPort = appdir.Port()
	}
	source.LogDir, source.Version = appdir.File("logs"), version
	cmd := "scan"
	// Double-clicked (Finder, Explorer, a .command file): no terminal to read
	// a report in, so open the web UI instead.
	if len(args) == 0 && !report.IsTerminal(os.Stdout) && os.Getenv("SW_NO_AUTO_SERVE") == "" && launchedByUser() {
		cmd = "open"
	}
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	if cmd == "mcp" && wantsHelp(args) {
		fmt.Println(i18n.T(i18n.Detect(langFlag(args)), "mcp.usage"))
		return 0
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	lang := fs.String("lang", "", "language: "+fmt.Sprint(i18n.Supported))
	asJSON := fs.Bool("json", false, "print JSON")
	verbose := fs.Bool("verbose", false, "show every detail")
	yes := fs.Bool("yes", false, "fix: apply every fix without asking")
	dryRun := fs.Bool("dry-run", false, "fix: only show what would change")
	undo := fs.Bool("undo", false, "fix: revert the last batch of fixes")
	interval := fs.Duration("interval", time.Minute, "watch: time between quick scans")
	full := fs.Duration("full", 30*time.Minute, "watch: time between full scans")
	listen := fs.String("listen", "", "serve: one IP:PORT of this machine (loopback or Tailscale); default 127.0.0.1:7348")
	allowLAN := fs.Bool("allow-lan", false, "serve: allow a LAN address (never 0.0.0.0)")
	noOpen := fs.Bool("no-open", false, "serve: do not open the browser")
	tab := fs.Bool("tab", false, "serve: open in a browser tab instead of an app window")
	background := fs.Bool("background", false, "serve: run as a background service (no browser, scan and notify)")
	popup := fs.String("popup", "high", "serve --background: open the window for new problems at this level or worse: critical|high|medium|off")
	days := fs.Int("days", 7, "ignore add: hide for this many days (1 to 30)")
	scope := fs.String("scope", "", "scan: only machine or code")
	category := fs.String("category", "", "scan: only one category")
	byRepo := fs.Bool("by-repo", false, "scan: group code findings per repository")
	safe := fs.Bool("safe", false, "scan: list what already passes")
	allowChanges := fs.Bool("allow-changes", false, "mcp: also offer the tools that change things (apply_fix, undo_fix, hide, restore)")
	experimental := fs.Bool("experimental", false, "scan, fix: also run experimental rules (new, not yet reviewed); they never change the score")
	ruleSource := fs.String("source", "", "rules new: the source the rule reads")
	severity := fs.String("severity", "medium", "rules new: critical|high|medium|low")
	platforms := fs.String("platforms", "", "rules new: comma-separated platforms (default: where the source runs)")
	dir := fs.String("dir", "rules", "rules new: folder to write the rule in")
	strict := fs.Bool("strict", false, "rules check: warnings fail too")
	isNew := fs.Bool("new", false, "rules check: the files are new rules (must start experimental)")
	idea := fs.String("idea", "", "feedback: suggest a new check, in your words")
	bug := fs.String("bug", "", "feedback: report a bug, in your words (the scan log is attached)")
	openLink := fs.Bool("open", false, "feedback: open the link in the browser")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, i18n.T(i18n.Detect(*lang), "cli.usage")) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Flags may also follow subcommand arguments: "ignore add x --days 1".
	var subArgs []string
	for fs.NArg() > 0 {
		subArgs = append(subArgs, fs.Arg(0))
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	l := i18n.Detect(*lang)
	opts := report.Options{Verbose: *verbose, Scope: *scope, Category: *category, ByRepo: *byRepo, Safe: *safe}
	if err := checkFilters(l, opts); err != "" {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var names []string
	for _, c := range source.All() {
		names = append(names, c.Name)
	}
	rs, err := engine.Load(rules.FS, names, fix.CheckRemedy)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	switch cmd {
	case "version":
		fmt.Println(version)
		return 0
	case "rules":
		return runRules(l, rs, subArgs, rulesOpts{JSON: *asJSON, Source: *ruleSource, Severity: *severity,
			Platforms: *platforms, Dir: *dir, Strict: *strict, New: *isNew})
	case "scan", "fix":
	case "watch":
		if *interval < 10*time.Second {
			*interval = 10 * time.Second
		}
		return runWatch(l, rs, *interval, *full)
	case "update":
		if len(subArgs) > 0 && (subArgs[0] == "on" || subArgs[0] == "off") {
			st := update.Load()
			st.Auto = subArgs[0] == "on"
			_ = update.Save(st)
			fmt.Println(i18n.T(l, "update.auto_"+subArgs[0]))
			return 0
		}
		return runUpdate(l)
	case "vulndb":
		return runVulnDB(l, subArgs)
	case "start":
		return runStart(l)
	case "stop":
		return runStop(l)
	case "status":
		return runStatus(l)
	case "agent": // older name for start/stop
		if len(subArgs) > 0 && subArgs[0] == "install" {
			return runStart(l)
		}
		if len(subArgs) > 0 && subArgs[0] == "uninstall" {
			return runStop(l)
		}
		return runStatus(l)
	case "ignore":
		return runIgnore(l, rs, subArgs, *days)
	case "feedback", "report":
		ideaSet, bugSet := false, false
		fs.Visit(func(f *flag.Flag) { ideaSet = ideaSet || f.Name == "idea"; bugSet = bugSet || f.Name == "bug" })
		if bugSet {
			return runBugReport(os.Stdout, l, *bug, *openLink)
		}
		return runFeedback(os.Stdout, l, rs, subArgs, *idea, ideaSet, *openLink, func() []engine.Finding {
			s := scanNow(rs, "en", true, true)
			return append(s.Findings, s.Ignored...)
		})
	case "passkey", "passkeys":
		return runPasskey(l, subArgs, *yes)
	case "logout":
		return runLogout(l)
	case "logs", "log":
		return runLogs(l, subArgs)
	case "serve":
		return runServe(l, rs, *listen, *allowLAN, !*noOpen, *tab, *background, *popup)
	case "open":
		return runOpen(l, rs)
	case "app-url":
		return runAppURL(l)
	case "app":
		return runApp(l, subArgs)
	case "mcp":
		return runMCP(l, rs, *allowChanges)
	case "help":
		fs.Usage()
		return 0
	default:
		fs.Usage()
		return 2
	}

	if cmd == "fix" && *undo {
		return runUndo(l)
	}

	s := scanNow(rs, l, !*asJSON, *experimental)
	findings := s.Findings
	if cmd == "fix" {
		return runFix(l, findings, *yes, *dryRun)
	}
	if cmd == "scan" {
		findings = opts.Filter(findings)
	}
	if *asJSON {
		s.Findings, s.Ignored = opts.Filter(s.Findings), opts.Filter(s.Ignored)
		if err := report.JSON(os.Stdout, s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		opts.Rules = rs
		report.Text(os.Stdout, s, opts)
	}
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			return 1
		}
	}
	return 0
}

// langFlag finds --lang in args before they are parsed.
func langFlag(args []string) string {
	for i, a := range args {
		for _, p := range []string{"--lang=", "-lang="} {
			if strings.HasPrefix(a, p) {
				return strings.TrimPrefix(a, p)
			}
		}
		if (a == "--lang" || a == "-lang") && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// scanNow runs every collector (with a progress line on stderr when
// progress is set) and evaluates the results.
func scanNow(rs []*engine.Rule, l string, progress, experimental bool) report.Scan {
	var names []string
	for _, c := range source.All() {
		names = append(names, c.Name)
	}
	var prog *report.Progress
	if progress {
		prog = report.StartProgress(os.Stderr, l, names)
	}
	results := source.Run(context.Background(), source.All(), func(n string) {
		if prog != nil {
			prog.Done(n)
		}
	})
	if prog != nil {
		prog.Stop()
	}
	return buildScan(rs, results, l, experimental)
}

// checkFilters validates --scope and --category; "" when they are fine.
func checkFilters(l string, o report.Options) string {
	if o.Scope != "" && o.Scope != "machine" && o.Scope != "code" {
		return fmt.Sprintf(i18n.T(l, "cli.bad_scope"), o.Scope)
	}
	if o.Category != "" {
		for _, c := range report.Categories {
			if c == o.Category {
				return ""
			}
		}
		return fmt.Sprintf(i18n.T(l, "cli.bad_category"), o.Category, strings.Join(report.Categories, ", "))
	}
	return ""
}

// buildScan evaluates collector results into a report in one language.
// experimental also runs the rules still waiting for review.
func buildScan(rs []*engine.Rule, results []source.Result, l string, experimental bool) report.Scan {
	items := map[string][]engine.Item{}
	ran := map[string]bool{}
	for _, r := range results {
		items[r.Name] = r.Items
		ran[r.Name] = r.SkipKey == "" && r.Err == nil
	}
	all := engine.EvaluateWith(rs, items, platform(), l, experimental)
	checked, passed := engine.CoverageWith(rs, all, ran, platform(), experimental)
	entries, _ := ignore.Default().List(time.Now())
	findings, ignored := ignore.Split(all, entries, time.Now())
	for i := range findings {
		findings[i].Key = engine.FindingID(findings[i])
	}
	for i := range ignored {
		ignored[i].Key = engine.FindingID(ignored[i])
	}
	score, gain := engine.Score(rs, findings, ran, platform())
	scoped := func(scope string) int {
		var srs []*engine.Rule
		for _, r := range rs {
			if report.Scope(r.Source) == scope {
				srs = append(srs, r)
			}
		}
		var sfs []engine.Finding
		for _, f := range findings {
			if report.Scope(f.Source) == scope {
				sfs = append(sfs, f)
			}
		}
		s, _ := engine.Score(srs, sfs, ran, platform())
		return s
	}
	host, _ := os.Hostname()
	return report.Scan{
		Version:      version,
		Lang:         l,
		Platform:     platform(),
		Host:         strings.TrimSuffix(host, ".local"),
		Time:         time.Now().Format("2006-01-02 15:04"),
		Score:        score,
		ScoreMachine: scoped("machine"),
		ScoreCode:    scoped("code"),
		Gain:         gain,
		Checked:      checked,
		Passed:       passed,
		Sources:      report.Statuses(results),
		Findings:     findings,
		Ignored:      ignored,
		Root:         os.Geteuid() == 0,
	}
}

// launchedByUser tells a double-click apart from a pipe or a script: the
// process has a desktop session and stdin is not a pipe or file.
func launchedByUser() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	piped := fi.Mode()&os.ModeNamedPipe != 0 || fi.Mode().IsRegular()
	if piped {
		return false
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
}
