// Command security-warden checks a work machine for open doors and
// secrets lying around. It only reads; it changes nothing and sends nothing.
package main

import (
	"context"
	"flag"
	"fmt"
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
	cmd := "scan"
	// Double-clicked (Finder, Explorer, a .command file): no terminal to read
	// a report in, so open the web UI instead.
	if len(args) == 0 && !report.IsTerminal(os.Stdout) && os.Getenv("SW_NO_AUTO_SERVE") == "" && launchedByUser() {
		cmd = "serve"
	}
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
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
	fs.Usage = func() { fmt.Fprintln(os.Stderr, i18n.T(i18n.Detect(*lang), "cli.usage")) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Flags may also follow a subcommand argument: "agent status --lang vi".
	var subArgs []string
	if fs.NArg() > 0 {
		subArgs = []string{fs.Arg(0)}
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	l := i18n.Detect(*lang)

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
		fmt.Printf(i18n.T(l, "cli.rules_header")+"\n\n", len(rs))
		for _, r := range rs {
			fmt.Printf("  %-36s %-8s %s\n", r.ID, r.Severity, r.Title.Get(l))
		}
		return 0
	case "scan", "fix":
	case "watch":
		if *interval < 10*time.Second {
			*interval = 10 * time.Second
		}
		return runWatch(l, rs, *interval, *full)
	case "agent":
		return runAgent(l, subArgs)
	case "ignore":
		return runIgnore(l, subArgs)
	case "serve":
		return runServe(l, rs, *listen, *allowLAN, !*noOpen, *tab)
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

	var prog *report.Progress
	if !*asJSON {
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

	items := map[string][]engine.Item{}
	ran := map[string]bool{}
	for _, r := range results {
		items[r.Name] = r.Items
		ran[r.Name] = r.SkipKey == "" && r.Err == nil
	}
	_ = ran
	s := buildScan(rs, results, l)
	findings := s.Findings
	if cmd == "fix" {
		return runFix(l, findings, *yes, *dryRun)
	}
	if *asJSON {
		if err := report.JSON(os.Stdout, s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		report.Text(os.Stdout, s, report.Options{Verbose: *verbose})
	}
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			return 1
		}
	}
	return 0
}

// buildScan evaluates collector results into a report in one language.
func buildScan(rs []*engine.Rule, results []source.Result, l string) report.Scan {
	items := map[string][]engine.Item{}
	ran := map[string]bool{}
	for _, r := range results {
		items[r.Name] = r.Items
		ran[r.Name] = r.SkipKey == "" && r.Err == nil
	}
	all := engine.Evaluate(rs, items, platform(), l)
	checked, passed := engine.Coverage(rs, all, ran, platform())
	entries, _ := ignore.Default().List(time.Now())
	findings, ignored := ignore.Split(all, entries, time.Now())
	score, gain := engine.Score(rs, findings, ran, platform())
	host, _ := os.Hostname()
	return report.Scan{
		Version:  version,
		Lang:     l,
		Platform: platform(),
		Host:     strings.TrimSuffix(host, ".local"),
		Time:     time.Now().Format("2006-01-02 15:04"),
		Score:    score,
		Gain:     gain,
		Checked:  checked,
		Passed:   passed,
		Sources:  report.Statuses(results),
		Findings: findings,
		Ignored:  ignored,
		Root:     os.Geteuid() == 0,
	}
}

// runIgnore lists or clears snoozed findings (snoozing happens in the web
// UI, where each finding has its own button).
func runIgnore(l string, args []string) int {
	t := func(k string) string { return i18n.T(l, k) }
	st := ignore.Default()
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "clear":
		if err := st.Remove(nil); err != nil {
			fmt.Println(err)
			return 2
		}
		fmt.Println(t("ignore.cleared"))
	default:
		es, err := st.List(time.Now())
		if err != nil {
			fmt.Println(err)
			return 2
		}
		if len(es) == 0 {
			fmt.Println(t("ignore.none"))
			return 0
		}
		for _, e := range es {
			until := t("ignore.forever")
			if !e.Until.IsZero() {
				until = e.Until.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("  %-12s %-18s %s\n    %s\n", e.ID, until, e.RuleID, engine.Clean(e.Title))
		}
	}
	return 0
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
