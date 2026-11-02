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
	"github.com/The-Last-Devops/security-warden/internal/i18n"
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
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	lang := fs.String("lang", "", "language: "+fmt.Sprint(i18n.Supported))
	asJSON := fs.Bool("json", false, "print JSON")
	verbose := fs.Bool("verbose", false, "show every detail")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, i18n.T(i18n.Detect(*lang), "cli.usage")) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	l := i18n.Detect(*lang)

	var names []string
	for _, c := range source.All() {
		names = append(names, c.Name)
	}
	rs, err := engine.Load(rules.FS, names)
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
	case "scan":
	case "help":
		fs.Usage()
		return 0
	default:
		fs.Usage()
		return 2
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
	findings := engine.Evaluate(rs, items, platform(), l)
	checked, passed := engine.Coverage(rs, findings, ran, platform())
	host, _ := os.Hostname()
	s := report.Scan{
		Version:  version,
		Lang:     l,
		Platform: platform(),
		Host:     strings.TrimSuffix(host, ".local"),
		Time:     time.Now().Format("2006-01-02 15:04"),
		Score:    engine.Score(findings),
		Checked:  checked,
		Passed:   passed,
		Sources:  report.Statuses(results),
		Findings: findings,
		Root:     os.Geteuid() == 0,
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
