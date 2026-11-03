package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/mcp"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/web"
)

// wantsHelp reports whether args ask for help (-h, -help, --help).
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

// runMCP serves the MCP tools on stdin/stdout until stdin closes. Only
// protocol messages go to stdout; everything else goes to stderr.
func runMCP(l string, rs []*engine.Rule, allowChanges bool) int {
	// stdin carries the protocol: commands run by fixes must never read it,
	// and their output must never reach stdout.
	fix.Runner = func(argv ...string) error {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		return cmd.Run()
	}
	if report.IsTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, i18n.T(l, "mcp.terminal"))
	}
	if allowChanges {
		fmt.Fprintln(os.Stderr, i18n.T(l, "mcp.ready_changes"))
	} else {
		fmt.Fprintln(os.Stderr, i18n.T(l, "mcp.ready"))
	}
	srv := mcp.New(mcp.Config{
		Version: version,
		Rules:   rs,
		Collect: func(ctx context.Context) []source.Result {
			return source.Run(ctx, source.All(), func(string) {})
		},
		Evaluate:       func(results []source.Result, lang string) report.Scan { return buildScan(rs, results, lang) },
		AllowChanges:   allowChanges,
		ServiceRunning: func() bool { return web.RunningHere(web.DefaultPort) },
		Log:            os.Stderr,
	})
	if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}
