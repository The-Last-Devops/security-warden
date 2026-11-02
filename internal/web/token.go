package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

// The login link is kept in a file only the user can read, so a background
// server never prints its secret to a log, and "security-warden open" can
// sign the browser in.

func loginFile() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "security-warden", "login-url")
}

// SaveLoginURL stores the current login link (0600, written exclusively).
func SaveLoginURL(url string) error {
	p := loginFile()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	_ = os.Remove(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(url); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoginURL reads the stored login link, or "" when none.
func StoredLoginURL() string {
	b, err := os.ReadFile(loginFile())
	if err != nil {
		return ""
	}
	u := strings.TrimSpace(string(b))
	if !strings.HasPrefix(u, "http://localhost:") && !strings.HasPrefix(u, "http://127.0.0.1:") && !strings.HasPrefix(u, "http://100.") {
		return "" // only links this tool writes
	}
	return u
}

// ForgetLoginURL removes the stored link when the server stops.
func ForgetLoginURL() { _ = os.Remove(loginFile()) }

// ScanNow runs a full scan and returns the findings in the server's language.
func (s *Server) ScanNow(ctx context.Context) []engine.Finding {
	return s.Scanner.Evaluate(s.scan(ctx, true), s.Lang).Findings
}
