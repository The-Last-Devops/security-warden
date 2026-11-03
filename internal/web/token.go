package web

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/The-Last-Devops/security-warden/internal/appdir"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

// The server's secret is kept in a file only the user can read. The CLI
// uses it to ask the running server for a one-time sign-in ticket, so the
// browser opens signed in without the secret ever appearing in a URL.

func tokenFile() string {
	return appdir.File("server-token")
}

// SaveToken stores the server secret (0600, written exclusively).
func SaveToken(token string) error {
	p := tokenFile()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	_ = os.Remove(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(token); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ForgetToken removes the secret when the server stops.
func ForgetToken() { _ = os.Remove(tokenFile()) }

// SignedInURL asks the server on this machine for a one-time ticket and
// returns a link that signs the browser in (valid 60 s, usable once). It
// falls back to the plain address.
func SignedInURL(port int) string {
	plain := fmt.Sprintf("http://localhost:%d/", port)
	b, err := os.ReadFile(tokenFile())
	if err != nil {
		return plain
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/ticket", port), nil)
	req.Host = fmt.Sprintf("localhost:%d", port)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(b)))
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return plain
	}
	defer resp.Body.Close()
	var v struct {
		Ticket string `json:"ticket"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) != nil || v.Ticket == "" {
		return plain
	}
	return fmt.Sprintf("http://localhost:%d/login?ticket=%s", port, v.Ticket)
}

// ScanNow runs a full scan and returns the findings in the server's language.
func (s *Server) ScanNow(ctx context.Context) []engine.Finding {
	return s.Scanner.Evaluate(s.scan(ctx, true), s.Lang, false).Findings
}
