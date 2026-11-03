package web

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/appdir"
)

// Settings the terminal can change too (security-warden passkey, logout).
// While the server runs it holds passkeys and sessions, so the CLI asks it
// over loopback with the server secret, the same way as /api/ticket. When
// no server runs, the CLI changes the files itself.

// PasskeyInfo describes one registered passkey (never the key itself).
type PasskeyInfo struct {
	Added      time.Time `json:"added"` // zero: registered before this was recorded
	Transports []string  `json:"transports,omitempty"`
}

// errNotRunning: no server answers on this machine, so the files are free.
var errNotRunning = errors.New("not running")

// localOnly allows a handler to the CLI on this machine only: a loopback
// client sending the server secret from the 0600 token file.
func (s *Server) localOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(clientIP(r))
		if ip == nil || !ip.IsLoopback() || !s.auth.bearerOK(r) {
			s.auth.fail(clientIP(r))
			errJSON(w, http.StatusUnauthorized, "not allowed")
			return
		}
		h(w, r)
	}
}

func passkeyInfos(u *pkUser) []PasskeyInfo {
	out := make([]PasskeyInfo, 0, len(u.Creds))
	for _, c := range u.Creds {
		pi := PasskeyInfo{Added: u.Added[hex.EncodeToString(c.ID)]}
		for _, t := range c.Transport {
			pi.Transports = append(pi.Transports, string(t))
		}
		out = append(out, pi)
	}
	return out
}

func (s *Server) handleLocalPasskeys(w http.ResponseWriter, r *http.Request) {
	u, err := s.pk.load()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot read passkeys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": passkeyInfos(u)})
}

func (s *Server) handleLocalPasskeysClear(w http.ResponseWriter, r *http.Request) {
	n, err := clearPasskeys(s.pk)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot save passkeys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"removed": n})
}

func (s *Server) handleLocalLogout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"ended": s.auth.logoutAll()})
}

// logoutAll ends every browser session and returns how many there were.
func (a *auth) logoutAll() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	now := a.now()
	for _, s := range a.sessions {
		if now.Before(s.Expires) {
			n++
		}
	}
	a.sessions = map[string]*session{}
	a.saveLocked()
	return n
}

func clearPasskeys(p *passkeys) (int, error) {
	u, err := p.load()
	if err != nil {
		return 0, err
	}
	n := len(u.Creds)
	u.Creds, u.Added = nil, nil
	return n, p.save(u)
}

// localCall sends one request to the server on the loopback port.
func localCall(port int, method, path string, out any) error {
	tok, terr := os.ReadFile(tokenFile())
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	req.Host = fmt.Sprintf("localhost:%d", port)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		if !RunningHere(port) {
			return errNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return errors.New("the running Security Warden is an older version: restart it (security-warden start) and try again")
	case terr != nil:
		return errors.New("Security Warden is running but its secret file is missing: restart it (security-warden start) and try again")
	default:
		return fmt.Errorf("Security Warden refused the request (%s)", resp.Status)
	}
}

// LocalPasskeys lists the passkeys that can sign in to the web UI.
func LocalPasskeys(port int) ([]PasskeyInfo, error) {
	var v struct {
		Passkeys []PasskeyInfo `json:"passkeys"`
	}
	err := localCall(port, "GET", "/api/local/passkeys", &v)
	if errors.Is(err, errNotRunning) {
		b, rerr := os.ReadFile(newPasskeys().path)
		if errors.Is(rerr, os.ErrNotExist) {
			return nil, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		var u pkUser
		if err := json.Unmarshal(b, &u); err != nil {
			return nil, err
		}
		return passkeyInfos(&u), nil
	}
	return v.Passkeys, err
}

// LocalClearPasskeys removes every passkey and returns how many there were.
func LocalClearPasskeys(port int) (int, error) {
	var v struct {
		Removed int `json:"removed"`
	}
	err := localCall(port, "POST", "/api/local/passkeys/clear", &v)
	if errors.Is(err, errNotRunning) {
		if _, serr := os.Stat(newPasskeys().path); errors.Is(serr, os.ErrNotExist) {
			return 0, nil
		}
		return clearPasskeys(newPasskeys())
	}
	return v.Removed, err
}

// LocalLogout ends every web session and returns how many were open.
func LocalLogout(port int) (int, error) {
	var v struct {
		Ended int `json:"ended"`
	}
	err := localCall(port, "POST", "/api/local/logout", &v)
	if errors.Is(err, errNotRunning) {
		a := newAuth()
		a.loadSessions(appdir.File("sessions.json"))
		if len(a.sessions) == 0 {
			return 0, nil
		}
		return a.logoutAll(), nil
	}
	return v.Ended, err
}
