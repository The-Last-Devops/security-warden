package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTL  = 12 * time.Hour
	maxFailures = 5
	lockout     = 15 * time.Minute
)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS random source never fails in practice
	}
	return hex.EncodeToString(b)
}

type session struct {
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

// auth holds the login token (shown once in the terminal) and the browser
// sessions created from it. Everything lives in memory: restarting serve
// signs everyone out.
type auth struct {
	token    string
	mu       sync.Mutex
	sessions map[string]*session    // key: sha256 of the session id
	failures map[string][]time.Time // per client IP
	now      func() time.Time
	store    string               // file the sessions survive restarts in ("" = memory only)
	tickets  map[string]time.Time // sha256(ticket) -> expiry; one-time sign-in
	cookie   string               // session cookie name, per port (cookies ignore ports)
}

func newAuth() *auth {
	return &auth{token: randomHex(32), sessions: map[string]*session{}, failures: map[string][]time.Time{}, tickets: map[string]time.Time{}, now: time.Now, cookie: "sw_session"}
}

// hashID: only hashes of session ids are kept, in memory and on disk, so
// the sessions file cannot be used to sign in.
func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

// loadSessions restores sessions saved by an earlier run, so restarting
// the server (an upgrade, the background agent) does not sign people out.
func (a *auth) loadSessions(path string) {
	a.store = path
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]*session
	if json.Unmarshal(b, &m) != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, s := range m {
		if s != nil && now.Before(s.Expires) && len(k) == 64 {
			a.sessions[k] = s
		}
	}
}

// saveLocked writes the sessions file; the caller holds a.mu.
func (a *auth) saveLocked() {
	if a.store == "" {
		return
	}
	b, err := json.Marshal(a.sessions)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(a.store), 0o700)
	tmp := a.store + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	if f.Close() == nil && werr == nil {
		_ = os.Rename(tmp, a.store)
	}
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// locked reports whether ip had too many failed logins recently.
func (a *auth) locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.now().Add(-lockout)
	var keep []time.Time
	for _, t := range a.failures[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	a.failures[ip] = keep
	return len(keep) >= maxFailures
}

func (a *auth) fail(ip string) {
	a.mu.Lock()
	a.failures[ip] = append(a.failures[ip], a.now())
	a.mu.Unlock()
}

// login checks the token and returns a new session id.
func (a *auth) login(ip, token string) (string, bool) {
	if a.locked(ip) {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
		a.fail(ip)
		return "", false
	}
	return a.newSession(ip), true
}

// newSession starts a signed-in browser session.
func (a *auth) newSession(ip string) string {
	id := randomHex(32)
	a.mu.Lock()
	a.sessions[hashID(id)] = &session{CSRF: randomHex(16), Expires: a.now().Add(sessionTTL)}
	delete(a.failures, ip)
	a.saveLocked()
	a.mu.Unlock()
	return id
}

func (a *auth) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookie, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second),
	})
}

func (a *auth) session(r *http.Request) (string, *session) {
	c, err := r.Cookie(a.cookie)
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[hashID(c.Value)]
	if !ok {
		return "", nil
	}
	if a.now().After(s.Expires) {
		delete(a.sessions, hashID(c.Value))
		a.saveLocked()
		return "", nil
	}
	return c.Value, s
}

func (a *auth) logout(id string) {
	a.mu.Lock()
	delete(a.sessions, hashID(id))
	a.saveLocked()
	a.mu.Unlock()
}

// newTicket issues a one-time sign-in ticket valid for 60 seconds.
func (a *auth) newTicket() string {
	t := randomHex(24)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, exp := range a.tickets {
		if now.After(exp) {
			delete(a.tickets, k)
		}
	}
	a.tickets[hashID(t)] = now.Add(60 * time.Second)
	return t
}

// useTicket consumes a ticket; it works once.
func (a *auth) useTicket(ip, t string) (string, bool) {
	if t == "" || a.locked(ip) {
		return "", false
	}
	a.mu.Lock()
	exp, ok := a.tickets[hashID(t)]
	delete(a.tickets, hashID(t))
	a.mu.Unlock()
	if !ok || a.now().After(exp) {
		a.fail(ip)
		return "", false
	}
	return a.newSession(ip), true
}

// bearerOK checks the server secret sent by the CLI on this machine.
func (a *auth) bearerOK(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(a.token)) == 1
}
