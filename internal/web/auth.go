package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	cookieName  = "sw_session"
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
	csrf    string
	expires time.Time
}

// auth holds the login token (shown once in the terminal) and the browser
// sessions created from it. Everything lives in memory: restarting serve
// signs everyone out.
type auth struct {
	token    string
	mu       sync.Mutex
	sessions map[string]*session
	failures map[string][]time.Time // per client IP
	now      func() time.Time
}

func newAuth() *auth {
	return &auth{token: randomHex(32), sessions: map[string]*session{}, failures: map[string][]time.Time{}, now: time.Now}
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
	id := randomHex(32)
	a.mu.Lock()
	a.sessions[id] = &session{csrf: randomHex(16), expires: a.now().Add(sessionTTL)}
	delete(a.failures, ip)
	a.mu.Unlock()
	return id, true
}

func (a *auth) session(r *http.Request) (string, *session) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok {
		return "", nil
	}
	if a.now().After(s.expires) {
		delete(a.sessions, c.Value)
		return "", nil
	}
	return c.Value, s
}

func (a *auth) logout(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}
