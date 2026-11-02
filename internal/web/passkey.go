package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/The-Last-Devops/security-warden/internal/appdir"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkeys: after signing in once with the token link, a browser can
// register a passkey (Touch ID, Windows Hello, a security key) and sign in
// with it later. WebAuthn needs a domain, not an IP, so this works on
// http://localhost (and on an HTTPS MagicDNS name in the future).
//
// Only public keys are stored, in passkeys.json (0600) in the config folder.

type pkUser struct {
	ID    []byte                `json:"id"`
	Creds []webauthn.Credential `json:"credentials"`
}

func (u *pkUser) WebAuthnID() []byte                         { return u.ID }
func (u *pkUser) WebAuthnName() string                       { return "warden" }
func (u *pkUser) WebAuthnDisplayName() string                { return "Security Warden" }
func (u *pkUser) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

type passkeys struct {
	path    string
	mu      sync.Mutex                 // guards the file
	pmu     sync.Mutex                 // guards pending
	pending map[string]pendingCeremony // ceremony id -> state, short-lived
}

type pendingCeremony struct {
	data    *webauthn.SessionData
	expires time.Time
}

func newPasskeys() *passkeys {
	return &passkeys{path: appdir.File("passkeys.json"), pending: map[string]pendingCeremony{}}
}

func (p *passkeys) load() (*pkUser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		// Create the user id once and keep it: registration begin and finish
		// must see the same id.
		u := &pkUser{ID: []byte(randomHex(16))}
		if err := p.saveLocked(u); err != nil {
			return nil, err
		}
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	var u pkUser
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, err
	}
	if len(u.ID) == 0 {
		u.ID = []byte(randomHex(16))
	}
	return &u, nil
}

func (p *passkeys) save(u *pkUser) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveLocked(u)
}

func (p *passkeys) saveLocked(u *pkUser) error {
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

func (p *passkeys) put(d *webauthn.SessionData) string {
	id := randomHex(16)
	p.pmu.Lock()
	defer p.pmu.Unlock()
	now := time.Now()
	for k, v := range p.pending {
		if now.After(v.expires) {
			delete(p.pending, k)
		}
	}
	p.pending[id] = pendingCeremony{d, now.Add(2 * time.Minute)}
	return id
}

func (p *passkeys) take(id string) (*webauthn.SessionData, bool) {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	c, ok := p.pending[id]
	delete(p.pending, id)
	if !ok || time.Now().After(c.expires) {
		return nil, false
	}
	return c.data, true
}

// webauthnFor builds the relying party for the host the browser used. Only
// a domain works: localhost for loopback.
func (s *Server) webauthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || net.ParseIP(host) != nil {
		return nil, errors.New("passkeys need a name, not an IP: open http://localhost:" + s.port())
	}
	return webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "Security Warden",
		RPOrigins:     []string{"http://" + r.Host, "https://" + r.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
	})
}

func (s *Server) port() string {
	_, p, _ := net.SplitHostPort(s.Addr)
	return p
}

const pkCookie = "sw_pk"

func (s *Server) handlePasskeyStatus(w http.ResponseWriter, r *http.Request) {
	u, err := s.pk.load()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot read passkeys")
		return
	}
	host, _, _ := net.SplitHostPort(r.Host)
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(u.Creds),
		"available": net.ParseIP(host) == nil,
		"localhost": "http://localhost:" + s.port(),
	})
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	wa, err := s.webauthnFor(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.pk.load()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot read passkeys")
		return
	}
	opts, data, err := wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Creds).CredentialDescriptors()))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	setCeremony(w, s.pk.put(data))
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	wa, err := s.webauthnFor(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	data, ok := s.takeCeremony(r)
	if !ok {
		errJSON(w, http.StatusBadRequest, "registration expired, try again")
		return
	}
	u, err := s.pk.load()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot read passkeys")
		return
	}
	cred, err := wa.FinishRegistration(u, *data, r)
	if err != nil {
		log.Printf("passkey registration: %s", webauthnErr(err))
		errJSON(w, http.StatusBadRequest, "passkey was not accepted: "+webauthnErr(err))
		return
	}
	u.Creds = append(u.Creds, *cred)
	if err := s.pk.save(u); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot save passkey")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(u.Creds)})
}

func (s *Server) handlePasskeyClear(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	u, err := s.pk.load()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot read passkeys")
		return
	}
	u.Creds = nil
	if err := s.pk.save(u); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot save passkeys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.auth.locked(clientIP(r)) {
		errJSON(w, http.StatusTooManyRequests, "too many attempts, wait 15 minutes")
		return
	}
	wa, err := s.webauthnFor(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.pk.load()
	if err != nil || len(u.Creds) == 0 {
		errJSON(w, http.StatusNotFound, "no passkey yet: sign in with the link from the terminal, then add one")
		return
	}
	opts, data, err := wa.BeginLogin(u)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	setCeremony(w, s.pk.put(data))
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.locked(ip) {
		errJSON(w, http.StatusTooManyRequests, "too many attempts, wait 15 minutes")
		return
	}
	wa, err := s.webauthnFor(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	data, ok := s.takeCeremony(r)
	u, lerr := s.pk.load()
	if !ok || lerr != nil {
		s.auth.fail(ip)
		errJSON(w, http.StatusBadRequest, "sign-in expired, try again")
		return
	}
	cred, err := wa.FinishLogin(u, *data, r)
	if err != nil {
		log.Printf("passkey sign-in: %s", webauthnErr(err))
		s.auth.fail(ip)
		errJSON(w, http.StatusUnauthorized, "passkey was not accepted")
		return
	}
	// Keep the signature counter current (clone detection).
	for i := range u.Creds {
		if bytes.Equal(u.Creds[i].ID, cred.ID) {
			u.Creds[i].Authenticator.SignCount = cred.Authenticator.SignCount
		}
	}
	_ = s.pk.save(u)
	id := s.auth.newSession(ip)
	setSessionCookie(w, id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webauthnErr gives the library's detail (no secrets: it describes which
// check failed).
func webauthnErr(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return pe.Details + ": " + pe.DevInfo
	}
	return err.Error()
}

func setCeremony(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: pkCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 120})
}

func (s *Server) takeCeremony(r *http.Request) (*webauthn.SessionData, bool) {
	c, err := r.Cookie(pkCookie)
	if err != nil {
		return nil, false
	}
	return s.pk.take(c.Value)
}
