// Package web serves the security-warden UI and its JSON API. It listens
// on one specific address (loopback or Tailscale by default), requires a
// login token, and protects every request against DNS rebinding and
// cross-site requests.
package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scanner runs a scan and evaluates it in a language; the CLI provides it
// so the web shows exactly what the terminal shows.
type Scanner struct {
	Collect  func(ctx context.Context, done func(name string)) []source.Result
	Evaluate func(results []source.Result, lang string) report.Scan
}

// Server is the web UI.
type Server struct {
	Addr     string // validated ip:port
	Kind     string // loopback, tailscale or lan
	Version  string
	Lang     string
	UI       fs.FS
	Scanner  Scanner
	auth     *auth
	pk       *passkeys
	mu       sync.Mutex
	results  []source.Result
	scanned  time.Time
	scanning sync.Mutex
	prog     progress
}

// progress is what the UI shows while a scan runs.
type progress struct {
	Running bool     `json:"running"`
	Done    []string `json:"done"`
	Total   int      `json:"total"`
}

// Token is the login secret to print in the terminal.
func (s *Server) Token() string { return s.auth.token }

// LoginURL is the link that signs the browser in. On loopback it uses
// localhost, the one host name passkeys accept over plain HTTP.
func (s *Server) LoginURL() string {
	host := s.Addr
	if s.Kind == KindLoopback {
		host = "localhost:" + s.port()
	}
	return "http://" + host + "/login?token=" + s.auth.token
}

// New prepares a server; call Run to start it.
// persist keeps sessions across restarts; tests turn it off.
var persist = true

func New(addr, kind, version, lang string, ui fs.FS, sc Scanner) *Server {
	s := &Server{Addr: addr, Kind: kind, Version: version, Lang: lang, UI: ui, Scanner: sc, auth: newAuth(), pk: newPasskeys()}
	if persist {
		s.auth.loadSessions(filepath.Join(filepath.Dir(s.pk.path), "sessions.json"))
	}
	return s
}

// allowedHosts are the Host header values a request may carry. Anything
// else is refused, which defeats DNS rebinding: a page on evil.example that
// resolves to 127.0.0.1 still sends Host: evil.example.
func (s *Server) allowedHosts() map[string]bool {
	h := map[string]bool{s.Addr: true}
	if s.Kind == KindLoopback {
		_, port, _ := net.SplitHostPort(s.Addr)
		h["localhost:"+port] = true
	}
	return h
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// Handler builds the HTTP handler with every protection applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.withSession(s.handleLogout))
	mux.HandleFunc("GET /api/meta", s.withSession(s.handleMeta))
	mux.HandleFunc("GET /api/scan", s.withSession(s.handleScan))
	mux.HandleFunc("POST /api/scan", s.withSession(s.handleRescan))
	mux.HandleFunc("POST /api/scan/start", s.withSession(s.handleScanStart))
	mux.HandleFunc("GET /api/scan/progress", s.withSession(s.handleProgress))
	mux.HandleFunc("POST /api/fix", s.withSession(s.handleFix))
	mux.HandleFunc("POST /api/undo", s.withSession(s.handleUndo))
	mux.HandleFunc("POST /api/ignore", s.withSession(s.handleIgnore))
	mux.HandleFunc("POST /api/unignore", s.withSession(s.handleUnignore))
	mux.HandleFunc("GET /api/passkey", s.handlePasskeyStatus)
	mux.HandleFunc("POST /api/passkey/register/begin", s.withSession(s.handleRegisterBegin))
	mux.HandleFunc("POST /api/passkey/register/finish", s.withSession(s.handleRegisterFinish))
	mux.HandleFunc("POST /api/passkey/clear", s.withSession(s.handlePasskeyClear))
	mux.HandleFunc("POST /api/passkey/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/passkey/login/finish", s.handleLoginFinish)
	// The app shell holds no data (every API call needs a session), so it
	// is served to anyone; it shows the sign-in screen when signed out.
	mux.Handle("GET /", http.FileServerFS(s.UI))

	allowed := s.allowedHosts()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if !allowed[r.Host] {
			http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Same-origin only: browsers always send Origin on cross-site
			// POSTs, so a page elsewhere cannot trigger a fix.
			if r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				errJSON(w, http.StatusForbidden, "cross-site request refused")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		mux.ServeHTTP(w, r)
	})
}

type sessHandler func(w http.ResponseWriter, r *http.Request, id string, sess *session)

func (s *Server) withSession(h sessHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, sess := s.auth.session(r)
		if sess == nil {
			errJSON(w, http.StatusUnauthorized, "sign in with the link printed by security-warden serve")
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
			errJSON(w, http.StatusForbidden, "missing or wrong CSRF token")
			return
		}
		h(w, r, id, sess)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	id, ok := s.auth.login(ip, r.URL.Query().Get("token"))
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.loginPage(w)
		return
	}
	setSessionCookie(w, id)
	// Drop the token from the address bar and history.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Security Warden</title>
<body style="font:15px system-ui;max-width:34rem;margin:15vh auto;padding:0 16px;color:#19202b">
<h1 style="font-size:20px">Security Warden</h1>
<p>Open the sign-in link printed in the terminal by <code>security-warden serve</code>.</p>
<p>Mở link đăng nhập mà <code>security-warden serve</code> in ra trong terminal.</p></body>`))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, id string, _ *session) {
	s.auth.logout(id)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request, _ string, sess *session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version, "lang": s.Lang, "csrf": sess.CSRF, "listen": s.Addr, "kind": s.Kind,
	})
}

// scan runs collectors at most once at a time.
func (s *Server) scan(ctx context.Context, force bool) []source.Result {
	s.scanning.Lock()
	defer s.scanning.Unlock()
	s.mu.Lock()
	fresh := s.results != nil && time.Since(s.scanned) < 30*time.Second
	s.mu.Unlock()
	if fresh && !force {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.results
	}
	source.ResetCaches()
	s.mu.Lock()
	s.prog = progress{Running: true, Total: len(source.All())}
	s.mu.Unlock()
	res := s.Scanner.Collect(ctx, func(name string) {
		s.mu.Lock()
		s.prog.Done = append(s.prog.Done, name)
		s.mu.Unlock()
	})
	s.mu.Lock()
	s.results, s.scanned = res, time.Now()
	s.prog.Running = false
	s.mu.Unlock()
	return res
}

func langOf(r *http.Request, def string) string {
	switch l := r.URL.Query().Get("lang"); l {
	case "en", "vi":
		return l
	}
	return def
}

// apiFinding adds what the UI needs to offer a fix button.
type apiFinding struct {
	engine.Finding
	Key       string   `json:"key"`
	Category  string   `json:"category"`
	Plan      []string `json:"plan,omitempty"`
	CanFix    bool     `json:"can_fix"`
	NeedsRoot bool     `json:"needs_root"`
	Undoable  bool     `json:"undoable"`
}

func (s *Server) render(results []source.Result, lang string) map[string]any {
	sc := s.Scanner.Evaluate(results, lang)
	out := make([]apiFinding, 0, len(sc.Findings))
	for _, f := range sc.Findings {
		f.Title, f.Explain, f.Fix = tilde(engine.Clean(f.Title)), tilde(engine.Clean(f.Explain)), tilde(engine.Clean(f.Fix))
		af := apiFinding{Finding: f, Key: engine.FindingID(f), Category: report.Category(f.Source)}
		if f.Remedy != nil {
			if a, ok := fix.Get(f.Remedy.Action); ok {
				for _, p := range a.Plan(f.Remedy.Params) {
					af.Plan = append(af.Plan, tilde(engine.Clean(p)))
				}
				af.NeedsRoot, af.Undoable = a.NeedsRoot, a.Undoable
				af.CanFix = !a.NeedsRoot // admin fixes stay in the terminal
			}
		}
		af.Item = nil // raw items stay on the machine; the UI needs only text
		out = append(out, af)
	}
	// What was checked, per source, for the "Checked" view.
	hits := map[string]int{}
	for _, f := range sc.Findings {
		hits[f.Source]++
	}
	type apiSource struct {
		Name     string `json:"name"`
		Label    string `json:"label"`
		Category string `json:"category"`
		State    string `json:"state"` // ok, issues, skipped, error
		Detail   string `json:"detail"`
		Items    int    `json:"items"`
		Issues   int    `json:"issues"`
	}
	var srcs []apiSource
	for _, st := range sc.Sources {
		a := apiSource{Name: st.Name, Label: i18n.T(lang, "source."+st.Name), Category: report.Category(st.Name), Items: st.Items, Issues: hits[st.Name]}
		switch {
		case st.Error != "":
			a.State, a.Detail = "error", st.Error
		case st.Skipped != "":
			a.State, a.Detail = "skipped", i18n.T(lang, st.Skipped)
		case a.Issues > 0:
			a.State = "issues"
		default:
			a.State = "ok"
		}
		srcs = append(srcs, a)
	}
	// Snoozed findings, with when they come back.
	until := map[string]string{}
	if es, err := ignore.Default().List(time.Now()); err == nil {
		for _, e := range es {
			if e.Until.IsZero() {
				until[e.ID] = ""
			} else {
				until[e.ID] = e.Until.Format(time.RFC3339)
			}
		}
	}
	type apiIgnored struct {
		Key      string `json:"key"`
		RuleID   string `json:"rule_id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Category string `json:"category"`
		Until    string `json:"until"`
	}
	ign := []apiIgnored{}
	for _, f := range sc.Ignored {
		id := engine.FindingID(f)
		ign = append(ign, apiIgnored{id, f.RuleID, tilde(engine.Clean(f.Title)), f.Severity, report.Category(f.Source), until[id]})
	}
	sc.Ignored = nil
	return map[string]any{"scan": sc, "findings": out, "ignored": ign, "sources": srcs, "scanned_at": s.scanned.Format(time.RFC3339)}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	writeJSON(w, http.StatusOK, s.render(s.scan(r.Context(), false), langOf(r, s.Lang)))
}

// handleScanStart begins a scan in the background; the UI polls progress
// and then reads the result with GET /api/scan.
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	// Mark running before returning, so the first progress poll cannot
	// see the previous, finished scan.
	s.mu.Lock()
	running := s.prog.Running
	if !running {
		s.prog = progress{Running: true, Total: len(source.All())}
	}
	s.mu.Unlock()
	if !running {
		go s.scan(context.Background(), true)
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	lang := langOf(r, s.Lang)
	s.mu.Lock()
	p := s.prog
	done := append([]string(nil), p.Done...)
	s.mu.Unlock()
	labels := make([]map[string]string, 0, len(done))
	for _, n := range done {
		labels = append(labels, map[string]string{"name": n, "label": i18n.T(lang, "source."+n)})
	}
	pending := []string{}
	seen := map[string]bool{}
	for _, n := range done {
		seen[n] = true
	}
	for _, c := range source.All() {
		if !seen[c.Name] {
			pending = append(pending, i18n.T(lang, "source."+c.Name))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"running": p.Running, "total": p.Total, "done": labels, "pending": pending})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	writeJSON(w, http.StatusOK, s.render(s.scan(r.Context(), true), langOf(r, s.Lang)))
}

func (s *Server) handleFix(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Keys) == 0 || len(req.Keys) > 100 {
		errJSON(w, http.StatusBadRequest, "send {\"keys\": [...]}")
		return
	}
	// Fix only what the latest scan found; the browser names findings by
	// id, it never sends actions or parameters.
	s.mu.Lock()
	results := s.results
	s.mu.Unlock()
	if results == nil {
		errJSON(w, http.StatusConflict, "scan first")
		return
	}
	byKey := map[string]engine.Finding{}
	for _, f := range s.Scanner.Evaluate(results, s.Lang).Findings {
		byKey[engine.FindingID(f)] = f
	}
	batch := fix.NewBatch()
	type result struct {
		Key   string `json:"key"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	var res []result
	for _, k := range req.Keys {
		f, ok := byKey[k]
		if !ok || f.Remedy == nil {
			res = append(res, result{k, false, "not fixable"})
			continue
		}
		a, _ := fix.Get(f.Remedy.Action)
		if a == nil || a.NeedsRoot {
			res = append(res, result{k, false, "needs admin rights: run security-warden fix in a terminal"})
			continue
		}
		if err := fix.Apply(batch, f.RuleID, f.Remedy.Action, f.Remedy.Params); err != nil {
			res = append(res, result{k, false, err.Error()})
			continue
		}
		res = append(res, result{k, true, ""})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": res})
}

func (s *Server) handleIgnore(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		Keys []string `json:"keys"`
		Days int      `json:"days"` // 0 = for good (critical: 30 days at most)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Keys) == 0 || len(req.Keys) > 500 || req.Days < 0 || req.Days > 365 {
		errJSON(w, http.StatusBadRequest, "send {\"keys\": [...], \"days\": 0..365}")
		return
	}
	s.mu.Lock()
	results := s.results
	s.mu.Unlock()
	if results == nil {
		errJSON(w, http.StatusConflict, "scan first")
		return
	}
	want := map[string]bool{}
	for _, k := range req.Keys {
		want[k] = true
	}
	var pick []engine.Finding
	for _, f := range s.Scanner.Evaluate(results, s.Lang).Findings {
		if want[engine.FindingID(f)] {
			pick = append(pick, f)
		}
	}
	if err := ignore.Default().Add(pick, time.Duration(req.Days)*24*time.Hour, time.Now()); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ignored": len(pick)})
}

func (s *Server) handleUnignore(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Keys) == 0 || len(req.Keys) > 500 {
		errJSON(w, http.StatusBadRequest, "send {\"keys\": [...]}")
		return
	}
	if err := ignore.Default().Remove(req.Keys); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	done, err := fix.UndoLast()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"undone": len(done), "error": msg})
}

// tilde shows the home folder as ~, like the terminal report.
func tilde(s string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return strings.ReplaceAll(s, h, "~")
	}
	return s
}

// Run serves on ln until ctx ends.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Addr: s.Addr, Handler: s.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hasUI reports whether the embedded UI was built.
func HasUI(ui fs.FS) bool {
	_, err := fs.Stat(ui, "index.html")
	return err == nil
}
