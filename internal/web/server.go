// Package web serves the security-warden UI and its JSON API. It listens
// on one specific address (loopback or Tailscale by default), requires a
// login token, and protects every request against DNS rebinding and
// cross-site requests.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scanner runs a scan and evaluates it in a language; the CLI provides it
// so the web shows exactly what the terminal shows.
type Scanner struct {
	Collect  func(ctx context.Context) []source.Result
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
	mu       sync.Mutex
	results  []source.Result
	scanned  time.Time
	scanning sync.Mutex
}

// Token is the login secret to print in the terminal.
func (s *Server) Token() string { return s.auth.token }

// LoginURL is the link that signs the browser in.
func (s *Server) LoginURL() string { return "http://" + s.Addr + "/login?token=" + s.auth.token }

// New prepares a server; call Run to start it.
func New(addr, kind, version, lang string, ui fs.FS, sc Scanner) *Server {
	return &Server{Addr: addr, Kind: kind, Version: version, Lang: lang, UI: ui, Scanner: sc, auth: newAuth()}
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

func (s *Server) origin() string { return "http://" + s.Addr }

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
	mux.HandleFunc("POST /api/fix", s.withSession(s.handleFix))
	mux.HandleFunc("POST /api/undo", s.withSession(s.handleUndo))
	static := http.FileServerFS(s.UI)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if _, sess := s.auth.session(r); sess == nil {
			s.loginPage(w)
			return
		}
		static.ServeHTTP(w, r)
	})

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
			if r.Header.Get("Origin") != s.origin() || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
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
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
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
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second),
	})
	// Drop the token from the address bar and history.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>security-warden</title>
<body style="font:15px system-ui;max-width:34rem;margin:15vh auto;padding:0 16px;color:#19202b">
<h1 style="font-size:20px">security-warden</h1>
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
		"version": s.Version, "lang": s.Lang, "csrf": sess.csrf, "listen": s.Addr, "kind": s.Kind,
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
	res := s.Scanner.Collect(ctx)
	s.mu.Lock()
	s.results, s.scanned = res, time.Now()
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
		f.Title, f.Explain, f.Fix = engine.Clean(f.Title), engine.Clean(f.Explain), engine.Clean(f.Fix)
		af := apiFinding{Finding: f, Key: FindingID(f), Category: report.Category(f.Source)}
		if f.Remedy != nil {
			if a, ok := fix.Get(f.Remedy.Action); ok {
				af.Plan = a.Plan(f.Remedy.Params)
				af.NeedsRoot, af.Undoable = a.NeedsRoot, a.Undoable
				af.CanFix = !a.NeedsRoot // admin fixes stay in the terminal
			}
		}
		af.Item = nil // raw items stay on the machine; the UI needs only text
		out = append(out, af)
	}
	return map[string]any{"scan": sc, "findings": out, "scanned_at": s.scanned.Format(time.RFC3339)}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	writeJSON(w, http.StatusOK, s.render(s.scan(r.Context(), false), langOf(r, s.Lang)))
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
		byKey[FindingID(f)] = f
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

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	done, err := fix.UndoLast()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"undone": len(done), "error": msg})
}

// FindingID names a finding by its rule and the facts it matched, so the
// id is the same in every language and across rescans.
func FindingID(f engine.Finding) string {
	b, _ := json.Marshal(f.Item) // map keys are sorted: stable
	h := sha256.Sum256(append([]byte(f.RuleID+"\x00"), b...))
	return hex.EncodeToString(h[:12])
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr: s.Addr, Handler: s.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
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
