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
	"github.com/The-Last-Devops/security-warden/internal/update"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/feedback"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/rulecheck"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scanner runs a scan and evaluates it in a language; the CLI provides it
// so the web shows exactly what the terminal shows.
type Scanner struct {
	Rules    []*engine.Rule
	Collect  func(ctx context.Context, done func(name string)) []source.Result
	Evaluate func(results []source.Result, lang string, experimental bool) report.Scan
}

// Server is the web UI.
type Server struct {
	Addr    string // validated ip:port
	Kind    string // loopback, tailscale or lan
	Version string
	Lang    string
	UI      fs.FS
	Scanner Scanner
	// Watching: the background service rescans and notifies on its own.
	Watching bool
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
	// Browsers share cookies between ports of one host, so each instance
	// (release on 7348, development on 7349) needs its own cookie names.
	s.auth.cookie = "sw_session_" + s.port()
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
	mux.HandleFunc("POST /api/ticket", s.handleTicket)
	mux.HandleFunc("POST /api/logout", s.withSession(s.handleLogout))
	mux.HandleFunc("GET /api/local/passkeys", s.localOnly(s.handleLocalPasskeys))
	mux.HandleFunc("POST /api/local/passkeys/clear", s.localOnly(s.handleLocalPasskeysClear))
	mux.HandleFunc("POST /api/local/logout", s.localOnly(s.handleLocalLogout))
	mux.HandleFunc("GET /api/meta", s.withSession(s.handleMeta))
	mux.HandleFunc("GET /api/scan", s.withSession(s.handleScan))
	mux.HandleFunc("GET /api/sources", s.withSession(s.handleSources))
	mux.HandleFunc("GET /api/logs", s.withSession(s.handleLogs))
	mux.HandleFunc("POST /api/scan", s.withSession(s.handleRescan))
	mux.HandleFunc("POST /api/scan/start", s.withSession(s.handleScanStart))
	mux.HandleFunc("GET /api/scan/progress", s.withSession(s.handleProgress))
	mux.HandleFunc("POST /api/fix", s.withSession(s.handleFix))
	mux.HandleFunc("POST /api/undo", s.withSession(s.handleUndo))
	mux.HandleFunc("POST /api/ignore", s.withSession(s.handleIgnore))
	mux.HandleFunc("GET /api/update", s.withSession(s.handleUpdateStatus))
	mux.HandleFunc("POST /api/update/auto", s.withSession(s.handleUpdateAuto))
	mux.HandleFunc("POST /api/app/auto", s.withSession(s.handleAppAuto))
	mux.HandleFunc("POST /api/app/install", s.withSession(s.handleAppInstall))
	mux.HandleFunc("POST /api/unignore", s.withSession(s.handleUnignore))
	mux.HandleFunc("GET /api/feedback", s.withSession(s.handleFeedback))
	mux.HandleFunc("POST /api/feedback/idea", s.withSession(s.handleFeedbackIdea))
	mux.HandleFunc("POST /api/feedback/bug", s.withSession(s.handleFeedbackBug))
	mux.HandleFunc("GET /api/passkey", s.handlePasskeyStatus)
	mux.HandleFunc("POST /api/passkey/register/begin", s.withSession(s.handleRegisterBegin))
	mux.HandleFunc("POST /api/passkey/register/finish", s.withSession(s.handleRegisterFinish))
	mux.HandleFunc("POST /api/passkey/clear", s.withSession(s.handlePasskeyClear))
	mux.HandleFunc("POST /api/passkey/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/passkey/login/finish", s.handleLoginFinish)
	// The app shell holds no data (every API call needs a session), so it
	// is served to anyone; it shows the sign-in screen when signed out.
	files := http.FileServerFS(s.UI)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Hashed assets never change; the page itself must always be
		// re-checked, or a browser keeps showing an old build after upgrades.
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})

	allowed := s.allowedHosts()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if !allowed[r.Host] {
			http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/api/ticket" && !strings.HasPrefix(r.URL.Path, "/api/local/") {
			// (/api/ticket and /api/local/ need the server secret in a header,
			// which a page elsewhere cannot send.)
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

// handleTicket gives the CLI on this machine a one-time sign-in ticket. It
// needs the server secret (from the 0600 token file) and a loopback client.
func (s *Server) handleTicket(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(clientIP(r))
	if ip == nil || !ip.IsLoopback() || !s.auth.bearerOK(r) {
		s.auth.fail(clientIP(r))
		errJSON(w, http.StatusUnauthorized, "not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ticket": s.auth.newTicket()})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if tk := r.URL.Query().Get("ticket"); tk != "" {
		id, ok := s.auth.useTicket(ip, tk)
		if !ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		s.auth.setSessionCookie(w, id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	id, ok := s.auth.login(ip, r.URL.Query().Get("token"))
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.loginPage(w)
		return
	}
	s.auth.setSessionCookie(w, id)
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
	http.SetCookie(w, &http.Cookie{Name: s.auth.cookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request, _ string, sess *session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version, "lang": s.Lang, "csrf": sess.CSRF, "listen": s.Addr, "kind": s.Kind,
		"app_hint": AppHint(),
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

// wantsExperimental: the page asked for experimental rules too (its
// "Show experimental checks" setting).
func wantsExperimental(r *http.Request) bool { return r.URL.Query().Get("experimental") == "1" }

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
	Gain      int      `json:"gain"`
	NeedsRoot bool     `json:"needs_root"`
	Undoable  bool     `json:"undoable"`
	// Repo and Place are the only parts of the item the page gets: which
	// repository (for the by-repo view) and where, as display text.
	Repo  string `json:"repo,omitempty"`
	Place string `json:"place,omitempty"`
	// Author is the GitHub handle of a contributed rule ("" for the core set).
	Author string `json:"author,omitempty"`
}

func (s *Server) render(results []source.Result, lang string, experimental bool) map[string]any {
	sc := s.Scanner.Evaluate(results, lang, experimental)
	type apiPassed struct {
		RuleID   string `json:"rule_id"`
		Label    string `json:"label"`
		Category string `json:"category"`
		Severity string `json:"severity"`
		Tier     string `json:"tier,omitempty"`
	}
	passed := []apiPassed{}
	for _, id := range sc.Passed {
		if r := s.rule(id); r != nil {
			passed = append(passed, apiPassed{id, r.Check.Get(lang), report.Category(r.Source), r.Severity, r.TierLabel()})
		}
	}
	out := make([]apiFinding, 0, len(sc.Findings))
	for _, f := range sc.Findings {
		f.Title, f.Explain, f.Fix = tilde(engine.Clean(f.Title)), tilde(engine.Clean(f.Explain)), tilde(engine.Clean(f.Fix))
		af := apiFinding{Finding: f, Key: engine.FindingID(f), Category: report.Category(f.Source), Gain: sc.Gain[f.RuleID]}
		if f.Remedy != nil {
			if a, ok := fix.Get(f.Remedy.Action); ok {
				for _, p := range a.Plan(f.Remedy.Params) {
					af.Plan = append(af.Plan, tilde(engine.Clean(p)))
				}
				af.NeedsRoot, af.Undoable = a.NeedsRoot, a.Undoable
				af.CanFix = !a.NeedsRoot // admin fixes stay in the terminal
			}
		}
		af.Repo, af.Place = report.Repo(f), report.Place(f)
		if r := s.rule(f.RuleID); r != nil {
			af.Author = r.Credit()
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
			end := e.Until
			if end.IsZero() { // written by an older version: ends MaxHide after
				end = e.Created.Add(ignore.MaxHide)
			}
			until[e.ID] = end.Format(time.RFC3339)
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
	return map[string]any{"scan": sc, "findings": out, "ignored": ign, "passed": passed, "sources": srcs, "scanned_at": s.scanned.Format(time.RFC3339), "watching": s.Watching}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	// ?cached=1: answer only from an earlier scan (the background service
	// keeps one fresh); 204 tells the UI to run a scan with progress.
	if r.URL.Query().Get("cached") == "1" {
		s.mu.Lock()
		res := s.results
		s.mu.Unlock()
		if res == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, s.render(res, langOf(r, s.Lang), wantsExperimental(r)))
		return
	}
	writeJSON(w, http.StatusOK, s.render(s.scan(r.Context(), false), langOf(r, s.Lang), wantsExperimental(r)))
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
	writeJSON(w, http.StatusOK, s.render(s.scan(r.Context(), true), langOf(r, s.Lang), wantsExperimental(r)))
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
	for _, f := range s.Scanner.Evaluate(results, s.Lang, true).Findings {
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
	for _, f := range s.Scanner.Evaluate(results, s.Lang, true).Findings {
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

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	st := update.Load()
	// The daily check can be up to a day old: refresh it when the page asks
	// and the last answer is more than an hour old, so the badge is right.
	if time.Since(st.Checked) > time.Hour && s.Version != "dev" {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		if latest, err := update.Latest(ctx); err == nil {
			st.Latest, st.Checked, st.LastError = latest, time.Now(), ""
			_ = update.Save(st)
		}
		cancel()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current": s.Version, "latest": st.Latest, "auto": st.Auto, "method": update.Method(),
		"available": update.Newer(st.Latest, s.Version), "checked": st.Checked, "error": st.LastError,
		// The macOS app: installed with automatic updates unless turned off.
		"mac": runtime.GOOS == "darwin", "app_installed": AppPath() != "", "auto_app": !st.NoAutoApp,
	})
}

// handleAppAuto turns installing the macOS app with automatic updates on
// or off (`security-warden app auto on|off`).
func (s *Server) handleAppAuto(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "send {\"on\": true|false}")
		return
	}
	st := update.Load()
	st.NoAutoApp = !req.On
	if err := update.Save(st); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"auto_app": !st.NoAutoApp})
}

// handleAppInstall installs the macOS app with Homebrew and opens it (the
// banner's button; `security-warden app install`). Homebrew installs only:
// others get the .dmg.
func (s *Server) handleAppInstall(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	if AppHint() != "brew" {
		errJSON(w, http.StatusBadRequest, "only for Homebrew installs on macOS without the app")
		return
	}
	if err := update.InstallAppCask(r.Context()); err != nil {
		errJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	st := update.Load()
	st.AppDone = true
	_ = update.Save(st)
	_ = OpenUI(DefaultPort)
	writeJSON(w, http.StatusOK, map[string]bool{"installed": true})
}

func (s *Server) handleUpdateAuto(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		Auto bool `json:"auto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "send {\"auto\": true|false}")
		return
	}
	st := update.Load()
	st.Auto = req.Auto
	if err := update.Save(st); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"auto": st.Auto})
}

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	done, err := fix.UndoLast()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"undone": len(done), "error": msg})
}

// feedbackInfo describes this server for issue drafts.
func (s *Server) feedbackInfo() feedback.Info {
	return feedback.Info{Version: s.Version, Platform: platformName(), Via: "web"}
}

func draftJSON(d feedback.Draft) map[string]any {
	return map[string]any{"preview": d.Preview, "url": d.URL, "title": d.Title, "shortened": d.Shortened, "kind": d.Kind}
}

// handleFeedback drafts a "this finding is wrong" issue for ?key= (or a
// rule id in ?rule=). It only builds the link: the browser opens it and the
// user submits it on GitHub, or not.
func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	target := strings.TrimSpace(r.URL.Query().Get("key"))
	if target == "" {
		target = strings.TrimSpace(r.URL.Query().Get("rule"))
	}
	if target == "" || len(target) > 200 {
		errJSON(w, http.StatusBadRequest, "give ?key=FINDING_KEY or ?rule=RULE_ID")
		return
	}
	s.mu.Lock()
	results := s.results
	s.mu.Unlock()
	sc := feedback.NewScrubber(feedback.DefaultEnv())
	if results != nil {
		// In English: the issue tracker's language.
		ev := s.Scanner.Evaluate(results, "en", true)
		if pick, err := ignore.Pick(append(ev.Findings, ev.Ignored...), target); err == nil {
			writeJSON(w, http.StatusOK, draftJSON(feedback.FalsePositive(pick[0], s.rule(pick[0].RuleID), s.feedbackInfo(), sc)))
			return
		}
	}
	if rule := s.rule(target); rule != nil {
		writeJSON(w, http.StatusOK, draftJSON(feedback.ForRule(rule, s.feedbackInfo(), sc)))
		return
	}
	errJSON(w, http.StatusNotFound, "no such finding or rule")
}

// handleFeedbackIdea drafts a "new check" issue from the user's words.
func (s *Server) handleFeedbackIdea(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "send {\"text\": \"...\"}")
		return
	}
	d, err := feedback.Idea(req.Text, s.feedbackInfo(), feedback.NewScrubber(feedback.DefaultEnv()))
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, draftJSON(d))
}

// handleFeedbackBug drafts a bug report from the user's words, with the
// newest lines of the scan log. Like the others, it only builds the link.
func (s *Server) handleFeedbackBug(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	req := struct {
		Text string `json:"text"`
		Log  bool   `json:"log"` // attach the newest lines of the scan log
	}{Log: true}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		errJSON(w, http.StatusBadRequest, "send {\"text\": \"what happened\", \"log\": true}")
		return
	}
	log := ""
	if req.Log {
		log, _ = source.ReadLog()
	}
	writeJSON(w, http.StatusOK, draftJSON(feedback.Bug(req.Text, log, s.feedbackInfo(), feedback.NewScrubber(feedback.DefaultEnv()))))
}

func platformName() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

// tilde shows the home folder as ~, like the terminal report.
func tilde(s string) string { return report.Tilde(s) }

// rule finds a loaded rule by id.
func (s *Server) rule(id string) *engine.Rule {
	for _, r := range s.Scanner.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
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

// handleSources lists what each source collects and every rule, for the
// "Rules & sources" page. Read-only: rules and schema are in the binary.
func (s *Server) handleSources(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	lang := langOf(r, s.Lang)
	type apiRule struct {
		ID        string   `json:"id"`
		Severity  string   `json:"severity"`
		Tier      string   `json:"tier"`
		Source    string   `json:"source"`
		Category  string   `json:"category"`
		Platforms []string `json:"platforms"`
		Title     string   `json:"title"`
		Check     string   `json:"check"`
		Author    string   `json:"author,omitempty"`
	}
	rs := []apiRule{}
	for _, x := range s.Scanner.Rules {
		rs = append(rs, apiRule{x.ID, x.Severity, x.Tier, x.Source, report.Category(x.Source), x.Platforms, x.Title.Get(lang), x.Check.Get(lang), x.Credit()})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":  rulecheck.Sources(s.Scanner.Rules, lang),
		"rules":    rs,
		"docs_url": rulecheck.DocsURL,
	})
}

// handleLogs returns the scan log (see source.LogDir): when each scan ran,
// and which sources failed, timed out or were slow, with the commands they
// waited on. It names commands only, never their output.
// With ?download=1 it is a text file to attach to a bug report, with the
// same identifying details taken out as in issue drafts.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request, _ string, _ *session) {
	text, err := source.ReadLog()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="security-warden-log.txt"`)
		_, _ = io.WriteString(w, feedback.ScrubLog(text, feedback.NewScrubber(feedback.DefaultEnv())))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": source.LogDir, "text": text})
}
