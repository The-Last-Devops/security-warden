package web

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

func TestValidateListen(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("100.77.56.76"), netip.MustParseAddr("192.168.1.20")}
	ok := []string{"127.0.0.1:7348", "[::1]:7348", "100.77.56.76:7348"}
	for _, a := range ok {
		if _, _, err := ValidateListen(a, false, local); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	bad := []string{"0.0.0.0:7348", "[::]:7348", ":7348", "localhost:7348", "100.1.2.3:7348", "192.168.1.20:7348", "8.8.8.8:80", "127.0.0.1:0", "127.0.0.1"}
	for _, a := range bad {
		if _, _, err := ValidateListen(a, false, local); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
	if _, kind, err := ValidateListen("192.168.1.20:7348", true, local); err != nil || kind != KindLAN {
		t.Errorf("LAN with --allow-lan: %v %s", err, kind)
	}
	if _, _, err := ValidateListen("0.0.0.0:7348", true, local); err == nil {
		t.Error("0.0.0.0 accepted with --allow-lan")
	}
}

func init() { persist = false }

func testServer() *Server {
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ui</title>")}}
	sc := Scanner{
		Collect:  func(context.Context, func(string)) []source.Result { return nil },
		Evaluate: func([]source.Result, string, bool) report.Scan { return report.Scan{} },
	}
	return New("127.0.0.1:7348", KindLoopback, "test", "en", ui, sc)
}

func do(h http.Handler, method, url string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(`{"keys":["x"]}`))
	r.Host = "127.0.0.1:7348"
	r.RemoteAddr = "127.0.0.1:5555"
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthFlow(t *testing.T) {
	s := testServer()
	h := s.Handler()

	if w := do(h, "GET", "/api/meta", nil); w.Code != 401 {
		t.Fatalf("meta without session = %d", w.Code)
	}
	if w := do(h, "GET", "/api/scan", nil); w.Code != 401 {
		t.Fatalf("scan without session = %d", w.Code)
	}
	if w := do(h, "GET", "/login?token="+s.Token(), map[string]string{"Host": "evil.example:7348"}); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding host accepted: %d", w.Code)
	}
	w := do(h, "GET", "/login?token="+s.Token(), nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login = %d", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie not HttpOnly + SameSite=Strict")
	}
	ck := cookie.Name + "=" + cookie.Value

	if w := do(h, "GET", "/api/meta", map[string]string{"Cookie": ck}); w.Code != 200 {
		t.Fatalf("meta with session = %d", w.Code)
	}
	// POST without Origin, from another origin, or without CSRF token: refused.
	if w := do(h, "POST", "/api/undo", map[string]string{"Cookie": ck}); w.Code != 403 {
		t.Errorf("POST without Origin = %d", w.Code)
	}
	if w := do(h, "POST", "/api/undo", map[string]string{"Cookie": ck, "Origin": "http://evil.example"}); w.Code != 403 {
		t.Errorf("cross-origin POST = %d", w.Code)
	}
	if w := do(h, "POST", "/api/undo", map[string]string{"Cookie": ck, "Origin": "http://127.0.0.1:7348"}); w.Code != 403 {
		t.Errorf("POST without CSRF = %d", w.Code)
	}
	if w := do(h, "GET", "/", map[string]string{"Cookie": ck}); w.Header().Get("Content-Security-Policy") == "" {
		t.Error("no CSP header")
	}
}

func TestLoginLockout(t *testing.T) {
	s := testServer()
	h := s.Handler()
	for i := 0; i < maxFailures; i++ {
		do(h, "GET", "/login?token=wrong", nil)
	}
	if w := do(h, "GET", "/login?token="+s.Token(), nil); w.Code == http.StatusSeeOther {
		t.Fatal("correct token accepted during lockout")
	}
}

func TestPasskeyNeedsName(t *testing.T) {
	s := testServer()
	h := s.Handler()
	// IP host: WebAuthn cannot use it, the server says so.
	w := do(h, "POST", "/api/passkey/login/begin", map[string]string{"Origin": "http://127.0.0.1:7348"})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "localhost") {
		t.Errorf("passkey on IP = %d %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(s.LoginURL(), "http://localhost:7348/login?token=") {
		t.Errorf("login URL = %s", s.LoginURL())
	}
	// Registration needs a session.
	w = do(h, "POST", "/api/passkey/register/begin", map[string]string{"Host": "localhost:7348", "Origin": "http://localhost:7348"})
	if w.Code != 401 {
		t.Errorf("register without session = %d", w.Code)
	}
}

func TestPasskeyUserIDStable(t *testing.T) {
	p := newPasskeys()
	p.path = t.TempDir() + "/passkeys.json"
	a, err := p.load()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.load()
	if string(a.ID) != string(b.ID) {
		t.Fatal("user id changed between loads; registration would fail")
	}
}

func TestSessionsSurviveRestart(t *testing.T) {
	path := t.TempDir() + "/sessions.json"
	a := newAuth()
	a.loadSessions(path)
	id := a.newSession("127.0.0.1")
	b := newAuth()
	b.loadSessions(path)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "sw_session", Value: id})
	if _, s := b.session(r); s == nil {
		t.Fatal("session lost after restart")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), id) {
		t.Fatal("session id stored in clear")
	}
	b.logout(id)
	c := newAuth()
	c.loadSessions(path)
	if _, s := c.session(r); s != nil {
		t.Fatal("logged-out session came back")
	}
}

func TestListenFixedPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer busy.Close()
	if _, err := Listen(busy.Addr().String()); !errors.Is(err, ErrInUse) {
		t.Errorf("busy port: %v, want ErrInUse", err)
	}
	if RunningHere(busy.Addr().(*net.TCPAddr).Port) {
		t.Error("a plain TCP listener taken for Security Warden")
	}
}

func TestTicketSignIn(t *testing.T) {
	s := testServer()
	h := s.Handler()
	// Without the secret: refused.
	if w := do(h, "POST", "/api/ticket", nil); w.Code != 401 {
		t.Fatalf("ticket without secret = %d", w.Code)
	}
	w := do(h, "POST", "/api/ticket", map[string]string{"Authorization": "Bearer " + s.Token()})
	if w.Code != 200 {
		t.Fatalf("ticket = %d", w.Code)
	}
	var v struct{ Ticket string }
	json.Unmarshal(w.Body.Bytes(), &v)
	w = do(h, "GET", "/login?ticket="+v.Ticket, nil)
	if w.Code != http.StatusSeeOther || len(w.Result().Cookies()) == 0 {
		t.Fatalf("ticket login = %d", w.Code)
	}
	// Used once only.
	w = do(h, "GET", "/login?ticket="+v.Ticket, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("ticket worked twice")
	}
	// Not from another machine, even with the secret.
	r := httptest.NewRequest("POST", "/api/ticket", nil)
	r.Host = "127.0.0.1:7348"
	r.RemoteAddr = "100.64.1.2:5555"
	r.Header.Set("Authorization", "Bearer "+s.Token())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("ticket from non-loopback = %d", rec.Code)
	}
}

func TestLocalSettings(t *testing.T) {
	s := testServer()
	h := s.Handler()
	s.pk.path = t.TempDir() + "/passkeys.json"
	s.auth.newSession("127.0.0.1")
	s.auth.newSession("127.0.0.1")
	// Without the secret, or from another machine: refused.
	if w := do(h, "POST", "/api/local/logout", nil); w.Code != 401 {
		t.Fatalf("logout without secret = %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/api/local/logout", nil)
	r.Host = "127.0.0.1:7348"
	r.RemoteAddr = "100.64.1.2:5555"
	r.Header.Set("Authorization", "Bearer "+s.Token())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("logout from non-loopback = %d", rec.Code)
	}
	bearer := map[string]string{"Authorization": "Bearer " + s.Token()}
	w := do(h, "POST", "/api/local/logout", bearer)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ended":2`) || len(s.auth.sessions) != 0 {
		t.Fatalf("logout = %d %s", w.Code, w.Body.String())
	}
	u, _ := s.pk.load()
	u.Creds = append(u.Creds, webauthn.Credential{ID: []byte{1, 2}})
	u.Added = map[string]time.Time{"0102": time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)}
	_ = s.pk.save(u)
	w = do(h, "GET", "/api/local/passkeys", bearer)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "2026-01-02T03:04:00Z") {
		t.Fatalf("passkeys = %d %s", w.Code, w.Body.String())
	}
	w = do(h, "POST", "/api/local/passkeys/clear", bearer)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"removed":1`) {
		t.Fatalf("clear = %d %s", w.Code, w.Body.String())
	}
	if u, _ := s.pk.load(); len(u.Creds) != 0 || u.Added != nil {
		t.Fatal("passkeys still there")
	}
}

func TestSourcesAPI(t *testing.T) {
	s := testServer()
	h := s.Handler()
	if w := do(h, "GET", "/api/sources", nil); w.Code != 401 {
		t.Fatalf("sources without session = %d", w.Code)
	}
	w := do(h, "GET", "/login?token="+s.Token(), nil)
	ck := w.Result().Cookies()[0]
	w = do(h, "GET", "/api/sources?lang=vi", map[string]string{"Cookie": ck.Name + "=" + ck.Value})
	if w.Code != 200 {
		t.Fatalf("sources = %d", w.Code)
	}
	var out struct {
		Sources []struct {
			Name   string
			Label  string
			Fields []struct{ Name, Type string }
		}
		Rules   []any
		DocsURL string `json:"docs_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != len(source.All()) || out.Rules == nil || !strings.HasPrefix(out.DocsURL, "https://github.com/") {
		t.Fatalf("sources = %d, rules = %v, docs = %q", len(out.Sources), out.Rules, out.DocsURL)
	}
	for _, src := range out.Sources {
		if src.Name == "tailscale" && (len(src.Fields) == 0 || src.Label == "") {
			t.Errorf("tailscale: %+v", src)
		}
	}
	if w := do(h, "POST", "/api/sources", map[string]string{"Cookie": ck.Name + "=" + ck.Value}); w.Code == 200 {
		t.Error("POST /api/sources answered")
	}
}

func TestFeedbackAPI(t *testing.T) {
	home, _ := os.UserHomeDir()
	f := engine.Finding{RuleID: "demo-rule", Severity: "high", Source: "credential_files",
		Title: "Readable: " + home + "/.aws/credentials", Explain: "why", Fix: "fix", Item: engine.Item{"path": home + "/.aws/credentials"}}
	rule := &engine.Rule{ID: "demo-rule", Severity: "high", Source: "credential_files", Author: "octocat",
		Title: engine.Text{"en": "Readable: {path}"}, Explain: engine.Text{"en": "why"}, Fix: engine.Text{"en": "fix"}}
	s := testServer()
	s.Scanner.Rules = []*engine.Rule{rule}
	s.Scanner.Evaluate = func([]source.Result, string, bool) report.Scan { return report.Scan{Findings: []engine.Finding{f}} }
	h := s.Handler()
	key := engine.FindingID(f)
	if w := do(h, "GET", "/api/feedback?key="+key, nil); w.Code != 401 {
		t.Fatalf("feedback without session = %d", w.Code)
	}
	w := do(h, "GET", "/login?token="+s.Token(), nil)
	c := w.Result().Cookies()[0]
	ck := c.Name + "=" + c.Value

	// A rule that does not fail (no scan yet) still gets a draft.
	w = do(h, "GET", "/api/feedback?rule=demo-rule", map[string]string{"Cookie": ck})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "False positive: demo-rule") {
		t.Fatalf("rule draft = %d %s", w.Code, w.Body)
	}
	s.results = []source.Result{{Name: "credential_files"}}
	w = do(h, "GET", "/api/feedback?key="+key, map[string]string{"Cookie": ck})
	var d struct{ Preview, URL string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &d) != nil || !strings.HasPrefix(d.URL, "https://github.com/The-Last-Devops/security-warden/issues/new?") ||
		!strings.Contains(d.Preview, "~/.aws/credentials") || (len(home) > 1 && strings.Contains(w.Body.String(), home)) {
		t.Fatalf("finding draft = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/api/feedback?key=nothing-like-this", map[string]string{"Cookie": ck}); w.Code != 404 {
		t.Errorf("unknown key = %d", w.Code)
	}
	if w := do(h, "GET", "/api/feedback", map[string]string{"Cookie": ck}); w.Code != 400 {
		t.Errorf("no key = %d", w.Code)
	}

	// The idea endpoint is a POST: same-origin and CSRF like every other.
	var meta struct{ CSRF string }
	_ = json.Unmarshal(do(h, "GET", "/api/meta", map[string]string{"Cookie": ck}).Body.Bytes(), &meta)
	post := func(body string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/feedback/idea", strings.NewReader(body))
		r.Host, r.RemoteAddr = "127.0.0.1:7348", "127.0.0.1:5555"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	idea := `{"text":"Check ` + strings.ReplaceAll(home, `\`, `\\`) + `/.npmrc for tokens"}`
	if w := post(idea, map[string]string{"Cookie": ck, "Origin": "http://127.0.0.1:7348"}); w.Code != 403 {
		t.Errorf("idea without CSRF = %d", w.Code)
	}
	if w := post(idea, map[string]string{"Cookie": ck, "Origin": "http://evil.example", "X-CSRF-Token": meta.CSRF}); w.Code != 403 {
		t.Errorf("cross-site idea = %d", w.Code)
	}
	w = post(idea, map[string]string{"Cookie": ck, "Origin": "http://127.0.0.1:7348", "X-CSRF-Token": meta.CSRF})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rule-request.yml") || (len(home) > 1 && strings.Contains(w.Body.String(), home)) {
		t.Fatalf("idea = %d %s", w.Code, w.Body)
	}
	if w := post(`{"text":"  "}`, map[string]string{"Cookie": ck, "Origin": "http://127.0.0.1:7348", "X-CSRF-Token": meta.CSRF}); w.Code != 400 {
		t.Errorf("empty idea = %d", w.Code)
	}

	// Credit for contributed rules reaches the page.
	w = do(h, "GET", "/api/scan?cached=1", map[string]string{"Cookie": ck})
	if !strings.Contains(w.Body.String(), `"author":"octocat"`) {
		t.Errorf("scan has no author: %s", w.Body)
	}
}

func TestLogsBugAndAppAPI(t *testing.T) {
	s := testServer()
	h := s.Handler()
	if w := do(h, "GET", "/api/logs", nil); w.Code != 401 {
		t.Fatalf("logs without session = %d", w.Code)
	}
	c := do(h, "GET", "/login?token="+s.Token(), nil).Result().Cookies()[0]
	ck := c.Name + "=" + c.Value
	if w := do(h, "GET", "/api/logs", map[string]string{"Cookie": ck}); w.Code != 200 || !strings.Contains(w.Body.String(), `"text"`) {
		t.Fatalf("logs = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/api/logs?download=1", map[string]string{"Cookie": ck}); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("log download = %d %v", w.Code, w.Header())
	}
	var meta struct{ CSRF string }
	_ = json.Unmarshal(do(h, "GET", "/api/meta", map[string]string{"Cookie": ck}).Body.Bytes(), &meta)
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host, r.RemoteAddr = "127.0.0.1:7348", "127.0.0.1:5555"
		r.Header.Set("Cookie", ck)
		r.Header.Set("Origin", "http://127.0.0.1:7348")
		r.Header.Set("X-CSRF-Token", meta.CSRF)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	w := post("/api/feedback/bug", `{"text":"the scan hangs at 89%","log":false}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "bug.yml") || strings.Contains(w.Body.String(), "Scan log") {
		t.Fatalf("bug = %d %s", w.Code, w.Body)
	}
	if w := post("/api/feedback/bug", `{"text":" "}`); w.Code != 400 {
		t.Errorf("empty bug = %d", w.Code)
	}
	// Installing the app is only for Homebrew installs on macOS without it;
	// a test binary is never one, so nothing runs brew here.
	if AppHint() != "brew" {
		if w := post("/api/app/install", ``); w.Code != 400 {
			t.Errorf("app install outside Homebrew = %d", w.Code)
		}
	}
}
