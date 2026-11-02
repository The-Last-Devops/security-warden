package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

func TestValidateListen(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("100.77.56.76"), netip.MustParseAddr("192.168.1.20")}
	ok := []string{"127.0.0.1:7878", "[::1]:7878", "100.77.56.76:7878"}
	for _, a := range ok {
		if _, _, err := ValidateListen(a, false, local); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	bad := []string{"0.0.0.0:7878", "[::]:7878", ":7878", "localhost:7878", "100.1.2.3:7878", "192.168.1.20:7878", "8.8.8.8:80", "127.0.0.1:0", "127.0.0.1"}
	for _, a := range bad {
		if _, _, err := ValidateListen(a, false, local); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
	if _, kind, err := ValidateListen("192.168.1.20:7878", true, local); err != nil || kind != KindLAN {
		t.Errorf("LAN with --allow-lan: %v %s", err, kind)
	}
	if _, _, err := ValidateListen("0.0.0.0:7878", true, local); err == nil {
		t.Error("0.0.0.0 accepted with --allow-lan")
	}
}

func init() { persist = false }

func testServer() *Server {
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ui</title>")}}
	sc := Scanner{
		Collect:  func(context.Context) []source.Result { return nil },
		Evaluate: func([]source.Result, string) report.Scan { return report.Scan{} },
	}
	return New("127.0.0.1:7878", KindLoopback, "test", "en", ui, sc)
}

func do(h http.Handler, method, url string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(`{"keys":["x"]}`))
	r.Host = "127.0.0.1:7878"
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
	if w := do(h, "GET", "/login?token="+s.Token(), map[string]string{"Host": "evil.example:7878"}); w.Code != http.StatusMisdirectedRequest {
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
	if w := do(h, "POST", "/api/undo", map[string]string{"Cookie": ck, "Origin": "http://127.0.0.1:7878"}); w.Code != 403 {
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
	w := do(h, "POST", "/api/passkey/login/begin", map[string]string{"Origin": "http://127.0.0.1:7878"})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "localhost") {
		t.Errorf("passkey on IP = %d %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(s.LoginURL(), "http://localhost:7878/login?token=") {
		t.Errorf("login URL = %s", s.LoginURL())
	}
	// Registration needs a session.
	w = do(h, "POST", "/api/passkey/register/begin", map[string]string{"Host": "localhost:7878", "Origin": "http://localhost:7878"})
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
	r.AddCookie(&http.Cookie{Name: cookieName, Value: id})
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
