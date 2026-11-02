package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveOnLoopback answers /api/passkey like a Security Warden server would.
func serveOnLoopback(t *testing.T, body string) int {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/passkey" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().(*net.TCPAddr).Port
}

func TestRunningVersion(t *testing.T) {
	port := serveOnLoopback(t, `{"available":true,"count":1,"localhost":"http://localhost:1","version":"v0.2.6"}`)
	if !RunningHere(port) || RunningVersion(port) != "v0.2.6" {
		t.Fatalf("running=%v version=%q", RunningHere(port), RunningVersion(port))
	}
}

// Servers before v0.2.5 do not report a version: start must see "" (which
// differs from its own version) and replace them.
func TestRunningVersionOldServer(t *testing.T) {
	port := serveOnLoopback(t, `{"available":true,"count":1,"localhost":"http://localhost:1"}`)
	if !RunningHere(port) || RunningVersion(port) != "" {
		t.Fatalf("running=%v version=%q", RunningHere(port), RunningVersion(port))
	}
}

func TestRunningHereIgnoresOtherServers(t *testing.T) {
	port := serveOnLoopback(t, `{"hello":"world"}`)
	if RunningHere(port) {
		t.Fatal("another app on the port is not Security Warden")
	}
}
