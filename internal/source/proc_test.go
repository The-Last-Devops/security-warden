package source

import "testing"

func TestParseProcAddr(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"00000000:0016", "0.0.0.0", 22},
		{"0501A8C0:0BB8", "192.168.1.5", 3000},
		{"00000000000000000000000000000000:1538", "::", 5432},
		{"00000000000000000000000001000000:1F90", "::1", 8080},
	}
	for _, c := range cases {
		h, p, err := parseProcAddr(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Errorf("parseProcAddr(%q) = %q, %d, %v; want %q, %d", c.in, h, p, err, c.host, c.port)
		}
	}
}

func TestClassifyKey(t *testing.T) {
	if _, enc, ok := classifyKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")); !ok || !enc {
		t.Error("encrypted PEM not detected")
	}
	if _, enc, ok := classifyKey([]byte("-----BEGIN PRIVATE KEY-----\nMIIE")); !ok || enc {
		t.Error("plain PKCS8 not detected")
	}
	if _, _, ok := classifyKey([]byte("ssh-ed25519 AAAA user@host")); ok {
		t.Error("public key taken for a private key")
	}
}

func TestHomebrewFormula(t *testing.T) {
	n, v := homebrewFormula("/opt/homebrew/Cellar/postgresql@16/16.4/bin/postgres")
	if n != "postgresql@16" || v != "16.4" {
		t.Errorf("got %q %q", n, v)
	}
	if s, ok := identify("/usr/local/Cellar/elasticsearch-full/7.17/libexec/jdk/bin/java"); !ok || s.product != "Elasticsearch" {
		t.Errorf("elasticsearch java not identified: %v", s)
	}
}
