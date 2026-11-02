package source

import (
	"strings"
	"testing"
	"time"
)

// fake builds a made-up token body of n characters from alphabet. The
// tokens are assembled at run time so no token-shaped string sits in the
// repository.
func fake(alphabet string, n int) string {
	var b strings.Builder
	x := uint32(2463534242)
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return b.String()
}

const (
	alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexd  = "0123456789abcdef"
)

func TestSecretPatternsLoad(t *testing.T) {
	set := secretPatterns()
	if len(set.patterns) != len(secretPatternList) {
		t.Fatalf("%d of %d patterns compiled", len(set.patterns), len(secretPatternList))
	}
	if len(set.patterns) < 150 {
		t.Fatalf("only %d patterns", len(set.patterns))
	}
	for _, p := range secretPatternList {
		if p.ID == "generic-api-key" {
			t.Error("generic-api-key must be skipped")
		}
	}
}

func TestSecretKindFamilies(t *testing.T) {
	cases := []struct{ want, text string }{
		{"github-pat", "export GH=" + "gh" + "p_" + fake(alnum, 36)},
		{"github-fine-grained-pat", "github" + "_pat_" + fake(alnum+"_", 82)},
		{"gitlab-pat", "token = " + "gl" + "pat-" + fake(alnum, 20)},
		{"aws-access-token", "AK" + "IA" + fake(upper, 16)},
		{"slack-bot-token", "xo" + "xb-" + fake("0123456789", 12) + "-" + fake("0123456789", 12) + "-" + fake(alnum, 24)},
		{"anthropic-api-key", `"` + "sk-ant-" + "api03-" + fake(alnum, 93) + `AA"`},
		{"npm-access-token", "//registry.npmjs.org/:_authToken=" + "np" + "m_" + fake(alnum, 36)},
		{"stripe-access-token", "sk" + "_live_" + fake(alnum, 24) + " "},
		{"digitalocean-pat", "do" + "p_v1_" + fake(hexd, 64)},
	}
	for _, c := range cases {
		if got := secretKind(c.text); got != c.want {
			t.Errorf("%s: got %q", c.want, got)
		}
	}
}

func TestSecretKindNotSecrets(t *testing.T) {
	for _, s := range []string{
		"",
		"export PATH=$HOME/bin:$PATH",
		"ghp_short",
		"AKIAIOSFODNN7EXAMPLE", // AWS documentation key, allowlisted
		"https://github.com/gitleaks/gitleaks",
		"alias ll='ls -la'",
		"sk_live_" + strings.Repeat("a", 24), // no entropy
		"the skeleton key skills",
	} {
		if got := secretKind(s); got != "" {
			t.Errorf("%q matched %s", s, got)
		}
	}
}

func TestScanSecretsHistory(t *testing.T) {
	tok := "gh" + "p_" + fake(alnum, 36)
	text := "ls\ngit push https://x:" + tok + "@github.com/a/b\nGH_TOKEN=" + tok + " gh pr list\n"
	hits := scanSecrets(text)
	if len(hits) != 2 {
		t.Fatalf("got %v", hits)
	}
	for _, h := range hits {
		if h.ID != "github-pat" || text[h.Start:h.End] != tok {
			t.Errorf("bad hit %+v", h)
		}
	}
}

// The keyword pass must keep a large history file fast.
func TestScanSecretsSpeed(t *testing.T) {
	line := "cd ~/code/project && git status && npm run build -- --watch # skeleton task 42\n"
	text := strings.Repeat(line, (4<<20)/len(line)) // about 4 MB
	start := time.Now()
	scanSecrets(text)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("4 MB took %v", d)
	}
}

func BenchmarkScanSecrets(b *testing.B) {
	line := "cd ~/code/project && git status && npm run build -- --watch # skeleton task 42\n"
	text := strings.Repeat(line, (1<<20)/len(line))
	b.SetBytes(int64(len(text)))
	for i := 0; i < b.N; i++ {
		scanSecrets(text)
	}
}
