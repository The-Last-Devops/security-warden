package source

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// secretPattern is one token format, generated from gitleaks' rules by
// tools/gen-secret-patterns (see secretpatterns_gen.go).
type secretPattern struct {
	ID          string
	Regex       string
	Keywords    []string // lower case; one must appear before the regex runs
	Entropy     float64  // minimum Shannon entropy of the secret, 0 = none
	SecretGroup int      // capture group holding the secret, 0 = first non-empty
	Allow       []string // regexes on the secret that mean "not a secret"
	AllowMatch  []string // same, on the whole match
	Stopwords   []string // lower case words that mean "not a secret"
}

type compiledPattern struct {
	secretPattern
	re         *regexp.Regexp
	allow      []*regexp.Regexp
	allowMatch []*regexp.Regexp
}

type secretSet struct {
	patterns  []compiledPattern
	allow     []*regexp.Regexp
	stopwords []string

	// Keyword index: every keyword is at least two bytes long, so a table
	// of two-byte prefixes finds all of them in one pass over the text.
	pre      [1 << 16]bool
	byPre    map[uint16][]int // prefix -> keyword indexes
	keywords []string         // lower case
	users    [][]int          // keyword index -> pattern indexes
}

func compileAll(xs []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, x := range xs {
		if re, err := regexp.Compile(x); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// secretPatterns compiles the patterns once, on first use. The generator
// already dropped what Go cannot compile; anything left over is skipped.
var secretPatterns = sync.OnceValue(func() *secretSet {
	s := &secretSet{allow: compileAll(secretGlobalAllow), stopwords: secretGlobalStopwords}
	for _, p := range secretPatternList {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		s.patterns = append(s.patterns, compiledPattern{p, re, compileAll(p.Allow), compileAll(p.AllowMatch)})
	}
	s.byPre = map[uint16][]int{}
	kwIndex := map[string]int{}
	for pi, p := range s.patterns {
		for _, kw := range p.Keywords {
			if len(kw) < 2 {
				continue
			}
			ki, ok := kwIndex[kw]
			if !ok {
				ki = len(s.keywords)
				kwIndex[kw] = ki
				s.keywords = append(s.keywords, kw)
				s.users = append(s.users, nil)
				k := uint16(kw[0])<<8 | uint16(kw[1])
				s.pre[k] = true
				s.byPre[k] = append(s.byPre[k], ki)
			}
			s.users[ki] = append(s.users[ki], pi)
		}
	}
	return s
})

// secretHit is one token found in a text: the gitleaks rule id and where it
// is. The value itself is never kept.
type secretHit struct {
	ID         string
	Start, End int
}

// asciiLower lowercases ASCII letters only, so byte offsets stay the same
// as in the original text.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// scanSecrets finds known token formats in text. One pass finds the
// lines holding a pattern's keywords (case-insensitive); each pattern's
// regex then runs only on those lines, which keeps large history files fast.
func scanSecrets(text string) []secretHit {
	set := secretPatterns()
	lines := make([][]int, len(set.patterns)) // pattern -> line starts
	lineStart := 0
	for i := 0; i+1 < len(text); i++ {
		c := lowerByte(text[i])
		if c == '\n' {
			lineStart = i + 1
			continue
		}
		k := uint16(c)<<8 | uint16(lowerByte(text[i+1]))
		if !set.pre[k] {
			continue
		}
		for _, ki := range set.byPre[k] {
			if !hasPrefixFold(text[i:], set.keywords[ki]) {
				continue
			}
			for _, pi := range set.users[ki] {
				if l := lines[pi]; len(l) == 0 || l[len(l)-1] != lineStart {
					lines[pi] = append(l, lineStart)
				}
			}
		}
	}
	var hits []secretHit
	for pi, starts := range lines {
		p := &set.patterns[pi]
		for _, st := range starts {
			end := strings.IndexByte(text[st:], '\n')
			if end < 0 {
				end = len(text)
			} else {
				end += st
			}
			line := text[st:end]
			for _, m := range p.re.FindAllStringSubmatchIndex(line, -1) {
				if set.keep(p, line, m) {
					hits = append(hits, secretHit{p.ID, st + m[0], st + m[1]})
				}
			}
		}
	}
	return hits
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 32
	}
	return c
}

// hasPrefixFold: s starts with the lower-case word w, ignoring ASCII case.
func hasPrefixFold(s, w string) bool {
	if len(s) < len(w) {
		return false
	}
	for i := 0; i < len(w); i++ {
		if lowerByte(s[i]) != w[i] {
			return false
		}
	}
	return true
}

// keep applies gitleaks' filters to one match: entropy, allowlists and
// stopwords.
func (s *secretSet) keep(p *compiledPattern, line string, m []int) bool {
	match := line[m[0]:m[1]]
	secret := match
	if p.SecretGroup > 0 && 2*p.SecretGroup+1 < len(m) {
		if m[2*p.SecretGroup] >= 0 {
			secret = line[m[2*p.SecretGroup]:m[2*p.SecretGroup+1]]
		}
	} else {
		for g := 2; g+1 < len(m); g += 2 {
			if m[g] >= 0 && m[g+1] > m[g] {
				secret = line[m[g]:m[g+1]]
				break
			}
		}
	}
	if p.Entropy > 0 && shannon(secret) <= p.Entropy {
		return false
	}
	for _, re := range s.allow {
		if re.MatchString(secret) {
			return false
		}
	}
	for _, re := range p.allow {
		if re.MatchString(secret) {
			return false
		}
	}
	for _, re := range p.allowMatch {
		if re.MatchString(match) {
			return false
		}
	}
	ls := asciiLower(secret)
	for _, w := range s.stopwords {
		if strings.Contains(ls, w) {
			return false
		}
	}
	for _, w := range p.Stopwords {
		if strings.Contains(ls, w) {
			return false
		}
	}
	return true
}

// secretKind returns the gitleaks rule id of the first known token format
// found in s, or "".
func secretKind(s string) string {
	if s == "" {
		return ""
	}
	hits := scanSecrets(s)
	if len(hits) == 0 {
		return ""
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Start < hits[j].Start })
	return hits[0].ID
}

// shannon is the Shannon entropy of s in bits per byte, as gitleaks
// computes it.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}
