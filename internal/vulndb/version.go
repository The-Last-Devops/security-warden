package vulndb

import (
	"math/big"
	"regexp"
	"strings"
)

// Compare orders two versions of one ecosystem: -1, 0 or 1. ok is false
// when either version cannot be read, and then nothing should be matched.
func Compare(eco, a, b string) (int, bool) {
	switch eco {
	case "PyPI":
		x, ok1 := parsePEP440(a)
		y, ok2 := parsePEP440(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return x.cmp(y), true
	case "RubyGems":
		return cmpGem(a, b)
	default: // npm, Go, crates.io: semantic versioning
		x, ok1 := parseSemver(a)
		y, ok2 := parseSemver(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return x.cmp(y), true
	}
}

// --- Semantic Versioning 2.0 (npm, Go modules, crates.io) ---

type semver struct {
	nums [3]*big.Int
	pre  []string
}

var semverRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := 0; i < 3; i++ {
		n := new(big.Int)
		if m[i+1] != "" {
			n.SetString(m[i+1], 10)
		}
		v.nums[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

func (a semver) cmp(b semver) int {
	for i := range a.nums {
		if c := a.nums[i].Cmp(b.nums[i]); c != 0 {
			return c
		}
	}
	// A pre-release sorts before the release itself.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := cmpIdent(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	return sign(len(a.pre) - len(b.pre))
}

// cmpIdent compares pre-release identifiers: numbers numerically and below
// words, words in ASCII order.
func cmpIdent(a, b string) int {
	an, bn := isNum(a), isNum(b)
	switch {
	case an && bn:
		x, _ := new(big.Int).SetString(a, 10)
		y, _ := new(big.Int).SetString(b, 10)
		return x.Cmp(y)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

func isNum(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// --- PEP 440 (PyPI), the parts real release numbers use ---

type pep440 struct {
	epoch   int
	release []int
	pre     [2]int // phase (0 a, 1 b, 2 rc) and number; phase -1 none
	post    int    // -1 none
	dev     int    // -1 none
}

var pepRe = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?([-_.]?dev[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func parsePEP440(s string) (pep440, bool) {
	m := pepRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	v := pep440{pre: [2]int{-1, 0}, post: -1, dev: -1}
	v.epoch = atoiSafe(m[1])
	for _, p := range strings.Split(m[2], ".") {
		v.release = append(v.release, atoiSafe(p))
	}
	if m[3] != "" {
		switch m[3] {
		case "a", "alpha":
			v.pre[0] = 0
		case "b", "beta":
			v.pre[0] = 1
		default:
			v.pre[0] = 2
		}
		v.pre[1] = atoiSafe(m[4])
	}
	switch {
	case m[5] != "":
		v.post = atoiSafe(m[5])
	case m[6] != "":
		v.post = atoiSafe(m[7])
	}
	if m[8] != "" {
		v.dev = atoiSafe(m[9])
	}
	return v, true
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' || n > 1<<40 {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func (a pep440) cmp(b pep440) int {
	if c := sign(a.epoch - b.epoch); c != 0 {
		return c
	}
	n := max(len(a.release), len(b.release))
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := sign(x - y); c != 0 {
			return c
		}
	}
	if c := cmpKeys(a.preKey(), b.preKey()); c != 0 {
		return c
	}
	if c := sign(a.post - b.post); c != 0 {
		return c
	}
	return cmpKeys(devKey(a.dev), devKey(b.dev))
}

// preKey: a dev release of the final version (1.0.dev1) sorts before its
// pre-releases; a version with no pre-release after all of them.
func (v pep440) preKey() [2]int {
	switch {
	case v.pre[0] < 0 && v.post < 0 && v.dev >= 0:
		return [2]int{-2, 0}
	case v.pre[0] < 0:
		return [2]int{3, 0}
	}
	return v.pre
}

func devKey(d int) [2]int {
	if d < 0 {
		return [2]int{1, 0}
	}
	return [2]int{0, d}
}

func cmpKeys(a, b [2]int) int {
	if c := sign(a[0] - b[0]); c != 0 {
		return c
	}
	return sign(a[1] - b[1])
}

// --- RubyGems (Gem::Version) ---

var gemSeg = regexp.MustCompile(`[0-9]+|[a-z]+`)

var gemValid = regexp.MustCompile(`^[0-9]+(?:[.-]?[0-9a-zA-Z]+)*$`)

func cmpGem(a, b string) (int, bool) {
	valid := gemValid
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !valid.MatchString(a) || !valid.MatchString(b) {
		return 0, false
	}
	x := gemSegs(a)
	y := gemSegs(b)
	n := max(len(x), len(y))
	for i := 0; i < n; i++ {
		p, q := "0", "0"
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		pn, qn := isNum(p), isNum(q)
		switch {
		case pn && qn:
			pi, _ := new(big.Int).SetString(p, 10)
			qi, _ := new(big.Int).SetString(q, 10)
			if c := pi.Cmp(qi); c != 0 {
				return c, true
			}
		case pn: // a word (pre-release) sorts before a number
			return 1, true
		case qn:
			return -1, true
		default:
			if c := strings.Compare(p, q); c != 0 {
				return c, true
			}
		}
	}
	return 0, true
}

// gemSegs splits "1.0.0.rc1" into 1 0 0 rc 1 and drops trailing zeros, as
// Gem::Version does.
func gemSegs(s string) []string {
	segs := gemSeg.FindAllString(strings.ToLower(strings.ReplaceAll(s, "-", ".pre.")), -1)
	for len(segs) > 0 && isNum(segs[len(segs)-1]) && strings.Trim(segs[len(segs)-1], "0") == "" {
		segs = segs[:len(segs)-1]
	}
	return segs
}
