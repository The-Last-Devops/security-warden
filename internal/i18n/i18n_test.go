package i18n

import (
	"strings"
	"testing"
)

// Every language must have exactly the English keys, none empty, and the
// same printf verbs.
func TestCatalogsComplete(t *testing.T) {
	for _, lang := range Supported {
		cat := Catalog(lang)
		for _, k := range Keys() {
			s, ok := cat[k]
			if !ok || strings.TrimSpace(s) == "" {
				t.Errorf("%s: missing %q", lang, k)
				continue
			}
			if strings.Count(s, "%d") != strings.Count(en[k], "%d") || strings.Count(s, "%s") != strings.Count(en[k], "%s") {
				t.Errorf("%s: %q has different placeholders", lang, k)
			}
		}
		for k := range cat {
			if _, ok := en[k]; !ok {
				t.Errorf("%s: extra key %q", lang, k)
			}
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{"vi_VN.UTF-8": "vi", "vi-VN": "vi", "en": "en", "fr_FR": "", "C": "", "": ""}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
