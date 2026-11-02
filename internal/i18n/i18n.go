// Package i18n holds every user-facing string of the CLI. Rule texts carry
// their own translations in the rule files.
package i18n

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Default is used when the user's language is not supported.
const Default = "en"

// Supported lists the languages with a full catalog, in display order.
var Supported = []string{"en", "vi"}

var catalogs = map[string]map[string]string{"en": en, "vi": vi}

// T returns the message for key in lang, falling back to English, then the key.
func T(lang, key string) string {
	if s, ok := catalogs[lang][key]; ok {
		return s
	}
	if s, ok := en[key]; ok {
		return s
	}
	return key
}

// Keys returns every key of the English catalog (the source of truth).
func Keys() []string {
	ks := make([]string, 0, len(en))
	for k := range en {
		ks = append(ks, k)
	}
	return ks
}

// Catalog returns the catalog of one language, for tests.
func Catalog(lang string) map[string]string { return catalogs[lang] }

// Normalize turns "vi_VN.UTF-8" or "vi-VN" into "vi" if supported.
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	tag, _, _ = strings.Cut(tag, ".")
	tag = strings.ReplaceAll(tag, "_", "-")
	base, _, _ := strings.Cut(tag, "-")
	for _, s := range Supported {
		if base == s {
			return s
		}
	}
	return ""
}

// Detect picks the language: explicit flag, SW_LANG, LC_ALL/LC_MESSAGES,
// the macOS preferred languages, then LANG. macOS sets LANG to en_US for
// most people regardless of their UI language, so it comes last.
func Detect(flag string) string {
	for _, v := range []string{flag, os.Getenv("SW_LANG"), os.Getenv("LC_ALL"), os.Getenv("LC_MESSAGES")} {
		if l := Normalize(v); l != "" {
			return l
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("defaults", "read", "-g", "AppleLanguages").Output(); err == nil {
			for _, f := range strings.FieldsFunc(string(out), func(r rune) bool {
				return r == '(' || r == ')' || r == ',' || r == '"' || r == '\n' || r == ' '
			}) {
				if l := Normalize(f); l != "" {
					return l
				}
				break // only the first preferred language counts
			}
		}
	}
	if l := Normalize(os.Getenv("LANG")); l != "" {
		return l
	}
	return Default
}
