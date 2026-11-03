package rulecheck

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// DocsURL is the guide to writing and contributing rules.
const DocsURL = "https://github.com/The-Last-Devops/security-warden/blob/main/docs/contributing-rules.md"

// FieldDoc is a source field with an example value from the rules' tests.
type FieldDoc struct {
	source.Field
	Example string `json:"example"`
}

// SourceDoc is what a rule author needs to know about one source.
type SourceDoc struct {
	Name          string     `json:"name"`
	Label         string     `json:"label"`
	Category      string     `json:"category"`
	CategoryLabel string     `json:"category_label"`
	Platforms     []string   `json:"platforms"`
	Rules         int        `json:"rules"`
	Fields        []FieldDoc `json:"fields"`
}

// Sources describes every source, in report order, with example values
// taken from the test samples of rs.
func Sources(rs []*engine.Rule, lang string) []SourceDoc {
	examples := Examples(rs)
	count := map[string]int{}
	for _, r := range rs {
		count[r.Source]++
	}
	var out []SourceDoc
	for _, c := range source.All() {
		info := source.Schema[c.Name]
		d := SourceDoc{Name: c.Name, Label: i18n.T(lang, "source."+c.Name), Category: report.Category(c.Name),
			CategoryLabel: i18n.T(lang, "cat."+report.Category(c.Name)), Platforms: info.Platforms, Rules: count[c.Name], Fields: []FieldDoc{}}
		for _, f := range info.Fields {
			ex := ""
			if v, ok := examples[c.Name][f.Name]; ok {
				ex = Show(v)
			}
			d.Fields = append(d.Fields, FieldDoc{f, ex})
		}
		out = append(out, d)
	}
	return out
}

// Examples collects, per source and field, a value used in the rules'
// test samples: the first non-empty one in rule order.
func Examples(rs []*engine.Rule) map[string]map[string]any {
	sorted := append([]*engine.Rule(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	out := map[string]map[string]any{}
	for _, r := range sorted {
		if out[r.Source] == nil {
			out[r.Source] = map[string]any{}
		}
		for _, t := range r.Tests {
			for k, v := range t.Item {
				if cur, ok := out[r.Source][k]; !ok || cur == "" {
					out[r.Source][k] = v
				}
			}
		}
	}
	return out
}

// Show prints an example value as it would be written in a rule: strings
// quoted, numbers and booleans bare.
func Show(v any) string {
	if s, ok := v.(string); ok {
		b, _ := json.Marshal(s)
		return string(b)
	}
	return fmt.Sprint(v)
}
