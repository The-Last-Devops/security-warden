package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/rulecheck"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

type rulesOpts struct {
	JSON      bool
	Source    string
	Severity  string
	Platforms string
	Dir       string
	Strict    bool
	New       bool
}

// runRules: list the rules, describe the sources, start a rule, or check
// rule files. Everything works from the binary alone.
func runRules(l string, rs []*engine.Rule, args []string, o rulesOpts) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "", "list":
		fmt.Printf(i18n.T(l, "cli.rules_header")+"\n\n", len(rs))
		for _, r := range rs {
			tier := ""
			if t := r.TierLabel(); t != "" {
				tier = "[" + i18n.T(l, "tier."+t) + "] "
			}
			fmt.Printf("  %-36s %-8s %s%s\n", r.ID, r.Severity, tier, r.Title.Get(l))
		}
		return 0
	case "sources":
		return runRulesSources(l, rs, args, o.JSON)
	case "new":
		return runRulesNew(l, rs, args, o)
	case "check":
		return runRulesCheck(l, args, o)
	}
	fmt.Fprintln(os.Stderr, i18n.T(l, "cli.usage"))
	return 2
}

func runRulesSources(l string, rs []*engine.Rule, args []string, asJSON bool) int {
	docs := rulecheck.Sources(rs, l)
	if len(args) > 0 {
		var one []rulecheck.SourceDoc
		for _, d := range docs {
			if d.Name == args[0] {
				one = append(one, d)
			}
		}
		if one == nil {
			fmt.Fprintf(os.Stderr, i18n.T(l, "rules.unknown_source")+"\n", args[0])
			return 2
		}
		docs = one
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"sources": docs, "docs_url": rulecheck.DocsURL})
		return 0
	}
	fmt.Printf(i18n.T(l, "rules.sources_header")+"\n", len(docs))
	for _, d := range docs {
		fmt.Printf("\n"+i18n.T(l, "rules.source_line")+"\n", d.Name, d.Label, d.Category, platformNames(d.Platforms), d.Rules)
		if len(args) == 0 {
			var names []string
			for _, f := range d.Fields {
				names = append(names, f.Name)
			}
			fmt.Printf("  %s\n", strings.Join(names, ", "))
			continue
		}
		fmt.Println("  " + i18n.T(l, "rules.fields"))
		for _, f := range d.Fields {
			ex := ""
			if f.Example != "" {
				ex = "  e.g. " + f.Example
			}
			fmt.Printf("    %-28s %-7s %s%s\n", f.Name, f.Type, f.Desc, ex)
		}
	}
	return 0
}

func platformNames(ps []string) string {
	name := map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"}
	var out []string
	for _, p := range ps {
		out = append(out, name[p])
	}
	return strings.Join(out, ", ")
}

var ruleID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func runRulesNew(l string, rs []*engine.Rule, args []string, o rulesOpts) int {
	t := func(k string) string { return i18n.T(l, k) }
	if len(args) != 1 || o.Source == "" {
		fmt.Fprintln(os.Stderr, t("rules.new_usage"))
		return 2
	}
	id := args[0]
	if !ruleID.MatchString(id) {
		fmt.Fprintf(os.Stderr, t("rules.bad_id")+"\n", id)
		return 2
	}
	for _, r := range rs {
		if r.ID == id {
			fmt.Fprintf(os.Stderr, t("rules.builtin_id")+"\n", id)
			return 2
		}
	}
	info, ok := source.Schema[o.Source]
	if !ok {
		fmt.Fprintf(os.Stderr, t("rules.unknown_source")+"\n", o.Source)
		return 2
	}
	switch o.Severity {
	case "critical", "high", "medium", "low":
	default:
		fmt.Fprintf(os.Stderr, t("rules.bad_severity")+"\n", o.Severity)
		return 2
	}
	plats := info.Platforms
	if o.Platforms != "" {
		plats = nil
		for _, p := range strings.Split(o.Platforms, ",") {
			p = strings.TrimSpace(p)
			if !contains(info.Platforms, p) {
				fmt.Fprintf(os.Stderr, t("rules.bad_platform")+"\n", o.Source, p, strings.Join(info.Platforms, ", "))
				return 2
			}
			plats = append(plats, p)
		}
	}
	data := Skeleton(id, o.Source, o.Severity, plats, rulecheck.Examples(rs)[o.Source])
	path := filepath.Join(o.Dir, id+".yaml")
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		fmt.Fprintf(os.Stderr, t("rules.exists")+"\n", path)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf(t("rules.created")+"\n", path, path)
	return 0
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Skeleton is a new rule file: every field, TODO texts in en and vi, and
// two tests built from the source schema (one reported, one not).
func Skeleton(id, src, severity string, platforms []string, examples map[string]any) []byte {
	info := source.Schema[src]
	// match on the first boolean field, so the skeleton's tests already run;
	// the author replaces it with the real condition.
	var key source.Field
	for _, f := range info.Fields {
		if f.Type == "bool" {
			key = f
			break
		}
	}
	match := "item." + key.Name
	if key.Name == "" && len(info.Fields) > 0 {
		key = info.Fields[0]
		match = fmt.Sprintf("item.%s != %s", key.Name, zero(key.Type))
	}
	sample := func(report bool) string {
		var parts []string
		for _, f := range info.Fields {
			v := ""
			switch {
			case f.Name == key.Name && f.Type == "bool":
				v = strconv.FormatBool(report)
			case f.Name == key.Name && !report:
				v = zero(f.Type)
			case f.Type == "bool":
				v = "false"
			default:
				if ex, ok := examples[f.Name]; ok && rulecheck.Show(ex) != `""` {
					v = rulecheck.Show(ex)
				} else if f.Type == "number" {
					v = "1"
				} else {
					v = `"example"`
				}
			}
			parts = append(parts, f.Name+": "+v)
		}
		return fmt.Sprintf("  - {item: {%s}, expect: %t}", strings.Join(parts, ", "), report)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# New rule: fill in every TODO, then run
#   security-warden rules check <this file> --new
# Fields of this source: security-warden rules sources %[2]s
# Guide: %[3]s
id: %[1]s
severity: %[4]s
# New rules start as experimental: they run only with --experimental until a
# maintainer reviews them and promotes them to community.
tier: experimental
platforms: [%[5]s]
source: %[2]s
# CEL over item; true means "report this item". TODO: the real condition.
# A missing field is an error: guard optional ones with has(item.x).
match: %[6]s
title:
  en: "TODO: the problem in one line, usually ending with the place"
  vi: "TODO: vấn đề trong một dòng, thường kết thúc bằng nơi bị"
check:
  en: "TODO: the check stated positively, no placeholders"
  vi: "TODO: điều được kiểm tra, nói theo hướng đạt"
explain:
  en: "TODO: why it matters, in plain words"
  vi: "TODO: vì sao quan trọng, nói dễ hiểu"
fix:
  en: "TODO: how to fix it. Commands in backticks, steps as 1. 2. 3., say when admin rights are needed"
  vi: "TODO: cách sửa. Lệnh đặt trong dấu backtick, các bước 1. 2. 3., nói rõ khi cần quyền quản trị"
references:
  - "TODO: a link that backs the rule up"
author: "TODO: your name or handle"
# Every sample needs every field the match and the texts use. TODO: make
# them real: one place that must be reported, one that must not.
tests:
%[7]s
%[8]s
`, id, src, rulecheck.DocsURL, severity, strings.Join(platforms, ", "), match, sample(true), sample(false))
	return []byte(b.String())
}

func zero(typ string) string {
	switch typ {
	case "number":
		return "0"
	case "bool":
		return "false"
	}
	return `""`
}

func runRulesCheck(l string, files []string, o rulesOpts) int {
	t := func(k string) string { return i18n.T(l, k) }
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, t("rules.check_usage"))
		return 2
	}
	type report struct {
		OK       bool               `json:"ok"`
		Errors   int                `json:"errors"`
		Warnings int                `json:"warnings"`
		Flagged  bool               `json:"flagged_commands"`
		Files    []rulecheck.Result `json:"files"`
	}
	rep := report{OK: true, Files: []rulecheck.Result{}}
	for _, f := range files {
		data, err := os.ReadFile(f)
		var res rulecheck.Result
		if err != nil {
			res = rulecheck.Result{File: f, Errors: []rulecheck.Issue{{Code: "read", Message: err.Error()}}, Warnings: []rulecheck.Issue{}}
		} else {
			res = rulecheck.Check(f, data, rulecheck.Options{Lang: l, New: o.New})
		}
		rep.Errors += len(res.Errors)
		rep.Warnings += len(res.Warnings)
		rep.Flagged = rep.Flagged || res.Flagged()
		rep.OK = rep.OK && res.OK(o.Strict)
		rep.Files = append(rep.Files, res)
	}
	if o.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		for _, r := range rep.Files {
			switch {
			case len(r.Errors) > 0:
				fmt.Printf(t("rules.check_fail")+"\n", r.File, len(r.Errors), len(r.Warnings), r.Tests.Passed, r.Tests.Total)
			case len(r.Warnings) > 0:
				fmt.Printf(t("rules.check_warn")+"\n", r.File, len(r.Warnings), r.Tests.Passed, r.Tests.Total)
			default:
				fmt.Printf(t("rules.check_ok")+"\n", r.File, r.Tests.Passed, r.Tests.Total)
			}
			for _, e := range r.Errors {
				fmt.Printf(t("rules.check_error")+"\n", where(r.File, e.Field), e.Message)
			}
			for _, w := range r.Warnings {
				fmt.Printf(t("rules.check_warning")+"\n", where(r.File, w.Field), w.Message)
			}
		}
		if len(rep.Files) > 1 {
			fmt.Printf("\n"+t("rules.check_summary")+"\n", len(rep.Files), rep.Errors, rep.Warnings)
		}
		if rep.Flagged {
			fmt.Println(t("rules.check_flagged"))
		}
		if o.Strict && rep.Errors == 0 && rep.Warnings > 0 {
			fmt.Println(t("rules.check_strict"))
		}
	}
	if !rep.OK {
		return 1
	}
	return 0
}

// where names a field of a file: rules/x.yaml:fix.en
func where(file, field string) string {
	if field == "" {
		return file
	}
	return file + ":" + field
}
