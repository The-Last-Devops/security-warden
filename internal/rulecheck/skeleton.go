package rulecheck

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/source"
)

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
				if ex, ok := examples[f.Name]; ok && Show(ex) != `""` {
					v = Show(ex)
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
author: "TODO: your GitHub handle, without @"
# Every sample needs every field the match and the texts use. TODO: make
# them real: one place that must be reported, one that must not.
tests:
%[7]s
%[8]s
`, id, src, DocsURL, severity, strings.Join(platforms, ", "), match, sample(true), sample(false))
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
