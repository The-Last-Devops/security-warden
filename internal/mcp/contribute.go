package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/feedback"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/rulecheck"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Contributing: links the user opens, never requests this server sends.

const reportHint = "\nIf something here looks wrong or missing, you can offer the user to report it (report_false_positive / suggest_rule)."

// hintOnce returns the "report it" line the first time per session.
func (s *Server) hintOnce() string {
	if s.hinted.CompareAndSwap(false, true) {
		return reportHint
	}
	return ""
}

const draftInstructions = "Show the preview to the user and let them open the link (and edit or submit it on GitHub) themselves; do not open or submit it yourself. Nothing has been sent."

func (s *Server) info() feedback.Info {
	p := runtime.GOOS
	if p == "darwin" {
		p = "macos"
	}
	return feedback.Info{Version: s.cfg.Version, Platform: p, Via: "mcp"}
}

func draftResult(d feedback.Draft) (any, string) {
	out := map[string]any{"preview": d.Preview, "url": d.URL, "title": d.Title, "shortened": d.Shortened, "instructions": draftInstructions}
	text := "Preview (exactly what the link fills in; identifying details already taken out):\n" + d.Preview + "\n\nLink: " + d.URL + "\n\n" + draftInstructions
	return out, text
}

func (s *Server) toolReportFalsePositive(ctx context.Context, a args) (any, string, error) {
	key, err := a.str("key")
	if err != nil {
		return nil, "", err
	}
	id, err := a.str("rule_id")
	if err != nil {
		return nil, "", err
	}
	if (key == "") == (id == "") {
		return nil, "", fail("give key or rule_id (one of them)")
	}
	exp, err := a.boolean("experimental")
	if err != nil {
		return nil, "", err
	}
	target := key + id
	if id != "" && s.rule(id) == nil {
		return nil, "", fail("unknown rule %q", clip(id, 80))
	}
	// English: the issue tracker's language.
	sc, _, _, err := s.scan(ctx, "en", false, exp || id != "" && s.rule(id).Tier == "experimental")
	if err != nil {
		return nil, "", err
	}
	scrub := feedback.NewScrubber(feedback.DefaultEnv())
	pick, perr := ignore.Pick(append(append([]engine.Finding(nil), sc.Findings...), sc.Ignored...), target)
	var d feedback.Draft
	switch {
	case perr == nil:
		d = feedback.FalsePositive(pick[0], s.rule(pick[0].RuleID), s.info(), scrub)
	case id != "":
		d = feedback.ForRule(s.rule(id), s.info(), scrub)
	case perr == ignore.ErrAmbiguous:
		return nil, "", fail("key %q matches more than one place: give more characters", clip(key, 40))
	default:
		return nil, "", fail("no current finding has key %q (see list_problems)", clip(key, 40))
	}
	out, text := draftResult(d)
	return out, text, nil
}

func (s *Server) toolSuggestRule(_ context.Context, a args) (any, string, error) {
	idea, err := a.str("idea")
	if err != nil {
		return nil, "", err
	}
	if len(idea) > feedback.MaxIdea {
		return nil, "", fail("idea is too long (%d bytes, at most %d)", len(idea), feedback.MaxIdea)
	}
	d, err := feedback.Idea(idea, s.info(), feedback.NewScrubber(feedback.DefaultEnv()))
	if err != nil {
		return nil, "", fail("idea is empty: say what should be checked and why")
	}
	out, text := draftResult(d)
	return out, text, nil
}

func (s *Server) toolReportBug(_ context.Context, a args) (any, string, error) {
	what, err := a.str("what")
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(what) == "" {
		return nil, "", fail("what is empty: say what happened")
	}
	if len(what) > feedback.MaxIdea {
		return nil, "", fail("what is too long (%d bytes, at most %d)", len(what), feedback.MaxIdea)
	}
	withLog := true // attached unless include_log is false
	if _, given := a["include_log"]; given {
		if withLog, err = a.boolean("include_log"); err != nil {
			return nil, "", err
		}
	}
	log := ""
	if withLog {
		log, _ = source.ReadLog()
	}
	out, text := draftResult(feedback.Bug(what, log, s.info(), feedback.NewScrubber(feedback.DefaultEnv())))
	return out, text, nil
}

var kebab = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func (s *Server) toolDraftRule(_ context.Context, a args) (any, string, error) {
	id, err := a.str("id")
	if err != nil {
		return nil, "", err
	}
	src, err := a.str("source")
	if err != nil {
		return nil, "", err
	}
	sev, err := a.oneOf("severity", []string{"critical", "high", "medium", "low"})
	if err != nil {
		return nil, "", err
	}
	if sev == "" {
		sev = "medium"
	}
	idea, err := a.str("idea")
	if err != nil {
		return nil, "", err
	}
	if !kebab.MatchString(id) || len(id) > 80 {
		return nil, "", fail("id must be kebab-case (lower case letters, digits and single hyphens), e.g. npmrc-token-plaintext")
	}
	if s.rule(id) != nil {
		return nil, "", fail("%s is already a built-in rule: pick another id, or change that rule's file", id)
	}
	info, ok := source.Schema[src]
	if !ok {
		return nil, "", fail("unknown source %q (see list_sources)", clip(src, 80))
	}
	y := string(rulecheck.Skeleton(id, src, sev, info.Platforms, rulecheck.Examples(s.cfg.Rules)[src]))
	if idea != "" {
		var c strings.Builder
		for _, l := range strings.Split(clip(engine.Clean(strings.ReplaceAll(idea, "\n", " ")), 600), ". ") {
			c.WriteString("# Idea: " + strings.TrimSpace(l) + "\n")
		}
		y = c.String() + y
	}
	path := "rules/" + id + ".yaml"
	steps := []string{
		"Fill in every TODO: match (CEL over item), title/check/explain/fix in en and vi, references, author (the user's GitHub handle, without @), and realistic tests.",
		"Call check_rule with the YAML and new=true until it reports no errors and no warnings.",
		"Ask the user before writing " + path + " in their fork of github.com/" + feedback.Repo + "; then they run `security-warden rules check --strict --new " + path + "`.",
		"The user opens a pull request with only that file (and regenerated docs), ticks the AI box and names the tool and model. Merging is always done by a maintainer, by hand.",
	}
	out := map[string]any{"yaml": y, "path": path, "next_steps": steps, "docs_url": rulecheck.DocsURL}
	text := "Skeleton for " + path + " (nothing was written):\n\n" + y + "\nNext:\n"
	for i, st := range steps {
		text += fmt.Sprintf("%d. %s\n", i+1, st)
	}
	return out, strings.TrimRight(text, "\n"), nil
}

// Prompts: ready-made instructions an MCP client offers its user.

type promptArg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type prompt struct {
	Name        string      `json:"name"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Arguments   []promptArg `json:"arguments"`
	text        func(args map[string]string) string
}

var prompts = []prompt{
	{
		Name:        "security-checkup",
		Title:       "Security checkup",
		Description: "Scan this machine and its code folders, summarize what is wrong, and propose fixes, asking before any change.",
		Arguments:   []promptArg{{Name: "scope", Description: "machine or code (default: both)"}},
		text: func(a map[string]string) string {
			scope := ""
			if a["scope"] == "machine" || a["scope"] == "code" {
				scope = fmt.Sprintf(" with scope %q", a["scope"])
			}
			return "Give me a security checkup of this machine with Security Warden.\n\n" +
				"1. Call scan" + scope + ". It only reads: no admin rights, nothing leaves the machine.\n" +
				"2. Summarize: the scores (machine, code), then the problems grouped by rule, most severe first, with how many places each has. Keep paths as given; do not invent values.\n" +
				"3. For the most severe problems, call get_fix and explain the steps in plain words. For leaked keys or tokens, say first that the credential must be revoked or rotated; deleting the file is not enough.\n" +
				"4. Propose what to fix, in order. Do not run any command, apply a fix or hide anything until I say yes to that exact change.\n" +
				"5. After changes, scan again (refresh=true) and tell me what improved.\n" +
				"If a finding looks wrong to me, or I think a check is missing, offer report_false_positive or suggest_rule: show me the preview and let me open the link myself."
		},
	},
	{
		Name:        "contribute-rule",
		Title:       "Contribute a new rule",
		Description: "Write a new Security Warden rule with the user: find the facts, start the file, check it, and prepare a pull request the maintainers review by hand.",
		Arguments:   []promptArg{{Name: "idea", Description: "What the rule should catch"}},
		text: func(a map[string]string) string {
			idea := strings.TrimSpace(a["idea"])
			if idea != "" {
				idea = "The idea: " + clip(engine.Clean(idea), 1000) + "\n\n"
			} else {
				idea = "First ask me what risky state the rule should find.\n\n"
			}
			return "Help me contribute a rule to Security Warden (github.com/" + feedback.Repo + ").\n\n" + idea +
				"1. Make sure no rule covers it yet (scan, explain_rule, or `security-warden rules`). Find the facts with list_sources (`security-warden rules sources NAME`). If no source has them, stop: the rule needs a code change; offer suggest_rule instead.\n" +
				"2. Start the file with draft_rule (`security-warden rules new ID --source NAME`). Fill in every TODO: match is CEL over item, true only for the risky state; title, check, explain and fix in English and natural Vietnamese; references; author is my GitHub handle; tests with one place that must be reported and one that must not. Keep tier: experimental.\n" +
				"3. Fix text is what people paste into a terminal: verified commands in backticks, numbered steps, nothing destructive, say when admin rights are needed.\n" +
				"4. Call check_rule with new=true (`security-warden rules check --strict --new rules/ID.yaml`) until it passes with no errors and no warnings.\n" +
				"5. Ask me before writing any file. Then I open a pull request from my fork with only the rule file (and regenerated docs). Say in the PR that an AI agent wrote it, with the tool and model. A maintainer reviews and merges by hand; nothing is merged automatically.\n" +
				"Guide: " + rulecheck.DocsURL
		},
	},
}

func (s *Server) promptList() []prompt { return prompts }

func (s *Server) getPrompt(params map[string]json.RawMessage) (map[string]any, *rpcError) {
	var name string
	_ = json.Unmarshal(params["name"], &name)
	for _, p := range prompts {
		if p.Name != name {
			continue
		}
		args := map[string]string{}
		if raw, ok := params["arguments"]; ok && string(raw) != "null" {
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				return nil, &rpcError{Code: codeInvalidParams, Message: "arguments must be an object"}
			}
			for k, v := range m {
				if sv, ok := v.(string); ok {
					args[k] = sv
				}
			}
		}
		return map[string]any{
			"description": p.Description,
			"messages":    []any{map[string]any{"role": "user", "content": map[string]any{"type": "text", "text": p.text(args)}}},
		}, nil
	}
	return nil, &rpcError{Code: codeInvalidParams, Message: "unknown prompt: " + clip(name, 80)}
}
