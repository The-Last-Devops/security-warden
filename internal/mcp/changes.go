package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
)

// The changing tools. They are only listed and accepted with AllowChanges,
// and each result says exactly what changed.

func (a args) strings(k string) ([]string, error) {
	raw, ok := a[k]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil || len(v) > 500 {
		return nil, fail("%s must be a list of at most 500 strings", k)
	}
	return v, nil
}

// target reads rule_id or key (exactly one of them).
func (a args) target() (string, error) {
	id, err := a.str("rule_id")
	if err != nil {
		return "", err
	}
	key, err := a.str("key")
	if err != nil {
		return "", err
	}
	switch {
	case id != "" && key != "":
		return "", fail("give rule_id or key, not both")
	case id == "" && key == "":
		return "", fail("give rule_id or key")
	case key != "" && len(key) < ignore.MinKey:
		return "", fail("key must have at least %d characters", ignore.MinKey)
	}
	return id + key, nil
}

func pickErr(err error, target string) error {
	switch {
	case errors.Is(err, ignore.ErrAmbiguous):
		return fail("%q matches more than one place: use a longer key", clip(target, 80))
	case errors.Is(err, ignore.ErrNoMatch):
		return fail("%q matches no problem in the latest scan", clip(target, 80))
	}
	return err
}

type changed struct {
	Key      string   `json:"key"`
	RuleID   string   `json:"rule_id"`
	Place    string   `json:"place"`
	Action   string   `json:"action,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Undoable bool     `json:"undoable,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

func (s *Server) toolApplyFix(ctx context.Context, a args) (any, string, error) {
	id, err := a.str("rule_id")
	if err != nil {
		return nil, "", err
	}
	keys, err := a.strings("keys")
	if err != nil {
		return nil, "", err
	}
	if id == "" && len(keys) == 0 {
		return nil, "", fail("give rule_id and/or keys: apply_fix never fixes everything at once")
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	sc, _, _, err := s.scan(ctx, i18n.Default, false, true)
	if err != nil {
		return nil, "", err
	}
	var pick []engine.Finding
	seen := map[string]bool{}
	add := func(fs []engine.Finding) {
		for _, f := range fs {
			if k := engine.FindingID(f); !seen[k] {
				seen[k] = true
				pick = append(pick, f)
			}
		}
	}
	if id != "" {
		if s.rule(id) == nil {
			return nil, "", fail("unknown rule %q", clip(id, 80))
		}
		fs, err := ignore.Pick(sc.Findings, id)
		if err != nil {
			return nil, "", fail("%s does not fail in the latest scan: nothing to fix", id)
		}
		add(fs)
	}
	for _, k := range keys {
		if len(k) < ignore.MinKey {
			return nil, "", fail("key %q is too short (at least %d characters)", clip(k, 40), ignore.MinKey)
		}
		fs, err := ignore.Pick(sc.Findings, k)
		if err != nil {
			return nil, "", pickErr(err, k)
		}
		add(fs)
	}

	batch := fix.NewBatch()
	applied, refused, failed := []changed{}, []changed{}, []changed{}
	for _, f := range pick {
		c := changed{Key: engine.FindingID(f), RuleID: f.RuleID, Place: report.PlaceOf(f)}
		if f.Remedy == nil {
			c.Reason = "no built-in fix: follow the steps from get_fix"
			refused = append(refused, c)
			continue
		}
		act, ok := fix.Get(f.Remedy.Action)
		if !ok {
			c.Reason = "unknown fix action"
			refused = append(refused, c)
			continue
		}
		c.Action, c.Commands, c.Undoable = act.ID, report.Plan(f), act.Undoable
		if act.NeedsRoot {
			c.Reason = "needs admin rights (a password prompt): the user runs `security-warden fix` in a terminal"
			refused = append(refused, c)
			continue
		}
		if err := ctx.Err(); err != nil {
			c.Reason = "cancelled before it ran"
			failed = append(failed, c)
			continue
		}
		if err := s.cfg.Apply(batch, f.RuleID, f.Remedy.Action, f.Remedy.Params); err != nil {
			c.Reason = clean(err.Error())
			failed = append(failed, c)
			continue
		}
		s.logf("applied %s (%s) for %s", act.ID, f.RuleID, c.Key[:8])
		applied = append(applied, c)
	}
	if len(applied) > 0 {
		s.forget()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Applied %d fix(es), refused %d, failed %d.", len(applied), len(refused), len(failed))
	for _, c := range applied {
		fmt.Fprintf(&b, "\n✓ %s · %s", c.RuleID, c.Place)
		for _, cmd := range c.Commands {
			fmt.Fprintf(&b, "\n   ran: %s", cmd)
		}
		if !c.Undoable {
			b.WriteString("\n   (cannot be undone)")
		}
	}
	for _, c := range refused {
		fmt.Fprintf(&b, "\n– %s · %s: %s", c.RuleID, c.Place, c.Reason)
	}
	for _, c := range failed {
		fmt.Fprintf(&b, "\n✗ %s · %s: %s", c.RuleID, c.Place, c.Reason)
	}
	undoable := false
	for _, c := range applied {
		undoable = undoable || c.Undoable
	}
	if undoable {
		b.WriteString("\nundo_fix (or `security-warden fix --undo`) reverts this batch. Scan again to confirm.")
	}
	return map[string]any{"batch": batch, "applied": applied, "refused": refused, "failed": failed}, b.String(), nil
}

func (s *Server) toolUndoFix(context.Context, args) (any, string, error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	done, err := s.cfg.Undo()
	type undone struct {
		RuleID string `json:"rule_id"`
		Action string `json:"action"`
		Batch  string `json:"batch"`
	}
	out := []undone{}
	for _, e := range done {
		out = append(out, undone{e.RuleID, e.Action, e.Batch})
	}
	if len(done) > 0 {
		s.forget()
	}
	res := map[string]any{"undone": out}
	var b strings.Builder
	if len(done) == 0 && err == nil {
		b.WriteString("Nothing to undo.")
	} else {
		fmt.Fprintf(&b, "Reverted %d change(s):", len(done))
		for _, u := range out {
			fmt.Fprintf(&b, "\n↩ %s (%s)", u.RuleID, u.Action)
		}
	}
	if err != nil {
		res["error"] = clean(err.Error())
		fmt.Fprintf(&b, "\nSome changes could not be reverted: %s", clean(err.Error()))
	}
	return res, b.String(), nil
}

func (s *Server) toolHide(ctx context.Context, a args) (any, string, error) {
	target, err := a.target()
	if err != nil {
		return nil, "", err
	}
	days, err := a.integer("days", 0)
	if err != nil {
		return nil, "", err
	}
	if days != 1 && days != 7 && days != 30 {
		return nil, "", fail("days must be 1, 7 or 30")
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	sc, _, _, err := s.scan(ctx, i18n.Default, false, true)
	if err != nil {
		return nil, "", err
	}
	pick, err := ignore.Pick(append(append([]engine.Finding(nil), sc.Findings...), sc.Ignored...), target)
	if err != nil {
		return nil, "", pickErr(err, target)
	}
	now := s.cfg.Now()
	until := now.Add(time.Duration(days) * 24 * time.Hour)
	if err := s.cfg.Ignore.Add(pick, time.Duration(days)*24*time.Hour, now); err != nil {
		return nil, "", err
	}
	hidden := []changed{}
	for _, f := range pick {
		hidden = append(hidden, changed{Key: engine.FindingID(f), RuleID: f.RuleID, Place: report.PlaceOf(f)})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Hid %d place(s) until %s:", len(hidden), until.UTC().Format(time.RFC3339))
	for _, h := range hidden {
		fmt.Fprintf(&b, "\n- %s · %s · key %s", h.RuleID, h.Place, h.Key[:8])
	}
	b.WriteString("\nrestore shows them again sooner.")
	return map[string]any{"hidden": hidden, "until": until.UTC().Format(time.RFC3339), "days": days}, b.String(), nil
}

func (s *Server) toolRestore(_ context.Context, a args) (any, string, error) {
	all, err := a.boolean("all")
	if err != nil {
		return nil, "", err
	}
	target := "all"
	if !all {
		if target, err = a.target(); err != nil {
			return nil, "", fail("give rule_id, key or all=true")
		}
	} else if v, _ := a.str("rule_id"); v != "" {
		return nil, "", fail("give rule_id, key or all=true, not several")
	} else if v, _ := a.str("key"); v != "" {
		return nil, "", fail("give rule_id, key or all=true, not several")
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	es, err := s.cfg.Ignore.List(s.cfg.Now())
	if err != nil {
		return nil, "", err
	}
	ids := ignore.RestoreIDs(es, target)
	if len(ids) == 0 {
		return nil, "", fail("nothing hidden matches %q", clip(target, 80))
	}
	if err := s.cfg.Ignore.Remove(ids); err != nil {
		return nil, "", err
	}
	byID := map[string]ignore.Entry{}
	for _, e := range es {
		byID[e.ID] = e
	}
	type shown struct {
		Key    string `json:"key"`
		RuleID string `json:"rule_id"`
		Title  string `json:"title"`
	}
	out := []shown{}
	var b strings.Builder
	fmt.Fprintf(&b, "Showing %d hidden place(s) again:", len(ids))
	for _, id := range ids {
		e := byID[id]
		out = append(out, shown{id, e.RuleID, clean(e.Title)})
		fmt.Fprintf(&b, "\n- %s · %s", e.RuleID, clean(e.Title))
	}
	return map[string]any{"restored": out}, b.String(), nil
}
