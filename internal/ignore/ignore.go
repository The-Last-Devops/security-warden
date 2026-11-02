// Package ignore keeps the findings a person chose to snooze, for a while
// or for good. An entry names one finding (rule + the facts it matched),
// never a whole rule, so a new problem of the same kind still shows.
package ignore

import (
	"encoding/json"
	"errors"
	"github.com/The-Last-Devops/security-warden/internal/appdir"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

// MaxHide is the longest any finding may be hidden: nothing is hidden for
// good, so a forgotten problem always comes back.
const MaxHide = 30 * 24 * time.Hour

// Entry is one snoozed finding.
type Entry struct {
	ID       string    `json:"id"`
	RuleID   string    `json:"rule_id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Created  time.Time `json:"created"`
	Until    time.Time `json:"until,omitempty"` // zero: for good
}

// Active reports whether the entry still applies at t.
// Active: still hidden at t. Old "for good" entries (no Until) last
// MaxHide from when they were made.
func (e Entry) Active(t time.Time) bool {
	until := e.Until
	if until.IsZero() {
		until = e.Created.Add(MaxHide)
	}
	return t.Before(until)
}

// Store is the ignore list on disk (ignores.json, 0600).
type Store struct {
	Path string
	mu   sync.Mutex
}

// Default returns the store in the user's config folder.
func Default() *Store {
	return &Store{Path: appdir.File("ignores.json")}
}

func (s *Store) readLocked() ([]Entry, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, err
	}
	return es, nil
}

func (s *Store) writeLocked(es []Entry) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(es, "", "  ")
	tmp := s.Path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// List returns the entries that still apply, dropping expired ones.
func (s *Store) List(now time.Time) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	es, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	var keep []Entry
	for _, e := range es {
		if e.Active(now) {
			keep = append(keep, e)
		}
	}
	if len(keep) != len(es) {
		_ = s.writeLocked(keep)
	}
	return keep, nil
}

// Add hides findings for d, at most MaxHide (0 or longer means MaxHide).
func (s *Store) Add(fs []engine.Finding, d time.Duration, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	es, err := s.readLocked()
	if err != nil {
		return err
	}
	byID := map[string]int{}
	for i, e := range es {
		byID[e.ID] = i
	}
	for _, f := range fs {
		dd := d
		if dd <= 0 || dd > MaxHide {
			dd = MaxHide
		}
		e := Entry{ID: engine.FindingID(f), RuleID: f.RuleID, Title: f.Title, Severity: f.Severity, Created: now}
		e.Until = now.Add(dd)
		if i, ok := byID[e.ID]; ok {
			es[i] = e
		} else {
			es = append(es, e)
		}
	}
	return s.writeLocked(es)
}

// Remove un-snoozes entries by id; no ids clears the whole list.
func (s *Store) Remove(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(ids) == 0 {
		return s.writeLocked(nil)
	}
	es, err := s.readLocked()
	if err != nil {
		return err
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	var keep []Entry
	for _, e := range es {
		if !drop[e.ID] {
			keep = append(keep, e)
		}
	}
	return s.writeLocked(keep)
}

// Split separates findings that are snoozed from the ones to show.
func Split(fs []engine.Finding, es []Entry, now time.Time) (shown, ignored []engine.Finding) {
	active := map[string]bool{}
	for _, e := range es {
		if e.Active(now) {
			active[e.ID] = true
		}
	}
	for _, f := range fs {
		if active[engine.FindingID(f)] {
			ignored = append(ignored, f)
		} else {
			shown = append(shown, f)
		}
	}
	return shown, ignored
}
