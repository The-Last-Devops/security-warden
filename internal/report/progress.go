package report

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/i18n"
)

// Progress draws one live line while sources run, then erases it. It does
// nothing when w is not a terminal, so pipes and CI logs stay clean.
type Progress struct {
	w       io.Writer
	lang    string
	on      bool
	mu      sync.Mutex
	pending []string
	total   int
	stop    chan struct{}
	done    chan struct{}
}

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// StartProgress begins drawing for the given source names.
func StartProgress(w io.Writer, lang string, names []string) *Progress {
	p := &Progress{w: w, lang: lang, on: IsTerminal(w), pending: append([]string(nil), names...),
		total: len(names), stop: make(chan struct{}), done: make(chan struct{})}
	if !p.on {
		close(p.done)
		return p
	}
	go p.loop()
	return p
}

// Done marks one source as finished.
func (p *Progress) Done(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, n := range p.pending {
		if n == name {
			p.pending = append(p.pending[:i], p.pending[i+1:]...)
			return
		}
	}
}

// Stop erases the line.
func (p *Progress) Stop() {
	if !p.on {
		return
	}
	close(p.stop)
	<-p.done
}

func (p *Progress) loop() {
	defer close(p.done)
	tick := time.NewTicker(80 * time.Millisecond)
	defer tick.Stop()
	for i := 0; ; i++ {
		p.mu.Lock()
		var names []string
		for _, n := range p.pending {
			names = append(names, i18n.T(p.lang, "source."+n))
		}
		left := len(p.pending)
		p.mu.Unlock()
		line := fmt.Sprintf("  \033[33m%s\033[0m %s \033[2m%s (%d/%d)\033[0m",
			frames[i%len(frames)], i18n.T(p.lang, "report.progress"), strings.Join(names, ", "), p.total-left, p.total)
		fmt.Fprintf(p.w, "\r\033[K%s", truncate(line, 160))
		select {
		case <-p.stop:
			fmt.Fprint(p.w, "\r\033[K")
			return
		case <-tick.C:
		}
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…\033[0m"
}
