package report

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
)

// Width is the line length the report keeps to.
const Width = 80

// listMax is how many places a problem lists before "+N more".
const listMax = 5

// wrapText breaks s into lines of at most width runes, on spaces. A word
// longer than width stays whole (paths and commands must stay copyable).
func wrapText(s string, width int) []string {
	var lines []string
	var cur strings.Builder
	n := 0
	for _, w := range strings.Fields(s) {
		k := utf8.RuneCountInString(w)
		if n > 0 && n+1+k > width {
			lines = append(lines, cur.String())
			cur.Reset()
			n = 0
		}
		if n > 0 {
			cur.WriteByte(' ')
			n++
		}
		cur.WriteString(w)
		n += k
	}
	if n > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// printer writes lines behind a colored rail, wrapped to Width.
type printer struct {
	w    io.Writer
	c    style
	rail string // "" for none
}

func (p printer) line(indent int, s string) {
	fmt.Fprintf(p.w, "  %s%s%s\n", p.rail, strings.Repeat(" ", indent), s)
}

// text wraps prose; first and rest prefix the first and following lines
// (a step number, then the same width of spaces).
func (p printer) text(indent int, first, rest, s string, color func(string) string) {
	if color == nil {
		color = func(x string) string { return x }
	}
	width := Width - 2 - utf8.RuneCountInString(stripANSI(p.rail)) - indent - utf8.RuneCountInString(stripANSI(first))
	for i, l := range wrapText(s, max(width, 20)) {
		pre := rest
		if i == 0 {
			pre = first
		}
		p.line(indent, pre+color(l))
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// steps prints a fix text: numbered steps on their own lines, commands on
// their own line after "$ ", short code inline. hide holds the commands
// listed per place below; they become a pointer.
func (p printer) steps(indent int, fix string, hide map[string]bool, seeBelow string) {
	steps := ParseSteps(Tilde(engine.Clean(fix)))
	for i, parts := range steps {
		num := p.c.wrap(green, "→ ")
		if len(steps) > 1 {
			num = p.c.bold(fmt.Sprintf("%d. ", i+1))
			if i+1 < 10 && len(steps) >= 10 {
				num += " "
			}
		}
		numW := utf8.RuneCountInString(stripANSI(num))
		blank := strings.Repeat(" ", numW)
		first := true
		var buf strings.Builder
		flush := func() {
			s := strings.TrimSpace(buf.String())
			buf.Reset()
			if s == "" {
				return
			}
			pre := blank
			if first {
				pre, first = num, false
			}
			p.text(indent, pre, blank, s, nil)
		}
		for j := 0; j < len(parts); j++ {
			part := parts[j]
			switch {
			case !part.IsCode:
				buf.WriteString(part.Text)
			case !IsBlock(part.Code):
				buf.WriteString(part.Code)
			case hide[part.Code]:
				buf.WriteString(seeBelow)
			default:
				// "(`cmd`)" or "`cmd`." : the brackets and the full stop
				// mean nothing once the command has its own line.
				if j+1 < len(parts) && !parts[j+1].IsCode {
					next := parts[j+1].Text
					if t := strings.TrimRight(buf.String(), " "); strings.HasSuffix(t, "(") && strings.HasPrefix(next, ")") {
						buf.Reset()
						buf.WriteString(strings.TrimSuffix(t, "("))
						next = next[1:]
					}
					next = leadPunct.ReplaceAllString(next, "")
					parts[j+1].Text = next
				}
				if first && strings.TrimSpace(buf.String()) == "" {
					// A step that starts with a command: on the number's line.
					buf.Reset()
					p.line(indent, num+strings.TrimLeft(prompt(p.c, part.Code), " "))
					first = false
					continue
				}
				flush()
				p.command(indent+numW+2, part.Code)
			}
		}
		flush()
		if first {
			p.line(indent, num)
		}
	}
}

// leadPunct is punctuation left at the start of a text after a command.
var leadPunct = regexp.MustCompile(`^\s*[.,;:]+(\s+|$)`)

// command prints one command on its own line, never wrapped.
// A long name without spaces (a path) is not something to run: no "$ ".
func (p printer) command(indent int, cmd string) {
	p.line(indent, prompt(p.c, cmd))
}

func prompt(c style, cmd string) string {
	if !strings.ContainsAny(cmd, " \t") {
		return "  " + c.wrap("1;36", cmd)
	}
	return c.dim("$ ") + c.wrap("1;36", cmd)
}

// FixText writes a fix text the way the report does (steps, commands on
// their own line), each line after prefix. For the fix command's list of
// manual steps.
func FixText(w io.Writer, fix, prefix string) {
	printer{w: w, c: style{on: IsTerminal(w)}, rail: prefix}.steps(0, fix, nil, "")
}

// Text writes the human report in s.Lang.
func Text(w io.Writer, s Scan, o Options) {
	t := func(k string) string { return i18n.T(s.Lang, k) }
	c := style{on: IsTerminal(w)}

	shield := "🛡  "
	if !c.on {
		shield = ""
	}
	fmt.Fprintf(w, "\n  %s%s %s\n\n", shield, c.bold("security-warden"),
		c.dim(fmt.Sprintf("%s · %s · %s", s.Version, s.Host, s.Time)))

	findings := o.Filter(s.Findings)

	// Score bar and counts, then the two parts on their own.
	n := map[string]int{}
	for _, f := range findings {
		n[f.Severity]++
	}
	scoreColor := func(v int) string {
		switch {
		case v < 50:
			return sevColor["high"]
		case v < 80:
			return sevColor["medium"]
		}
		return green
	}
	barColor := scoreColor(s.Score)
	filled := s.Score / 5
	bar := c.wrap(barColor, strings.Repeat("█", filled)) + c.dim(strings.Repeat("░", 20-filled))
	if !c.on {
		bar = "[" + strings.Repeat("#", filled) + strings.Repeat(".", 20-filled) + "]"
	}
	label := pad(t("report.score"), 12)
	fmt.Fprintf(w, "  %s  %s  %s%s\n", c.bold(label), bar, c.wrap(barColor+";1", fmt.Sprintf("%3d", s.Score)), c.dim("/100"))
	for _, sc := range []struct {
		key string
		v   int
	}{{"machine", s.ScoreMachine}, {"code", s.ScoreCode}} {
		f := sc.v / 5
		b := c.wrap(scoreColor(sc.v), strings.Repeat("▪", f)) + c.dim(strings.Repeat("·", 20-f))
		if !c.on {
			b = " " + strings.Repeat("#", f) + strings.Repeat(".", 20-f) + " "
		}
		fmt.Fprintf(w, "  %s  %s  %s%s\n", pad(t("scope."+sc.key), 12), b, c.wrap(scoreColor(sc.v), fmt.Sprintf("%3d", sc.v)), c.dim("/100"))
	}
	var counts []string
	for _, sev := range engine.Severities {
		if n[sev] > 0 && sev != "info" {
			counts = append(counts, c.wrap(sevColor[sev], fmt.Sprintf("● %d %s", n[sev], t("count."+sev))))
		}
	}
	if len(counts) > 0 {
		fmt.Fprintf(w, "  %s  %s\n", pad("", 12), strings.Join(counts, "  "))
	}
	fmt.Fprintln(w)
	if o.Scope != "" || o.Category != "" {
		var what []string
		if o.Scope != "" {
			what = append(what, t("scope."+o.Scope))
		}
		if o.Category != "" {
			what = append(what, t("cat."+o.Category))
		}
		fmt.Fprintf(w, "  %s\n\n", c.dim(fmt.Sprintf(t("report.showing"), strings.Join(what, " · "))))
	}

	if o.Safe {
		safeView(w, c, t, s, o)
	} else {
		if len(findings) == 0 {
			key := "report.none"
			if o.Scope != "" || o.Category != "" {
				key = "report.none_here"
			}
			fmt.Fprintf(w, "  %s %s\n\n", c.wrap(green, "✓"), c.bold(t(key)))
		}
		if o.ByRepo {
			for _, sec := range repoSections(findings, t("report.other_repos")) {
				name := sec.repo
				if name == "" {
					name = t("scope.machine")
				}
				fmt.Fprintf(w, "  %s %s %s\n\n", c.wrap("1;35", "■"), c.bold(name), c.dim(fmt.Sprintf("· %d", len(sec.groups))))
				for _, g := range sec.groups {
					writeGroup(w, c, t, g, o, true)
				}
			}
		} else {
			gs := Groups(findings)
			for _, sev := range engine.Severities {
				var these []Group
				for _, g := range gs {
					if g.All[0].Severity == sev {
						these = append(these, g)
					}
				}
				if len(these) == 0 {
					continue
				}
				pill := c.wrap(sevPill[sev], " "+t("severity."+sev)+" ")
				if !c.on {
					pill = "[" + t("severity."+sev) + "]"
				}
				line := strings.Repeat("─", max(4, Width-8-utf8.RuneCountInString(t("severity."+sev))-len(fmt.Sprint(len(these)))-5))
				fmt.Fprintf(w, "  %s %s %s\n\n", pill, c.dim(fmt.Sprintf("· %d", len(these))), c.wrap(sevColor[sev], line))
				for _, g := range these {
					writeGroup(w, c, t, g, o, false)
				}
			}
		}
	}

	// What passed, and what could not be checked.
	fmt.Fprintf(w, "  %s %s\n", c.wrap(green, "✓"), c.dim(fmt.Sprintf(t("report.passed"), len(s.Passed), s.Checked)))
	if o.Verbose && !o.Safe {
		for _, id := range s.Passed {
			fmt.Fprintf(w, "      %s\n", c.dim(id))
		}
	}
	for _, st := range s.Sources {
		switch {
		case st.Error != "":
			fmt.Fprintf(w, "  %s %s\n", c.wrap(sevColor["medium"], "!"), c.dim(t("source."+st.Name)+": "+fmt.Sprintf(t("source.error"), engine.Clean(st.Error))))
		case st.Skipped != "" && o.Verbose:
			fmt.Fprintf(w, "  %s %s\n", c.dim("–"), c.dim(t("source."+st.Name)+": "+t(st.Skipped)))
		}
	}
	if n := len(s.Ignored); n > 0 {
		fmt.Fprintf(w, "  %s\n", c.dim(fmt.Sprintf(t("report.ignored"), n)))
	}
	if len(findings) > 0 && !o.Safe {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.hide_hint")))
	}
	if !o.Verbose {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.more")))
	}
	if !o.Safe {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.views")))
	}
	if !s.Root {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.not_root")))
	}
	fmt.Fprintf(w, "  %s\n\n", c.dim(t("report.private")))
}

// writeGroup prints one problem: headline, why (not for minor ones), how
// to fix, and its places.
func writeGroup(w io.Writer, c style, t func(string) string, g Group, o Options, pill bool) {
	f := g.All[0]
	rail := c.wrap(sevColor[f.Severity], "┃ ")
	if !c.on {
		rail = "| "
	}
	p := printer{w: w, c: c, rail: rail}
	title := Tilde(engine.Clean(f.Title))
	if len(g.All) > 1 {
		title = Headline(title)
	}
	pre, rest := "", ""
	if pill {
		lbl := c.wrap(sevPill[f.Severity], " "+t("severity."+f.Severity)+" ")
		if !c.on {
			lbl = "[" + t("severity."+f.Severity) + "]"
		}
		pre = lbl + " "
		rest = strings.Repeat(" ", utf8.RuneCountInString(stripANSI(pre)))
	}
	p.text(0, pre, rest, title, c.bold)
	if o.Verbose {
		meta := f.RuleID
		if len(g.All) == 1 {
			meta += " · " + fmt.Sprintf(t("report.key"), ShortKey(f))
		}
		p.line(2, c.dim(meta))
	}
	minor := f.Severity == "low" || f.Severity == "info"
	if !minor || o.Verbose {
		p.text(2, "", "", Tilde(engine.Clean(f.Explain)), c.dim)
	}

	plans := make([][]string, len(g.All))
	for i, x := range g.All {
		plans[i] = Plan(x)
	}
	pp := PerPlaceOf(g.All, plans)
	p.line(2, c.wrap(green, t("report.how")))
	switch {
	case pp != nil && pp.Plan:
		// The auto-fix commands of each place, below.
	case len(plans[0]) > 0:
		for _, cmd := range plans[0] {
			p.command(4, cmd)
		}
	default:
		var hide map[string]bool
		if pp != nil {
			hide = pp.Hide
		}
		p.steps(2, f.Fix, hide, t("report.see_below"))
	}
	if pp != nil {
		p.line(2, c.wrap(green, fmt.Sprintf(t("report.per_place"), len(pp.Places))))
		for i, pl := range pp.Places {
			if i == listMax && !o.Verbose {
				p.line(4, c.dim(fmt.Sprintf(t("report.and_more"), len(pp.Places)-listMax)))
				break
			}
			place := pl.Place
			if o.Verbose {
				place += "  " + c.dim("["+ShortKey(g.All[i])+"]")
			}
			p.line(4, place)
			for _, cmd := range pl.Cmds {
				p.command(6, cmd)
			}
		}
	} else if len(g.All) > 1 {
		p.line(2, c.wrap(green, fmt.Sprintf(t("report.places"), len(g.All))))
		for i, x := range g.All {
			if i == listMax && !o.Verbose {
				p.line(4, c.dim(fmt.Sprintf(t("report.and_more"), len(g.All)-listMax)))
				break
			}
			place := PlaceOf(x)
			if o.Verbose {
				place += "  " + c.dim("["+ShortKey(x)+"]")
			}
			p.line(4, c.dim("•")+" "+place)
		}
	}
	if len(plans[0]) > 0 {
		p.line(2, c.dim(t("report.can_fix")))
	}
	fmt.Fprintln(w)
}

type repoSection struct {
	repo   string // "" for the machine itself
	groups []Group
}

// repoSections is the by-repo view: the machine first, then each
// repository, worst first (then the one with most problems).
func repoSections(fs []engine.Finding, other string) []repoSection {
	idx := map[string]int{}
	var secs []repoSection
	var byRepo [][]engine.Finding
	for _, f := range fs {
		repo := ""
		if Scope(f.Source) == "code" {
			if repo = Repo(f); repo == "" {
				repo = other
			}
		}
		i, ok := idx[repo]
		if !ok {
			i = len(secs)
			idx[repo] = i
			secs = append(secs, repoSection{repo: repo})
			byRepo = append(byRepo, nil)
		}
		byRepo[i] = append(byRepo[i], f)
	}
	for i := range secs {
		secs[i].groups = Groups(byRepo[i])
	}
	rank := sevRank()
	sort.SliceStable(secs, func(i, j int) bool {
		a, b := secs[i], secs[j]
		if (a.repo == "") != (b.repo == "") {
			return a.repo == ""
		}
		ra, rb := rank[a.groups[0].All[0].Severity], rank[b.groups[0].All[0].Severity]
		if ra != rb {
			return ra < rb
		}
		return len(a.groups) > len(b.groups)
	})
	return secs
}

// safeView lists the checks that pass, per category, like the UI's Safe view.
func safeView(w io.Writer, c style, t func(string) string, s Scan, o Options) {
	byID := map[string]*engine.Rule{}
	for _, r := range o.Rules {
		byID[r.ID] = r
	}
	by := map[string][]string{}
	total := 0
	for _, id := range s.Passed {
		r := byID[id]
		if r == nil || !o.Keep(r.Source) {
			continue
		}
		label := engine.Clean(r.Check.Get(s.Lang))
		if label == "" {
			label = id
		}
		if o.Verbose {
			label += "  " + c.dim("["+id+"]")
		}
		cat := Category(r.Source)
		by[cat] = append(by[cat], label)
		total++
	}
	fmt.Fprintf(w, "  %s %s\n\n", c.wrap(green, "✓"), c.bold(fmt.Sprintf(t("report.safe_title"), total)))
	p := printer{w: w, c: c}
	for _, cat := range Categories {
		if len(by[cat]) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s %s\n", c.bold(t("cat."+cat)), c.dim(fmt.Sprintf("· %d", len(by[cat]))))
		for _, l := range by[cat] {
			p.text(2, c.wrap(green, "✓ "), "  ", l, nil)
		}
		fmt.Fprintln(w)
	}
}
