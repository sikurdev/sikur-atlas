package tui

import (
	"fmt"
	"strings"
)

// State is everything the renderer needs; pure data so rendering is
// testable.
type State struct {
	Snapshot   Snapshot
	Rows       []Row
	Selected   int
	Sort       SortKey
	Filter     string
	Filtering  bool
	Focus      string
	ShowSystem bool
	Drill      bool // detail panel for the selected row
	Err        error
	Width      int
	Height     int
	Plain      bool // no ANSI (for --once/CI)
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiInvert = "\x1b[7m"
	ansiRed    = "\x1b[31m"
)

func (s *State) style(code, text string) string {
	if s.Plain {
		return text
	}
	return code + text + ansiReset
}

func fmtBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func fmtRTT(us uint32) string {
	switch {
	case us == 0:
		return "-"
	case us < 1000:
		return fmt.Sprintf("%dµs", us)
	default:
		return fmt.Sprintf("%.1fms", float64(us)/1000)
	}
}

// Render draws one full frame.
func Render(s *State) string {
	if s.Width <= 0 {
		s.Width = 100
	}
	var b strings.Builder

	// Header.
	mode := "live"
	if s.Focus != "" {
		mode = "focus"
	}
	title := fmt.Sprintf(" ATLAS TOP  %s  agent %s  %s",
		s.Snapshot.Meta.Kernel, s.Snapshot.Meta.Version, mode)
	if psi := s.Snapshot.Meta.HostPSI; psi != nil && psi.Available {
		title += fmt.Sprintf("  psi cpu %.1f%% mem %.1f%% io %.1f%%",
			psi.CPUSomePct, psi.MemSomePct, psi.IOSomePct)
	}
	b.WriteString(s.style(ansiBold, pad(title, s.Width)) + "\n")

	if s.Err != nil {
		b.WriteString(s.style(ansiRed, "  cannot reach agent: "+s.Err.Error()) + "\n")
		b.WriteString("  is `sudo atlas` running? (default http://127.0.0.1:7171)\n")
		return b.String()
	}

	filterLine := fmt.Sprintf(" sort:%s  services:%d", s.Sort, len(s.Rows))
	if s.Filter != "" || s.Filtering {
		cursor := ""
		if s.Filtering {
			cursor = "_"
		}
		filterLine += "  filter:" + s.Filter + cursor
	}
	if s.Focus != "" {
		filterLine += "  focus:" + s.Focus
	}
	if s.ShowSystem {
		filterLine += "  +system"
	}
	b.WriteString(s.style(ansiDim, pad(filterLine, s.Width)) + "\n")

	// Table.
	header := fmt.Sprintf(" %-22s %-9s %6s %8s %6s %6s %6s %8s %5s %5s",
		"SERVICE", "KIND", "CPU%", "RSS", "CONN", "RATE", "FAIL", "RTT", "DEPS", "BY")
	b.WriteString(s.style(ansiBold, pad(header, s.Width)) + "\n")

	maxRows := s.Height - 6
	if maxRows < 3 {
		maxRows = len(s.Rows)
	}
	for i, r := range s.Rows {
		if i >= maxRows {
			b.WriteString(s.style(ansiDim, fmt.Sprintf("  … %d more", len(s.Rows)-maxRows)) + "\n")
			break
		}
		label := r.Label
		if len(label) > 22 {
			label = label[:21] + "…"
		}
		line := fmt.Sprintf(" %-22s %-9s %6.1f %8s %6d %6d %6d %8s %5d %5d",
			label, r.Kind, r.CPUPct, fmtBytes(r.RSS), r.Active, r.Rate,
			r.Fails, fmtRTT(r.RTTUs), r.Deps, r.Callers)
		switch {
		case i == s.Selected && !s.Plain:
			line = ansiInvert + pad(line, s.Width) + ansiReset
		case r.Fails > 0 || r.OOMs > 0:
			line = s.style(ansiRed, line)
		}
		b.WriteString(line + "\n")
	}
	if len(s.Rows) == 0 {
		b.WriteString(s.style(ansiDim, "  no services match") + "\n")
	}

	if s.Drill && s.Selected < len(s.Rows) {
		b.WriteString(renderDrill(s, s.Rows[s.Selected]))
	}

	footer := " q quit  / filter  ↑↓ select  enter details  f focus  s sort  y system"
	b.WriteString(s.style(ansiDim, pad(footer, s.Width)) + "\n")
	return b.String()
}

// renderDrill shows the selected service's dependencies, callers and
// recent lifecycle — the same evidence the web inspector shows.
func renderDrill(s *State, row Row) string {
	var b strings.Builder
	g := s.Snapshot.Graph
	labels := make(map[string]string, len(g.Nodes))
	members := make(map[string]string)
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label
		for _, m := range n.Members {
			members[m] = n.ID
		}
	}
	b.WriteString(s.style(ansiBold, pad(" ── "+row.Label+" ──", s.Width)) + "\n")

	edgeLine := func(e AppEdge, peer string) string {
		target := e.Path
		if e.Protocol != "unix" {
			target = fmt.Sprintf(":%d", e.DstPort)
		}
		health := fmt.Sprintf("act %d", e.ActiveConns)
		if w := e.Window; w != nil {
			health = fmt.Sprintf("act %d  %d/%ds", e.ActiveConns, w.Opens, w.Seconds)
			if w.Failures > 0 {
				health += fmt.Sprintf("  FAIL %d", w.Failures)
			}
			if w.RTTAvgUs > 0 {
				health += "  " + fmtRTT(w.RTTAvgUs)
			}
		}
		return fmt.Sprintf("   %-24s %-28s %s [%s]", peer, target, health, e.Protocol)
	}
	b.WriteString("  depends on:\n")
	deps := 0
	for _, e := range g.Edges {
		if e.Src == row.ID {
			b.WriteString(edgeLine(e, labels[e.Dst]) + "\n")
			deps++
		}
	}
	if deps == 0 {
		b.WriteString(s.style(ansiDim, "   (none)") + "\n")
	}
	b.WriteString("  called by:\n")
	callers := 0
	for _, e := range g.Edges {
		if e.Dst == row.ID {
			b.WriteString(edgeLine(e, labels[e.Src]) + "\n")
			callers++
		}
	}
	if callers == 0 {
		b.WriteString(s.style(ansiDim, "   (none)") + "\n")
	}

	shown := 0
	for i := len(s.Snapshot.Life) - 1; i >= 0 && shown < 5; i-- {
		ev := s.Snapshot.Life[i]
		if members[ev.NodeID] != row.ID {
			continue
		}
		if shown == 0 {
			b.WriteString("  lifecycle (15m):\n")
		}
		line := fmt.Sprintf("   %s  %-5s %s",
			ev.Time.Local().Format("15:04:05"), ev.Kind, ev.Detail)
		if ev.Kind == "oom" || ev.Kind == "crash" {
			line = s.style(ansiRed, line)
		}
		b.WriteString(line + "\n")
		shown++
	}
	return b.String()
}

func pad(sr string, w int) string {
	if len(sr) >= w {
		return sr
	}
	return sr + strings.Repeat(" ", w-len(sr))
}
