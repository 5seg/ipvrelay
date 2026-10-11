// Package tui renders the server browser and drives server switching.
//
// The user needs exactly six facts per server: country, city, hostname,
// whether it is RAM-only, its load, and its measured latency. Anything else is
// noise.
package tui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Row is one selectable server.
type Row struct {
	Hostname  string
	Country   string // ISO code, e.g. "JP"
	City      string
	RamOnly   bool
	Virtual   bool
	IPv6      bool
	Load      int // 0..100, lower is better
	LatencyMS int // -1 when not measured yet
	Active    bool
}

// Status describes the tunnel the user is currently on.
type Status struct {
	ConnectedHost string
	ExitIP        string
	Backend       string // "kernel" or "userspace"
	Switching     bool
	LastError     string
	Conns         int64
	BytesUp       int64
	BytesDown     int64
	UpdatedAt     time.Time
}

// Service is the control surface the UI is allowed to touch. The proxy and
// tunnel live behind it so the UI stays testable and free of I/O.
type Service interface {
	// Rows returns every known server, in display order.
	Rows() []Row
	// Status returns the current tunnel state.
	Status() Status
	// Switch asks for a server change. It must not block on the handshake.
	Switch(hostname string) error
}

type sortMode int

const (
	sortRTT sortMode = iota
	sortLoad
	sortCountry
	sortModeCount
)

func (s sortMode) String() string {
	switch s {
	case sortLoad:
		return "Load"
	case sortCountry:
		return "Country"
	default:
		return "RTT"
	}
}

type tickMsg time.Time

type model struct {
	svc     Service
	refresh time.Duration

	rawRows []Row
	view    []Row
	status  Status

	cursor int
	top    int
	width  int
	height int

	query   string
	search  bool
	ramOnly bool
	sort    sortMode
	err     string
}

func newModel(svc Service, refresh time.Duration) model {
	return model{
		svc:     svc,
		refresh: refresh,
		sort:    sortRTT,
		width:   80,
		height:  24,
	}
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Init() tea.Cmd {
	return tickCmd(m.refresh)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.clamp()
		return m, nil

	case tickMsg:
		m.reload()
		return m, tickCmd(m.refresh)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Bracketed paste delivers the whole selection in one message.
	if msg.Paste {
		text := strings.TrimPrefix(string(msg.Runes), "/")
		if text != "" {
			m.search = true
			m.query += text
			m.apply()
		}
		return m, nil
	}

	if m.search {
		switch key {
		case "esc":
			m.search = false
			m.query = ""
			m.apply()
			return m, nil
		case "enter":
			m.search = false
			return m, nil
		case "backspace":
			if len(m.query) > 0 {
				runes := []rune(m.query)
				m.query = string(runes[:len(runes)-1])
				m.apply()
			}
			return m, nil
		default:
			if len(msg.Runes) > 0 {
				m.query += string(msg.Runes)
				m.apply()
			}
			return m, nil
		}
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-10)
	case "pgdown":
		m.move(10)
	case "home", "g":
		m.cursor = 0
		m.clamp()
	case "end", "G":
		m.cursor = len(m.view) - 1
		m.clamp()
	case "enter":
		if len(m.view) > 0 && m.cursor >= 0 && m.cursor < len(m.view) {
			if err := m.svc.Switch(m.view[m.cursor].Hostname); err != nil {
				m.err = err.Error()
			} else {
				m.err = ""
			}
			m.status = m.svc.Status()
		}
	case "/":
		m.search = true
	case "r":
		m.ramOnly = !m.ramOnly
		m.apply()
	case "s":
		m.sort = (m.sort + 1) % sortModeCount
		m.apply()
	}

	return m, nil
}

func (m *model) reload() {
	m.rawRows = m.svc.Rows()
	m.status = m.svc.Status()
	m.apply()
}

func (m *model) apply() {
	if m.rawRows == nil {
		m.rawRows = m.svc.Rows()
	}

	q := strings.TrimSpace(strings.ToLower(m.query))
	filtered := make([]Row, 0, len(m.rawRows))
	for _, r := range m.rawRows {
		if m.ramOnly && !r.RamOnly {
			continue
		}
		if q != "" {
			match := strings.Contains(strings.ToLower(r.Country), q) ||
				strings.Contains(strings.ToLower(r.City), q) ||
				strings.Contains(strings.ToLower(r.Hostname), q)
			if !match {
				continue
			}
		}
		filtered = append(filtered, r)
	}

	switch m.sort {
	case sortLoad:
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].Load != filtered[j].Load {
				return filtered[i].Load < filtered[j].Load
			}
			return filtered[i].Hostname < filtered[j].Hostname
		})
	case sortCountry:
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].Country != filtered[j].Country {
				return filtered[i].Country < filtered[j].Country
			}
			if filtered[i].City != filtered[j].City {
				return filtered[i].City < filtered[j].City
			}
			return filtered[i].Hostname < filtered[j].Hostname
		})
	default: // sortRTT
		sort.SliceStable(filtered, func(i, j int) bool {
			a, b := filtered[i].LatencyMS, filtered[j].LatencyMS
			if a >= 0 && b >= 0 {
				if a != b {
					return a < b
				}
			} else if a >= 0 && b < 0 {
				return true
			} else if a < 0 && b >= 0 {
				return false
			}
			return filtered[i].Hostname < filtered[j].Hostname
		})
	}

	m.view = filtered
	m.clamp()
}

func (m *model) move(delta int) {
	m.cursor += delta
	m.clamp()
}

func (m *model) clamp() {
	if len(m.view) == 0 {
		m.cursor, m.top = 0, 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.view) {
		m.cursor = len(m.view) - 1
	}

	visible := m.listHeight()
	if visible < 1 {
		visible = 1
	}
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+visible {
		m.top = m.cursor - visible + 1
	}
	if m.top < 0 {
		m.top = 0
	}
}

func (m model) listHeight() int {
	h := m.height - 5
	if h < 1 {
		return 1
	}
	return h
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	ramStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	activeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	selStyle    = lipgloss.NewStyle().Reverse(true)
	dimStyle    = lipgloss.NewStyle().Faint(true)
	errStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	switchStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
)

func (m model) View() string {
	var b strings.Builder

	st := m.status
	connHost := st.ConnectedHost
	if connHost == "" {
		connHost = "-"
	}
	exitIP := st.ExitIP
	if exitIP == "" {
		exitIP = "-"
	}
	backend := st.Backend
	if backend == "" {
		backend = "-"
	}

	statusLine := fmt.Sprintf("Tunnel: %s | Exit: %s | Backend: %s | Conns: %d | Up: %s | Down: %s",
		connHost, exitIP, backend, st.Conns,
		formatBytes(st.BytesUp), formatBytes(st.BytesDown))
	if st.Switching {
		statusLine += " " + switchStyle.Render("[Switching...]")
	}
	if st.LastError != "" {
		statusLine += " " + errStyle.Render("Err: "+st.LastError)
	}
	b.WriteString(titleStyle.Render(statusLine) + "\n")

	ramLabel := "OFF"
	if m.ramOnly {
		ramLabel = ramStyle.Render("ON")
	}
	subLine := fmt.Sprintf("Sort: %s | RAM-only: %s | Filter: %q | Servers: %d/%d",
		m.sort, ramLabel, m.query, len(m.view), len(m.rawRows))
	if m.err != "" {
		subLine += " " + errStyle.Render("Switch error: "+m.err)
	}
	b.WriteString(dimStyle.Render(subLine) + "\n")

	colHeader := fmt.Sprintf(" %-2s %-4s %-20s %-32s %-8s %-6s %-7s",
		"", "CC", "CITY", "HOSTNAME", "FLAGS", "LOAD", "RTT")
	b.WriteString(headerStyle.Render(colHeader) + "\n")

	visible := m.listHeight()
	end := m.top + visible
	if end > len(m.view) {
		end = len(m.view)
	}

	for i := m.top; i < end; i++ {
		r := m.view[i]
		actMark := " "
		if r.Active {
			actMark = "*"
		}

		rttStr := "-"
		if r.LatencyMS >= 0 {
			rttStr = fmt.Sprintf("%dms", r.LatencyMS)
		}

		loadStr := fmt.Sprintf("%d%%", r.Load)

		ramTag := "   "
		if r.RamOnly {
			ramTag = "RAM"
		}
		vTag := " "
		if r.Virtual {
			vTag = "v"
		}
		sixTag := " "
		if r.IPv6 {
			sixTag = "6"
		}
		flags := fmt.Sprintf("%s %s%s", ramTag, vTag, sixTag)

		rowText := fmt.Sprintf(" %-2s %-4s %-20s %-32s %-8s %-6s %-7s",
			actMark, r.Country, truncate(r.City, 20), r.Hostname, flags, loadStr, rttStr)

		if i == m.cursor {
			b.WriteString(selStyle.Render(rowText))
		} else if r.RamOnly {
			coloredFlags := ramStyle.Render(ramTag) + " " + vTag + sixTag
			coloredRow := fmt.Sprintf(" %-2s %-4s %-20s %-32s %-8s %-6s %-7s",
				actMark, r.Country, truncate(r.City, 20), r.Hostname, coloredFlags, loadStr, rttStr)
			b.WriteString(coloredRow)
		} else {
			b.WriteString(rowText)
		}
		b.WriteString("\n")
	}

	for i := end - m.top; i < visible; i++ {
		b.WriteString("\n")
	}

	if m.search {
		b.WriteString(switchStyle.Render(fmt.Sprintf("/%s_", m.query)))
	} else {
		b.WriteString(dimStyle.Render("[↑/↓/j/k:move  Enter:switch  /:search  r:ram  s:sort  q:quit]"))
	}

	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Run draws the interface until ctx is cancelled or the user quits. refresh is
// how often the view is redrawn from the Service.
func Run(ctx context.Context, svc Service, refresh time.Duration) error {
	m := newModel(svc, refresh)
	m.reload()

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || err == tea.ErrInterrupted || ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
}
