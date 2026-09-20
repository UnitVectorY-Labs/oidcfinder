package oidcfinder

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

type reviewLoaded struct {
	filter, search string
	page           int
	items          []Candidate
	status         Status
	err            error
}
type reviewDone struct {
	err     error
	message string
}
type reviewModel struct {
	store                               *Store
	export                              string
	items                               []Candidate
	status                              Status
	filter, search, message             string
	cursor, page, width, height, scroll int
	mode                                string
	inputID, inputName, inputSearch     string
	field                               int
	busy                                bool
}

func (m reviewModel) load() tea.Cmd {
	return func() tea.Msg {
		items, e := m.store.listCandidates(m.filter, m.search, m.page*50, 50)
		if e != nil {
			return reviewLoaded{filter: m.filter, search: m.search, page: m.page, err: e}
		}
		s, e := m.store.status()
		return reviewLoaded{filter: m.filter, search: m.search, page: m.page, items: items, status: s, err: e}
	}
}
func (m reviewModel) Init() tea.Cmd { return m.load() }
func (m reviewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
	case reviewLoaded:
		if v.filter != m.filter || v.search != m.search || v.page != m.page {
			return m, nil
		}
		m.busy = false
		if v.err != nil {
			m.message = v.err.Error()
		} else {
			m.items = v.items
			m.status = v.status
			m.cursor = min(m.cursor, max(0, len(m.items)-1))
		}
	case reviewDone:
		m.busy = false
		if v.err != nil {
			m.message = v.err.Error()
		} else {
			m.message = v.message
		}
		return m, m.load()
	case tea.KeyMsg:
		key := v.String()
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.busy {
			return m, nil
		}
		if m.mode == "accept" || m.mode == "search" {
			if key == "esc" {
				m.mode = ""
				return m, nil
			}
			if key == "tab" {
				m.field = 1 - m.field
				return m, nil
			}
			if key == "enter" {
				if m.mode == "search" {
					m.search = m.inputSearch
					m.mode = ""
					m.page = 0
					m.cursor = 0
					return m, m.load()
				}
				c := m.items[m.cursor]
				m.mode = ""
				m.busy = true
				return m, func() tea.Msg {
					e := m.store.decide(c.ID, "accepted", m.inputID, m.inputName, m.export)
					return reviewDone{err: e, message: "Accepted and written to " + m.export}
				}
			}
			dst := &m.inputSearch
			if m.mode == "accept" {
				dst = &m.inputID
				if m.field == 1 {
					dst = &m.inputName
				}
			}
			if key == "backspace" {
				r := []rune(*dst)
				if len(r) > 0 {
					*dst = string(r[:len(r)-1])
				}
			} else if v.Type == tea.KeyRunes {
				for _, r := range v.Runes {
					if !unicode.IsControl(r) && len(*dst) < 256 {
						*dst += string(r)
					}
				}
			}
			return m, nil
		}
		if m.mode == "detail" {
			switch key {
			case "esc", "enter", "q":
				m.mode = ""
				m.scroll = 0
			case "down", "j":
				m.scroll++
			case "up", "k":
				m.scroll = max(0, m.scroll-1)
			case "pgdown":
				m.scroll += max(1, m.height-5)
			case "pgup":
				m.scroll = max(0, m.scroll-max(1, m.height-5))
			}
			return m, nil
		}
		switch key {
		case "q":
			return m, tea.Quit
		case "down", "j":
			m.cursor = max(0, min(m.cursor+1, len(m.items)-1))
		case "up", "k":
			m.cursor = max(0, m.cursor-1)
		case "n", "pgdown":
			if len(m.items) == 50 {
				m.page++
				m.cursor = 0
				return m, m.load()
			}
		case "p", "pgup":
			if m.page > 0 {
				m.page--
				m.cursor = 0
				return m, m.load()
			}
		case "tab":
			filters := []string{"pending", "accepted", "rejected", "catalog", "all"}
			for i, f := range filters {
				if f == m.filter {
					m.filter = filters[(i+1)%len(filters)]
					break
				}
			}
			m.page = 0
			m.cursor = 0
			return m, m.load()
		case "/":
			m.mode = "search"
			m.inputSearch = m.search
		case "f5":
			return m, m.load()
		case "enter":
			if len(m.items) > 0 {
				m.mode = "detail"
			}
		case "a":
			if len(m.items) > 0 {
				c := m.items[m.cursor]
				if c.InCatalog {
					m.message = "Already in the catalog"
					break
				}
				m.mode = "accept"
				m.inputID = c.ServiceID
				m.inputName = c.Name
				m.field = 0
			}
		case "r", "u":
			if len(m.items) > 0 {
				c := m.items[m.cursor]
				decision := "rejected"
				if key == "u" {
					decision = "pending"
				}
				m.busy = true
				return m, func() tea.Msg {
					e := m.store.decide(c.ID, decision, "", "", m.export)
					return reviewDone{err: e, message: "Decision: " + decision}
				}
			}
		}
	}
	return m, nil
}
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
func fit(s string, n int) string {
	r := []rune(safeText(s))
	if len(r) > n && n > 1 {
		return string(r[:n-1]) + "…"
	}
	return string(r)
}
func (m reviewModel) View() string {
	width := max(30, m.width-2)
	height := max(12, m.height)
	var b strings.Builder
	fmt.Fprintf(&b, "OIDCFINDER  ·  %s  ·  page %d\n", m.filter, m.page+1)
	fmt.Fprintf(&b, "Targets %d · Due %d · Review %d · Accepted %d · Rejected %d\n", m.status.Targets, m.status.Due, m.status.Pending, m.status.Accepted, m.status.Rejected)
	fmt.Fprintf(&b, "Catalog %d services · refreshed %s\n\n", m.status.CatalogEntries, m.status.CatalogFetched)
	if m.mode == "detail" && len(m.items) > 0 {
		c := m.items[m.cursor]
		var meta any
		_ = json.Unmarshal([]byte(c.Metadata), &meta)
		pretty, _ := json.MarshalIndent(meta, "", "  ")
		text := fmt.Sprintf("Issuer: %s\nJWKS: %s\nOIDC: %s\nOAuth: %s\nDecision: %s · In catalog: %t\nFirst: %s\nLast: %s\n\n%s", c.Issuer, c.JWKS, c.OIDC, c.OAuth, c.Decision, c.InCatalog, date(c.FirstSeen), date(c.LastSeen), pretty)
		lines := []string{}
		for _, line := range strings.Split(text, "\n") {
			r := []rune(safeText(line))
			for len(r) > width {
				lines = append(lines, string(r[:width]))
				r = r[width:]
			}
			lines = append(lines, string(r))
		}
		start := min(m.scroll, max(0, len(lines)-1))
		for _, l := range lines[start:min(len(lines), start+height-8)] {
			b.WriteString(l + "\n")
		}
		b.WriteString("\n↑/↓ scroll · Esc back")
		return b.String()
	}
	if m.mode == "accept" {
		b.WriteString("Accept candidate — edit the catalog entry\n\n")
		a, z := "  ", "  "
		if m.field == 0 {
			a = "> "
		} else {
			z = "> "
		}
		fmt.Fprintf(&b, "%sID: %s\n%sName: %s\n\nTab switch field · Enter save · Esc cancel\n", a, safeText(m.inputID), z, safeText(m.inputName))
		return b.String()
	}
	if m.mode == "search" {
		fmt.Fprintf(&b, "Search issuer/name: %s\nEnter apply · Esc back\n", safeText(m.inputSearch))
		return b.String()
	}
	count := max(1, height-11)
	start := 0
	if m.cursor >= count {
		start = m.cursor - count + 1
	}
	if len(m.items) == 0 {
		b.WriteString("No candidates in this view. Run a crawl or press Tab to change filter.\n")
	}
	for i := start; i < min(len(m.items), start+count); i++ {
		c := m.items[i]
		mark := " "
		if i == m.cursor {
			mark = ">"
		}
		catalog := ""
		if c.InCatalog {
			catalog = " [catalog]"
		}
		fmt.Fprintf(&b, "%s %s\n", mark, fit(fmt.Sprintf("#%d %-8s %s%s", c.ID, c.Decision, c.Issuer, catalog), width-2))
	}
	fmt.Fprintf(&b, "\n%s\n", fit(m.message, width))
	b.WriteString("↑/↓ select · Enter details · a accept · r reject · u undo rejection\nTab filter · / search · n/p page · F5 refresh · q quit\n")
	return b.String()
}
func runTUI(s *Store, path string, in io.Reader, out io.Writer) error {
	m := reviewModel{store: s, export: path, filter: "pending", width: 100, height: 24}
	_, e := tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen()).Run()
	return e
}
