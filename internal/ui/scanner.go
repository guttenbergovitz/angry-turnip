package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ViewState represents screen mode.
type ViewState int

const (
	StateScanning ViewState = iota
	StateExplorer
	StateExportModal
	StateHelp
)

// TickMsg triggers periodic UI updates during scan.
type TickMsg struct {
	time time.Time
}

// ScanProgress tracks scan progress.
type ScanProgress struct {
	Current      int
	Total        int
	CurrentPkg   string
	CurrentVulns int
	Completed    bool
	Error        string
}

// VulnEntry represents an SCA vulnerability entry.
type VulnEntry struct {
	Package        string
	Version        string
	CVE            string
	CVEID          string
	Severity       string
	CVSS           float64
	CVSSVector     string
	Description    string
	CVETitle       string
	CVEDescription string
	PublishedAt    string
	DependencyPath []string
}

// Model represents the Lazygit/btm style Fullscreen DevSecOps TUI state.
type Model struct {
	activeTab       ActiveTab
	activePane      ActivePane
	state           ViewState
	isMaximized     bool
	isDetailExpanded bool // true = show detail pane below table
	progress        ScanProgress
	startTime        time.Time
	result           *types.ScanResult
	evaluation       *policy.EvaluationResult
	graph            *types.DependencyGraph
	vulns            []VulnEntry
	secretFindings   []secrets.SecretFinding
	iacIssues        []container.SecurityIssue
	licenseFindings  []license.LicenseFinding
	filteredItems    []TUIFinding
	markedFixed      map[string]bool // Canonical finding Key -> locally hidden in UI
	showHidden       bool            // When true, display locally hidden items so they can be unhidden
	revealSecrets    bool            // When false (default), secret values are masked
	spinner          spinner.Model
	progressBar     progress.Model
	vulnTable       table.Model
	reasonVP        viewport.Model
	chainVP         viewport.Model
	detailVP        viewport.Model
	styles          Styles
	width           int
	height          int
	selectedIdx     int
	filterSeverity  string // "", "critical", "high", "medium", "low"
	searchQuery     string
	isSearching     bool
	groupMode       GroupMode
	exportFormat        string // "json", "csv", "markdown", "cyclonedx", "spdx"
	exportStatus        string
	tableReasonColWidth int
	tableTargetColWidth int
	tableIDColWidth     int
	activityLogs        []string
	cancelFunc          func() // Cancel scan context on early quit
	mu                  sync.Mutex
}

// ProgressMsg updates scan progress.
type ProgressMsg struct {
	Progress ScanProgress
}

// VulnMsg adds a vulnerability entry.
type VulnMsg struct {
	Entry VulnEntry
}

// DoneMsg indicates full scan completion across all domains and policy evaluation.
type DoneMsg struct {
	Result     *types.ScanResult
	Evaluation *policy.EvaluationResult
	Graph      *types.DependencyGraph
	Secrets    []secrets.SecretFinding
	IaC        []container.SecurityIssue
	Licenses   []license.LicenseFinding
}

// ExportDoneMsg reports completion of an asynchronous file export operation.
type ExportDoneMsg struct {
	FileName string
	Err      error
}

// ErrorMsg indicates scan error.
type ErrorMsg struct {
	Err string
}

// NewModel initializes the TUI model.
func NewModel() *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9"))

	p := progress.New(progress.WithDefaultGradient())

	columns := []table.Column{
		{Title: "DOMAIN", Width: 10},
		{Title: "SEVERITY", Width: 12},
		{Title: "TARGET / PACKAGE", Width: 25},
		{Title: "ID / RULE", Width: 20},
		{Title: "REASON SUMMARY", Width: 35},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	tStyle := table.DefaultStyles()
	tStyle.Header = tStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#6272A4")).
		BorderBottom(true).
		Bold(true)
	tStyle.Selected = tStyle.Selected.
		Foreground(lipgloss.Color("#F8F8F2")).
		Background(lipgloss.Color("#44475A")).
		Bold(true)
	t.SetStyles(tStyle)

	rVP := viewport.New(50, 10)
	cVP := viewport.New(50, 10)
	dVP := viewport.New(50, 10)

	m := &Model{
		activeTab:        TabVulnerabilities,
		activePane:       PaneTable,
		state:            StateScanning,
		startTime:        time.Now(),
		markedFixed:      make(map[string]bool),
		spinner:          s,
		progressBar:      p,
		vulnTable:        t,
		reasonVP:         rVP,
		chainVP:          cVP,
		detailVP:         dVP,
		styles:           DefaultStyles(),
		width:            140,
		height:           40,
		filterSeverity:   "critical,high", // Smart default: show Critical+High only
		isDetailExpanded: false,
	}
	m.recalculateViewports()
	return m
}

// SetProgress updates scan progress state.
func (m *Model) SetProgress(current, total int, currentPkg string, vulns int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Current = current
	m.progress.Total = total
	m.progress.CurrentPkg = currentPkg
	m.progress.CurrentVulns = vulns
}

// AddVulnerability adds a detected vulnerability entry.
func (m *Model) AddVulnerability(entry VulnEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vulns = append(m.vulns, entry)
}

// SetDone marks scanning as finished, computes canonical policy evaluation, and enables explorer mode.
func (m *Model) SetDone(result *types.ScanResult, graph *types.DependencyGraph, secretsList []secrets.SecretFinding, iacList []container.SecurityIssue, licensesList []license.LicenseFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Completed = true
	m.result = result
	if result != nil {
		eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Now().UTC())
		m.evaluation = &eval
	}
	m.graph = graph
	m.secretFindings = secretsList
	m.iacIssues = iacList
	m.licenseFindings = licensesList
	m.state = StateExplorer
	m.applyFiltersLocked()
}

// SetError marks scanning as failed.
func (m *Model) SetError(err string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Error = err
}

// SetCancelFunc sets context cancel function for early quit.
func (m *Model) SetCancelFunc(cancel func()) {
	m.cancelFunc = cancel
}

// switchToTab changes active tab and resets view state.
func (m *Model) switchToTab(tab ActiveTab) {
	m.activeTab = tab
	m.selectedIdx = 0
	m.vulnTable.SetCursor(0)
	m.applyFilters()
}

// Init initializes the model.
func (m *Model) Init() tea.Cmd {
	return ticker()
}

func ticker() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles key presses, window resizing, and state transitions.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalculateViewports()
		m.updateTableLayout()
		return m, nil
	case ProgressMsg:
		m.mu.Lock()
		m.progress = msg.Progress
		if msg.Progress.CurrentPkg != "" && msg.Progress.CurrentPkg != "Starting scan..." {
			timestamp := time.Now().Format("15:04:05")
			logLine := fmt.Sprintf("  • [%s] ⚡ Scanned %s (%d/%d)", timestamp, msg.Progress.CurrentPkg, msg.Progress.Current, msg.Progress.Total)
			m.activityLogs = append(m.activityLogs, logLine)
			if len(m.activityLogs) > 6 {
				m.activityLogs = m.activityLogs[len(m.activityLogs)-6:]
			}
		}
		m.mu.Unlock()
		m.updateTableLayout()
		return m, nil
	case VulnMsg:
		m.mu.Lock()
		m.vulns = append(m.vulns, msg.Entry)
		timestamp := time.Now().Format("15:04:05")
		sevUpper := strings.ToUpper(msg.Entry.Severity)
		logLine := fmt.Sprintf("  • [%s] ⚠ VULNERABILITY DETECTED in %s (%s - %s)", timestamp, msg.Entry.Package, sevUpper, msg.Entry.CVE)
		m.activityLogs = append(m.activityLogs, logLine)
		if len(m.activityLogs) > 6 {
			m.activityLogs = m.activityLogs[len(m.activityLogs)-6:]
		}
		m.mu.Unlock()
		m.applyFilters()
		return m, nil
	case DoneMsg:
		m.mu.Lock()
		m.progress.Completed = true
		m.result = msg.Result
		if msg.Evaluation != nil {
			m.evaluation = msg.Evaluation
		} else if msg.Result != nil {
			eval := policy.Evaluate(msg.Result, policy.DefaultPolicy(), nil, time.Now().UTC())
			m.evaluation = &eval
		}
		m.graph = msg.Graph
		if len(msg.Secrets) > 0 {
			m.secretFindings = msg.Secrets
		}
		if len(msg.IaC) > 0 {
			m.iacIssues = msg.IaC
		}
		if len(msg.Licenses) > 0 {
			m.licenseFindings = msg.Licenses
		}
		m.state = StateExplorer
		m.mu.Unlock()
		m.applyFilters()
		return m, nil
	case ExportDoneMsg:
		m.mu.Lock()
		if msg.Err != nil {
			m.exportStatus = fmt.Sprintf("Export failed: %v", msg.Err)
		} else {
			m.exportStatus = fmt.Sprintf("Exported findings to %s", msg.FileName)
			m.state = StateExplorer
		}
		m.mu.Unlock()
		return m, nil
	case ErrorMsg:
		m.mu.Lock()
		m.progress.Error = msg.Err
		m.mu.Unlock()
		return m, tea.Quit
	case TickMsg:
		var cmd tea.Cmd
		if m.state == StateScanning {
			m.spinner, cmd = m.spinner.Update(msg)
			return m, tea.Batch(cmd, ticker())
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if key == "ctrl+c" {
		if m.cancelFunc != nil {
			m.cancelFunc()
		}
		return m, tea.Quit
	}

	// Search Mode input handler
	if m.isSearching {
		switch key {
		case "enter", "esc":
			m.isSearching = false
			return m, nil
		case "backspace":
			if len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
				m.applyFilters()
			}
			return m, nil
		default:
			if len(key) == 1 {
				m.searchQuery += key
				m.applyFilters()
			}
			return m, nil
		}
	}

	// Export Modal input handler
	if m.state == StateExportModal {
		switch key {
		case "esc", "q":
			m.state = StateExplorer
			m.exportStatus = ""
		case "1":
			return m, m.executeExport("json")
		case "2":
			return m, m.executeExport("csv")
		case "3":
			return m, m.executeExport("markdown")
		case "4":
			return m, m.executeExport("cyclonedx")
		case "5":
			return m, m.executeExport("spdx")
		}
		return m, nil
	}

	// Help Modal input handler
	if m.state == StateHelp {
		switch key {
		case "esc", "q", "?":
			m.state = StateExplorer
		}
		return m, nil
	}

	switch m.state {
	case StateScanning:
		if key == "q" {
			// Cancel scan context to stop goroutine
			if m.cancelFunc != nil {
				m.cancelFunc()
			}
			return m, tea.Quit
		}

	case StateExplorer:
		switch key {
		case "q":
			return m, tea.Quit
		case "1":
			m.switchToTab(TabVulnerabilities)
		case "2":
			m.switchToTab(TabSecrets)
		case "3":
			m.switchToTab(TabIaC)
		case "4":
			m.switchToTab(TabLicenses)
		case "5":
			m.switchToTab(TabDependencyGraph)
		case "g":
			m.groupMode = (m.groupMode + 1) % 3
			m.applyFilters()
		case "e":
			m.state = StateExportModal
		case "?":
			m.state = StateHelp
		case "/":
			m.isSearching = true
			m.searchQuery = ""
		case "C":
			m.filterSeverity = "critical"
			m.applyFilters()
		case "H":
			m.filterSeverity = "high"
			m.applyFilters()
		case "M":
			m.filterSeverity = "medium"
			m.applyFilters()
		case "L":
			m.filterSeverity = "low"
			m.applyFilters()
		case "y":
			// Copy CVE/rule ID to clipboard (ignore non-actionable group headers)
			if m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
				item := m.filteredItems[m.selectedIdx]
				if item.IsGroupHeader {
					m.exportStatus = "Group header selected (select a finding row to copy ID)"
					return m, nil
				}
				if copyToClipboard(item.ID) == nil {
					m.exportStatus = "✓ Copied " + item.ID + " to clipboard"
				} else {
					m.exportStatus = "✗ Failed to copy to clipboard"
				}
			}
		case "x":
			// Hide/unhide selected finding locally by canonical Key (ID + PURL / location)
			if m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
				item := m.filteredItems[m.selectedIdx]
				if item.IsGroupHeader {
					m.exportStatus = "Cannot hide a group header"
					return m, nil
				}
				key := item.Key
				if key == "" {
					key = item.ID + "|" + item.Package + "@" + item.Version
				}
				if m.markedFixed[key] {
					delete(m.markedFixed, key)
					m.exportStatus = "✓ Unhidden locally: " + item.ID + " (" + item.Package + ")"
				} else {
					m.markedFixed[key] = true
					m.exportStatus = "✓ Hidden locally (not remediated): " + item.ID + " (" + item.Package + ")"
				}
				m.applyFilters()
			}
		case "X":
			// Restore all locally hidden findings
			count := len(m.markedFixed)
			m.markedFixed = make(map[string]bool)
			m.showHidden = false
			m.exportStatus = fmt.Sprintf("✓ Restored %d locally hidden finding(s)", count)
			m.applyFilters()
		case "v":
			// Toggle viewing locally hidden items so individual items can be inspected or unhidden
			m.showHidden = !m.showHidden
			if m.showHidden {
				m.exportStatus = "Showing locally hidden findings (press [x] to unhide, [v] to hide again)"
			} else {
				m.exportStatus = "Hiding locally hidden findings"
			}
			m.applyFilters()
		case "s":
			// Explicitly toggle secret value reveal/masking
			m.revealSecrets = !m.revealSecrets
			if m.revealSecrets {
				m.exportStatus = "⚠ Secret values revealed (press [s] to mask)"
			} else {
				m.exportStatus = "✓ Secret values masked"
			}
			m.applyFilters()
		case "enter":
			// Toggle detail expansion
			m.isDetailExpanded = !m.isDetailExpanded
			m.recalculateViewports()
		case "a", "esc":
			m.filterSeverity = ""
			m.searchQuery = ""
			m.applyFilters()
		case "tab", "l":
			// tab or l (vim right) = next pane
			m.activePane = (m.activePane + 1) % 4
			m.updateSelectedPaneContents()
		case "h":
			// h (vim left) = previous pane
			m.activePane = (m.activePane + 3) % 4 // -1 mod 4 = 3
			m.updateSelectedPaneContents()
		case "w":
			m.isMaximized = !m.isMaximized
		case "up", "k":
			if m.activePane == PaneTable {
				var cmd tea.Cmd
				m.vulnTable, cmd = m.vulnTable.Update(msg)
				m.selectedIdx = m.vulnTable.Cursor()
				m.updateSelectedPaneContents()
				return m, cmd
			} else if m.activePane == PaneReason {
				m.reasonVP.LineUp(1)
			} else if m.activePane == PaneChain {
				m.chainVP.LineUp(1)
			} else if m.activePane == PaneDetails {
				m.detailVP.LineUp(1)
			}
		case "down", "j":
			if m.activePane == PaneTable {
				var cmd tea.Cmd
				m.vulnTable, cmd = m.vulnTable.Update(msg)
				m.selectedIdx = m.vulnTable.Cursor()
				m.updateSelectedPaneContents()
				return m, cmd
			} else if m.activePane == PaneReason {
				m.reasonVP.LineDown(1)
			} else if m.activePane == PaneChain {
				m.chainVP.LineDown(1)
			} else if m.activePane == PaneDetails {
				m.detailVP.LineDown(1)
			}
		}
	}

	return m, nil
}

func (m *Model) applyFilters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyFiltersLocked()
}

func (m *Model) applyFiltersLocked() {
	var items []TUIFinding

	// Collect findings according to ActiveTab
	switch m.activeTab {
	case TabVulnerabilities:
		if m.evaluation != nil && len(m.evaluation.Decisions) > 0 {
			pathByPkg := make(map[string][]string)
			for _, v := range m.vulns {
				if len(v.DependencyPath) > 0 {
					pathByPkg[v.Package] = v.DependencyPath
				}
			}
			for _, fd := range m.evaluation.Decisions {
				f := fd.Finding
				var signals []string
				signals = append(signals, string(fd.Decision))
				if f.KnownExploited {
					signals = append(signals, "KEV")
				}
				if f.EPSSScore > 0 {
					signals = append(signals, fmt.Sprintf("EPSS %.1f%%", f.EPSSScore*100))
				}
				if fd.AcceptedRisk {
					signals = append(signals, "Accepted Risk")
				}

				reasonParts := append([]string(nil), fd.Reasoning...)
				if f.EffectiveScoreReason != "" {
					reasonParts = append(reasonParts, "Score provenance: "+f.EffectiveScoreReason)
				}
				reason := fmt.Sprintf("[%s] %s", strings.Join(signals, " · "), strings.Join(reasonParts, " "))

				depPath := pathByPkg[f.Package+"@"+f.Version]
				if len(depPath) == 0 {
					depPath = pathByPkg[f.Package]
				}

				domainLabel := "SCA:" + string(fd.Decision)
				items = append(items, TUIFinding{
					Key:             f.Key,
					Domain:          domainLabel,
					Decision:        string(fd.Decision),
					Package:         f.Package,
					Version:         f.Version,
					ID:              f.ID,
					Severity:        string(f.Severity),
					CVSS:            f.CVSSScore,
					Title:           f.Summary,
					Description:     f.Summary,
					ReasonFlagged:   reason,
					DependencyPath:  depPath,
					Remediation:     "Review policy decision and upgrade affected component version",
					MissingEvidence: f.MissingEvidence,
				})
			}
		} else {
			for _, v := range m.vulns {
				cveID := v.CVE
				if v.CVEID != "" {
					cveID = v.CVEID
				}
				pkgDisplay := v.Package
				chainPrefix := ""
				if len(v.DependencyPath) > 1 {
					rootDep := v.DependencyPath[0]
					pkgDisplay = fmt.Sprintf("%s (via %s)", v.Package, rootDep)
					chainPrefix = fmt.Sprintf("[Chain: %s] ", strings.Join(v.DependencyPath, " -> "))
				}

				reason := fmt.Sprintf("%sA vulnerability affects %s (%s). The issue is tracked upstream as %s with CVSS score %.1f.", chainPrefix, v.Package, v.Version, cveID, v.CVSS)
				if v.CVEDescription != "" {
					reason = chainPrefix + v.CVEDescription
				}
				items = append(items, TUIFinding{
					Key:            fmt.Sprintf("%s|%s@%s", cveID, v.Package, v.Version),
					Domain:         "SCA",
					Package:        pkgDisplay,
					Version:        v.Version,
					ID:             cveID,
					Severity:       v.Severity,
					CVSS:           v.CVSS,
					Title:          v.CVETitle,
					Description:    v.Description,
					ReasonFlagged:  reason,
					DependencyPath: v.DependencyPath,
					Remediation:    "Upgrade package to non-vulnerable patch version",
				})
			}
		}

	case TabSecrets:
		for _, s := range m.secretFindings {
			relPath := filepath.Base(s.FilePath)
			matchDisplay := secrets.MaskSecret(s.Match) + " (masked — press [s] to reveal)"
			if m.revealSecrets {
				matchDisplay = s.Match + " (REVEALED — press [s] to mask)"
			}
			items = append(items, TUIFinding{
				Key:           fmt.Sprintf("SECRET|%s:%d|%s", s.FilePath, s.LineNumber, s.Type),
				Domain:        "SECRET",
				Package:       relPath,
				ID:            string(s.Type),
				Severity:      "secret",
				Title:         fmt.Sprintf("Leaked %s at line %d", s.Type, s.LineNumber),
				Description:   fmt.Sprintf("Hardcoded secret discovered in %s:%d\nMatch: %s", s.FilePath, s.LineNumber, matchDisplay),
				ReasonFlagged: fmt.Sprintf("High-entropy secret key pattern matching %s discovered in source code (Shannon Entropy: %.2f)", s.Type, s.Entropy),
				Remediation:   "Revoke secret key immediately and remove from git commit history",
				RawSecret:     s,
			})
		}

	case TabIaC:
		for _, iac := range m.iacIssues {
			relPath := filepath.Base(iac.Source)
			items = append(items, TUIFinding{
				Key:           fmt.Sprintf("IAC|%s:%d|%s", iac.Source, iac.LineNumber, iac.RuleID),
				Domain:        "IaC",
				Package:       relPath,
				ID:            iac.RuleID,
				Severity:      string(iac.Severity),
				Title:         iac.Title,
				Description:   iac.Message,
				ReasonFlagged: fmt.Sprintf("IaC Linter Rule %s triggered: %s", iac.RuleID, iac.Message),
				Remediation:   "Update Dockerfile / GitHub Action workflow according to security best practices",
				RawIaC:        iac,
			})
		}

	case TabLicenses:
		for _, lic := range m.licenseFindings {
			sev := "low"
			reason := "Permissive license (MIT/Apache/BSD) safe for commercial software distribution"
			if lic.Category == license.Copyleft {
				sev = "high"
				reason = "Copyleft license (GPL/AGPL) poses legal infection risk requiring source code disclosure"
			}
			items = append(items, TUIFinding{
				Key:           fmt.Sprintf("LICENSE|%s@%s|%s", lic.PackageName, lic.Version, lic.License),
				Domain:        "LICENSE",
				Package:       lic.PackageName,
				Version:       lic.Version,
				ID:            lic.License,
				Severity:      sev,
				Title:         fmt.Sprintf("%s (%s)", lic.License, lic.Category),
				Description:   fmt.Sprintf("Package %s uses %s license", lic.PackageName, lic.License),
				ReasonFlagged: reason,
				Remediation:   "Review open source license terms and compliance requirements",
				RawLicense:    lic,
			})
		}

	case TabDependencyGraph:
		if m.graph != nil {
			keys := make([]string, 0, len(m.graph.Nodes))
			for k := range m.graph.Nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				node := m.graph.Nodes[k]
				items = append(items, TUIFinding{
					Key:           "GRAPH|" + k,
					Domain:        "GRAPH",
					Package:       node.Name,
					Version:       node.Version,
					ID:            fmt.Sprintf("Depth %d", node.Depth),
					Severity:      "low",
					Title:         fmt.Sprintf("Node: %s@%s", node.Name, node.Version),
					Description:   fmt.Sprintf("Ecosystem: %s | Direct: %v | Depth: %d", node.Ecosystem, node.Direct, node.Depth),
					ReasonFlagged: fmt.Sprintf("Dependency graph node with %d vulnerabilities", len(node.Vulnerabilities)),
				})
			}
		}
	}

	// Severity & Text Search filtering
	var filtered []TUIFinding
	search := strings.ToLower(strings.TrimSpace(m.searchQuery))

	// Parse filterSeverity as comma-separated list (e.g., "critical,high")
	allowedSeverities := make(map[string]bool)
	if m.filterSeverity != "" {
		for _, sev := range strings.Split(m.filterSeverity, ",") {
			allowedSeverities[strings.TrimSpace(strings.ToLower(sev))] = true
		}
	}

	for _, item := range items {
		key := item.Key
		if key == "" {
			key = item.ID + "|" + item.Package + "@" + item.Version
		}
		// Skip locally hidden findings unless showHidden is toggled on
		if m.markedFixed[key] && !m.showHidden {
			continue
		}
		if m.activeTab == TabVulnerabilities && m.filterSeverity != "" && !allowedSeverities[strings.ToLower(item.Severity)] {
			continue
		}
		if search != "" {
			matchPkg := strings.Contains(strings.ToLower(item.Package), search)
			matchID := strings.Contains(strings.ToLower(item.ID), search)
			matchTitle := strings.Contains(strings.ToLower(item.Title), search) || strings.Contains(strings.ToLower(item.Description), search)
			if !matchPkg && !matchID && !matchTitle {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	// Grouping Mode
	if m.groupMode == GroupPackage {
		filtered = groupFindingsByPackage(filtered)
	} else if m.groupMode == GroupSeverity {
		filtered = groupFindingsBySeverity(filtered)
	}

	m.filteredItems = filtered
	if m.selectedIdx >= len(m.filteredItems) {
		m.selectedIdx = 0
	}
	m.updateTableLayout()
	m.updateSelectedPaneContents()
}

func (m *Model) recalculateViewports() {
	bodyHeight := m.height - 4
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	topHeight := bodyHeight / 2
	bottomHeight := bodyHeight - topHeight

	availWidth := m.width - 2
	if availWidth < 30 {
		availWidth = 30
	}

	wReason := int(float64(availWidth) * 0.25)
	wDetail := int(float64(availWidth) * 0.50)
	wChain := availWidth - wReason - wDetail

	if m.isMaximized {
		topHeight = bodyHeight
		bottomHeight = bodyHeight
		wReason = m.width - 2
		wDetail = m.width - 2
		wChain = m.width - 2
	}

	// Calculate rich 5-column table widths
	domainColWidth, sevColWidth, targetColWidth, idColWidth, reasonColWidth := calculateColumnWidths(availWidth)
	m.tableTargetColWidth = targetColWidth
	m.tableIDColWidth = idColWidth
	m.tableReasonColWidth = reasonColWidth

	m.vulnTable.SetColumns([]table.Column{
		{Title: "DOMAIN", Width: domainColWidth},
		{Title: "SEVERITY", Width: sevColWidth},
		{Title: "TARGET / PACKAGE", Width: targetColWidth},
		{Title: "ID / RULE", Width: idColWidth},
		{Title: "REASON SUMMARY", Width: reasonColWidth},
	})

	m.vulnTable.SetWidth(availWidth - 4)
	m.vulnTable.SetHeight(topHeight - 3)

	m.reasonVP.Width = wReason - 4
	m.reasonVP.Height = bottomHeight - 3

	m.detailVP.Width = wDetail - 4
	m.detailVP.Height = bottomHeight - 3

	m.chainVP.Width = wChain - 4
	m.chainVP.Height = bottomHeight - 3

	m.updateTableLayout()
	m.updateSelectedPaneContents()
}

// calculateColumnWidths computes 5-column table widths from available width.
func calculateColumnWidths(availWidth int) (domain, severity, target, id, reason int) {
	// Subtract 18 for outer box border & 5-column cell padding
	tableInnerWidth := availWidth - 18
	if tableInnerWidth < 30 {
		tableInnerWidth = 30
	}
	domain = 10
	severity = 12
	remWidth := tableInnerWidth - domain - severity
	target = int(float64(remWidth) * 0.25)
	id = int(float64(remWidth) * 0.25)
	reason = remWidth - target - id
	if reason < 10 {
		reason = 10
	}
	return
}

func (m *Model) updateTableLayout() {
	targetWidth := m.tableTargetColWidth
	if targetWidth <= 0 {
		targetWidth = 20
	}
	idWidth := m.tableIDColWidth
	if idWidth <= 0 {
		idWidth = 20
	}
	reasonWidth := m.tableReasonColWidth
	if reasonWidth <= 0 {
		reasonWidth = 30
	}

	var rows []table.Row
	for _, item := range m.filteredItems {
		pkgStr := truncateRunes(item.Package, targetWidth)
		idStr := truncateRunes(item.ID, idWidth)
		reasonSummary := truncateRunes(item.ReasonFlagged, reasonWidth)

		rows = append(rows, table.Row{
			item.Domain,
			strings.ToUpper(item.Severity),
			pkgStr,
			idStr,
			reasonSummary,
		})
	}
	m.vulnTable.SetRows(rows)
}

func truncateRunes(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return string(runes[:maxWidth])
	}
	return string(runes[:maxWidth-3]) + "..."
}

func (m *Model) updateSelectedPaneContents() {
	if len(m.filteredItems) == 0 {
		m.reasonVP.SetContent("No findings in this category.")
		m.chainVP.SetContent("No dependency chain available.")
		m.detailVP.SetContent("No detailed inspection content.")
		return
	}

	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filteredItems) {
		m.selectedIdx = 0
		m.vulnTable.SetCursor(0)
	}

	item := m.filteredItems[m.selectedIdx]

	// 1. Reason Viewport Content (Word Wrapped)
	reasonWrapped := lipgloss.NewStyle().
		Width(m.reasonVP.Width).
		Render(item.ReasonFlagged)
	m.reasonVP.SetContent(reasonWrapped)

	// 2. Dependency Chain Viewport Content
	var chainBuf strings.Builder
	if len(item.DependencyPath) > 0 {
		for i, nodeName := range item.DependencyPath {
			indent := strings.Repeat("  ", i)
			if i == 0 {
				chainBuf.WriteString(fmt.Sprintf("%s󰏖 Root: %s\n", indent, nodeName))
			} else if i == len(item.DependencyPath)-1 {
				chainBuf.WriteString(fmt.Sprintf("%s└── %s [VULNERABLE TARGET]\n", indent, nodeName))
			} else {
				chainBuf.WriteString(fmt.Sprintf("%s└── %s\n", indent, nodeName))
			}
		}
	} else {
		chainBuf.WriteString(fmt.Sprintf("Target: %s@%s\nNo deep dependency path recorded.", item.Package, item.Version))
	}
	m.chainVP.SetContent(chainBuf.String())

	// 3. Detail Inspection Viewport Content
	var detailBuf strings.Builder
	detailBuf.WriteString(fmt.Sprintf("Target Package: %s\n", item.Package))
	if item.Version != "" {
		detailBuf.WriteString(fmt.Sprintf("Version: %s\n", item.Version))
	}
	detailBuf.WriteString(fmt.Sprintf("ID / Rule: %s\n", item.ID))
	detailBuf.WriteString(fmt.Sprintf("Severity: %s\n\n", RenderSeverityBadge(item.Severity, m.styles)))

	detailBuf.WriteString("󰈔 Context & Description:\n")
	descWrapped := lipgloss.NewStyle().
		Width(m.detailVP.Width).
		Render(item.Description)
	detailBuf.WriteString(descWrapped + "\n\n")

	if item.Remediation != "" {
		detailBuf.WriteString("🛠️ Recommended Action:\n")
		remWrapped := lipgloss.NewStyle().
			Width(m.detailVP.Width).
			Render(item.Remediation)
		detailBuf.WriteString(remWrapped + "\n")
	}

	m.detailVP.SetContent(detailBuf.String())
}

func (m *Model) executeExport(fmtName string) tea.Cmd {
	m.mu.Lock()
	res := m.result
	if res == nil {
		m.exportStatus = "Error: No scan result available to export"
		m.mu.Unlock()
		return nil
	}
	m.exportStatus = "Exporting " + fmtName + " report..."
	m.mu.Unlock()

	return func() tea.Msg {
		ext := fmtName
		if fmtName == "cyclonedx" {
			ext = "cyclonedx.json"
		} else if fmtName == "spdx" {
			ext = "spdx.json"
		}

		fileName := fmt.Sprintf("vigil-export-%d.%s", time.Now().Unix(), ext)
		file, err := os.Create(fileName)
		if err != nil {
			return ExportDoneMsg{Err: fmt.Errorf("create export file: %w", err)}
		}
		defer file.Close()

		var exportErr error
		switch fmtName {
		case "json":
			exportErr = export.JSON(res, file)
		case "csv":
			exportErr = export.CSV(res, file)
		case "markdown":
			exportErr = export.Markdown(res, file)
		case "cyclonedx":
			exportErr = export.CycloneDX(res, file)
		case "spdx":
			exportErr = export.SPDX(res, file)
		}
		return ExportDoneMsg{FileName: fileName, Err: exportErr}
	}
}

// View renders the Lazygit/btm style Fullscreen DevSecOps Multi-Pane TUI
func (m *Model) View() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.progress.Error != "" {
		return m.renderError()
	}

	switch m.state {
	case StateScanning:
		return m.renderScanning()
	case StateExplorer:
		return m.renderLazygitExplorer()
	case StateExportModal:
		return m.renderExportModal()
	case StateHelp:
		return m.renderHelp()
	default:
		return m.renderScanning()
	}
}

func (m *Model) renderScanning() string {
	var sections []string
	header := m.styles.Header.Render(fmt.Sprintf("🛡️ VIGIL DEVSECOPS SCANNER %s", m.spinner.View()))
	sections = append(sections, header)

	bodyHeight := m.height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	availWidth := m.width - 2
	if availWidth < 20 {
		availWidth = 20
	}

	// Calculate dynamic table column widths for scanning view
	domainColWidth, sevColWidth, targetColWidth, idColWidth, reasonColWidth := calculateColumnWidths(availWidth)
	m.tableTargetColWidth = targetColWidth
	m.tableIDColWidth = idColWidth
	m.tableReasonColWidth = reasonColWidth

	m.vulnTable.SetColumns([]table.Column{
		{Title: "DOMAIN", Width: domainColWidth},
		{Title: "SEVERITY", Width: sevColWidth},
		{Title: "TARGET / PACKAGE", Width: targetColWidth},
		{Title: "ID / RULE", Width: idColWidth},
		{Title: "REASON SUMMARY", Width: reasonColWidth},
	})
	m.vulnTable.SetWidth(availWidth - 4)
	m.vulnTable.SetHeight(bodyHeight - 8)

	var scanBody []string
	scanBody = append(scanBody, m.styles.Title.Render("⚡ Active Phase: [1/4] Dependency Vulnerability Analysis (10 Parallel Workers)"))

	if m.progress.Total > 0 {
		percent := float64(m.progress.Current) / float64(m.progress.Total)
		if percent > 1.0 {
			percent = 1.0
		}
		barWidth := 34
		filled := int(percent * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		scanBody = append(scanBody, fmt.Sprintf("Progress: [%s] %d%% (%d/%d packages)", bar, int(percent*100), m.progress.Current, m.progress.Total))
	}

	if m.progress.CurrentPkg != "" {
		scanBody = append(scanBody, fmt.Sprintf("Current Target: %s", m.styles.Subtitle.Render(m.progress.CurrentPkg)))
	}

	elapsed := time.Since(m.startTime).Seconds()
	scanBody = append(scanBody, fmt.Sprintf("󰥔 Elapsed: %.0fs | Found Vulnerabilities: %d", elapsed, len(m.vulns)))

	if len(m.activityLogs) > 0 {
		scanBody = append(scanBody, "", m.styles.Title.Render("󱇤 Real-Time Activity Log:"))
		scanBody = append(scanBody, m.activityLogs...)
	}

	if len(m.vulns) > 0 {
		scanBody = append(scanBody, "", m.styles.Title.Render("󰍜 Live Vulnerabilities Stream:"), m.vulnTable.View())
	}

	boxContent := strings.Join(scanBody, "\n")
	scanPaneBox := RenderPaneBorder("󰥔 Full-Spectrum Security Scan in Progress", boxContent, availWidth, bodyHeight, true)
	sections = append(sections, scanPaneBox)

	footer := m.styles.StatusBar.Render("Press [q] to cancel scanning")
	sections = append(sections, footer)

	return strings.Join(sections, "\n")
}

func (m *Model) renderLazygitExplorer() string {
	var sections []string

	// 1. Top Header Banner with Policy Decision, Evidence State, Coverage, and Threat Intel status
	vulnCount := len(m.vulns)
	covText := "Coverage: n/a"
	decisionText := "DECISION: PENDING"
	evidenceText := "EVIDENCE: UNVERIFIED"
	tiText := ""
	if m.result != nil {
		vulnCount = m.result.TotalVulns
		if m.result.Coverage.TotalPackages > 0 {
			covText = fmt.Sprintf("Coverage: %d/%d", m.result.Coverage.ScannedPackages, m.result.Coverage.TotalPackages)
		}
		if m.result.ThreatIntel.KEV.Status != "" {
			tiText = fmt.Sprintf(" | KEV: %s | EPSS: %s", m.result.ThreatIntel.KEV.Status, m.result.ThreatIntel.EPSS.Status)
		}
	}
	if m.evaluation != nil {
		decisionText = fmt.Sprintf("DECISION: %s", m.evaluation.OverallDecision)
		evidenceText = fmt.Sprintf("EVIDENCE: %s", m.evaluation.EvidenceState)
	}

	headerText := fmt.Sprintf("🛡️ VIGIL SECURITY ASSESSMENT | %s | %s | %s%s | %d VULNS | %d SECRETS | %d IAC",
		decisionText, evidenceText, covText, tiText, vulnCount, len(m.secretFindings), len(m.iacIssues))
	sections = append(sections, m.styles.Header.Render(headerText))

	// 2. Navigation Tabs Bar
	tabs := []string{"[1] Vulns (SCA)", "[2] Secrets", "[3] IaC Security", "[4] Licenses", "[5] Dep Graph"}
	var renderedTabs []string
	for i, tab := range tabs {
		if ActiveTab(i) == m.activeTab {
			renderedTabs = append(renderedTabs, m.styles.ActiveTab.Render(tab))
		} else {
			renderedTabs = append(renderedTabs, m.styles.InactiveTab.Render(tab))
		}
	}
	tabsRow := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	sections = append(sections, tabsRow)

	// 3. Filter & Search Bar with Visual Badges
	var filterBadges []string

	// Severity badges (show which are active)
	severities := []struct {
		name  string
		key   string
		color lipgloss.Color
	}{
		{"CRIT", "critical", lipgloss.Color("#FF5555")},
		{"HIGH", "high", lipgloss.Color("#FFB86C")},
		{"MED", "medium", lipgloss.Color("#F1FA8C")},
		{"LOW", "low", lipgloss.Color("#8BE9FD")},
	}

	activeSevs := make(map[string]bool)
	if m.filterSeverity != "" {
		for _, sev := range strings.Split(m.filterSeverity, ",") {
			activeSevs[strings.TrimSpace(strings.ToLower(sev))] = true
		}
	}

	for _, sev := range severities {
		if len(activeSevs) == 0 || activeSevs[sev.key] {
			badge := lipgloss.NewStyle().Foreground(sev.color).Bold(true).Render("●" + sev.name)
			filterBadges = append(filterBadges, badge)
		} else {
			badge := lipgloss.NewStyle().Foreground(lipgloss.Color("#44475A")).Render("○" + sev.name)
			filterBadges = append(filterBadges, badge)
		}
	}

	searchStr := ""
	if m.searchQuery != "" {
		searchStr = fmt.Sprintf(" | Search: %q", m.searchQuery)
	}
	if m.isSearching {
		searchStr = fmt.Sprintf(" | Search: %q █", m.searchQuery)
	}

	markedCount := len(m.markedFixed)
	markedStr := ""
	if markedCount > 0 {
		markedStr = fmt.Sprintf(" | Hidden: %d", markedCount)
	}

	filterBar := fmt.Sprintf("%s%s%s | Findings: %d",
		strings.Join(filterBadges, " "),
		searchStr,
		markedStr,
		len(m.filteredItems),
	)
	sections = append(sections, m.styles.FilterBar.Render(filterBar))

	// 4. Single-Pane Layout (optional detail expansion)
	bodyHeight := m.height - 4
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	availWidth := m.width - 2
	if availWidth < 30 {
		availWidth = 30
	}

	if m.isDetailExpanded {
		// Show table + detail pane
		tableHeight := bodyHeight / 2
		detailHeight := bodyHeight - tableHeight

		tableBox := RenderPaneBorder("󰍜 Security Findings", m.vulnTable.View(), availWidth, tableHeight, true)

		// Combined detail view
		var detailBuf strings.Builder
		if m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
			item := m.filteredItems[m.selectedIdx]
			detailBuf.WriteString(fmt.Sprintf("Package: %s@%s | %s | CVSS: %.1f\n", item.Package, item.Version, RenderSeverityBadge(item.Severity, m.styles), item.CVSS))
			detailBuf.WriteString(strings.Repeat("─", availWidth-6) + "\n\n")
			detailBuf.WriteString("Reason: " + item.ReasonFlagged + "\n\n")
			if len(item.DependencyPath) > 0 {
				detailBuf.WriteString("Chain: " + strings.Join(item.DependencyPath, " → ") + "\n\n")
			}
			detailBuf.WriteString("Description: " + item.Description + "\n\n")
			detailBuf.WriteString("Fix: " + item.Remediation)
		} else {
			detailBuf.WriteString("No item selected")
		}

		detailBox := RenderPaneBorder("󰈔 Details (Enter to collapse)", detailBuf.String(), availWidth, detailHeight, false)
		sections = append(sections, lipgloss.JoinVertical(lipgloss.Left, tableBox, detailBox))
	} else {
		// Show table only (full height)
		tableBox := RenderPaneBorder("󰍜 Security Findings (Enter to expand details)", m.vulnTable.View(), availWidth, bodyHeight, true)
		sections = append(sections, tableBox)
	}

	// 5. Status / Footer Bar
	if m.exportStatus != "" {
		sections = append(sections, m.styles.KeyHint.Render("󰄬 "+m.exportStatus))
	}

	// Build context-aware status bar
	statusParts := []string{
		"[↑/↓/h/l] Navigate",
		"[Enter] Details",
		"[y] Copy",
		"[x/X/v] Hide/Restore",
		"[s] Reveal Secret",
		"[1-5] Tab",
		"[C/H/M/L] Filter",
		"[/] Search",
		"[e] Export",
		"[?] Help",
		"[q] Quit",
	}
	footer := m.styles.StatusBar.Render(strings.Join(statusParts, " | "))
	sections = append(sections, footer)

	return strings.Join(sections, "\n")
}

func (m *Model) renderExportModal() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("󰈔 VIGIL EXPORT REPORT DIALOG") + "\n\n")
	b.WriteString("Select export format:\n\n")
	b.WriteString("  [1] JSON Format (.json)\n")
	b.WriteString("  [2] CSV Spreadsheet (.csv)\n")
	b.WriteString("  [3] Markdown Report (.md)\n")
	b.WriteString("  [4] CycloneDX v1.5 SBOM (.cyclonedx.json)\n")
	b.WriteString("  [5] SPDX v2.3 SBOM (.spdx.json)\n\n")
	b.WriteString(m.styles.Subtitle.Render("Press [1-5] to export, or [Esc] to cancel"))

	return m.styles.ModalBox.Render(b.String())
}

func (m *Model) renderHelp() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("󰋗 VIGIL KEYBOARD SHORTCUTS") + "\n\n")

	b.WriteString(m.styles.Subtitle.Render("Navigation:") + "\n")
	b.WriteString("  j/k or ↓/↑       Move down/up in table\n")
	b.WriteString("  h/l              Switch pane left/right (vim style)\n")
	b.WriteString("  Tab              Cycle through panes\n")
	b.WriteString("  Enter            Expand/collapse detail view\n\n")

	b.WriteString(m.styles.Subtitle.Render("Tabs:") + "\n")
	b.WriteString("  1-5              Switch between tabs (Vulns/Secrets/IaC/Licenses/Graph)\n\n")

	b.WriteString(m.styles.Subtitle.Render("Filtering:") + "\n")
	b.WriteString("  C/H/M/L          Filter by Critical/High/Medium/Low severity\n")
	b.WriteString("  a or Esc         Clear all filters\n")
	b.WriteString("  /                Search (type to filter, Enter to exit)\n\n")

	b.WriteString(m.styles.Subtitle.Render("Actions:") + "\n")
	b.WriteString("  y                Copy CVE ID to clipboard\n")
	b.WriteString("  x/X              Mark/unmark item as fixed (hide from view)\n")
	b.WriteString("  g                Cycle grouping mode (None/Package/Severity)\n")
	b.WriteString("  e                Export report dialog\n")
	b.WriteString("  w                Maximize/restore window\n\n")

	b.WriteString(m.styles.Subtitle.Render("Other:") + "\n")
	b.WriteString("  ?                Show this help\n")
	b.WriteString("  q                Quit\n")
	b.WriteString("  Ctrl+C           Force quit\n\n")

	b.WriteString(m.styles.Subtitle.Render("Press [?], [q], or [Esc] to close"))

	return m.styles.ModalBox.Render(b.String())
}

func (m *Model) renderError() string {
	return fmt.Sprintf("\n[!] Vigil Error: %s\nPress q to exit.\n", m.progress.Error)
}

func groupFindingsByPackage(items []TUIFinding) []TUIFinding {
	groupedMap := make(map[string][]TUIFinding)
	for _, item := range items {
		groupedMap[item.Package] = append(groupedMap[item.Package], item)
	}

	pkgs := make([]string, 0, len(groupedMap))
	for pkg := range groupedMap {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	var result []TUIFinding
	for _, pkg := range pkgs {
		list := groupedMap[pkg]
		headerFinding := TUIFinding{
			Key:           "GROUP|PKG|" + pkg,
			Domain:        "GROUP",
			Package:       pkg,
			ID:            fmt.Sprintf("(%d items)", len(list)),
			Severity:      list[0].Severity,
			ReasonFlagged: fmt.Sprintf("Package group containing %d security items", len(list)),
			IsGroupHeader: true,
		}
		result = append(result, headerFinding)
		result = append(result, list...)
	}
	return result
}

// copyToClipboard copies text to system clipboard using platform-specific commands.
func copyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		// Try xclip first, fallback to xsel
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("no clipboard tool found (install xclip or xsel)")
		}
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := stdin.Write([]byte(text)); err != nil {
		return err
	}

	stdin.Close()
	return cmd.Wait()
}

func groupFindingsBySeverity(items []TUIFinding) []TUIFinding {
	groupedMap := make(map[string][]TUIFinding)
	for _, item := range items {
		sev := strings.ToLower(strings.TrimSpace(item.Severity))
		if sev == "" {
			sev = "unknown"
		}
		groupedMap[sev] = append(groupedMap[sev], item)
	}

	var result []TUIFinding
	order := []string{"critical", "high", "medium", "low", "unknown", "secret", "iac"}
	for _, sev := range order {
		if list, ok := groupedMap[sev]; ok && len(list) > 0 {
			headerFinding := TUIFinding{
				Key:           "GROUP|SEV|" + sev,
				Domain:        "GROUP",
				Package:       strings.ToUpper(sev),
				ID:            fmt.Sprintf("(%d items)", len(list)),
				Severity:      sev,
				ReasonFlagged: fmt.Sprintf("Severity category %s", strings.ToUpper(sev)),
				IsGroupHeader: true,
			}
			result = append(result, headerFinding)
			result = append(result, list...)
		}
	}
	return result
}
