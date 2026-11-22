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

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
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

// Model represents the Vigil Security Assessment TUI state.
type Model struct {
	activeTab           ActiveTab
	activePane          ActivePane
	state               ViewState
	isMaximized         bool
	isDetailExpanded    bool
	projectPath         string
	lockFileName        string
	workerCount         int
	stages              []StageState
	progress            ScanProgress
	startTime           time.Time
	result              *types.ScanResult
	evaluation          *policy.EvaluationResult
	graph               *types.DependencyGraph
	vulns               []VulnEntry
	secretFindings      []secrets.SecretFinding
	iacIssues           []container.SecurityIssue
	licenseFindings     []license.LicenseFinding
	filteredItems       []TUIFinding
	markedFixed         map[string]bool // Canonical finding Key -> locally hidden
	revealedSecrets     map[string]bool // Canonical secret Key -> explicitly revealed by user
	showHidden          bool
	spinner             spinner.Model
	vulnTable           table.Model
	styles              Styles
	width               int
	height              int
	selectedIdx         int
	filterSeverity      string // "" (default: show all findings) or comma-separated severities
	quickFilter         string // "", "block", "review", "kev"
	searchQuery         string
	isSearching         bool
	groupMode           GroupMode
	sortMode            SortMode
	exportStatus        string
	tableDecisionWidth  int
	tableDomainWidth    int
	tableSeverityWidth  int
	tableTargetColWidth int
	tableIDColWidth     int
	tableReasonColWidth int
	activityLogs        []string
	cancelFunc          func()
	mu                  sync.Mutex
}

// ProgressMsg updates scan progress.
type ProgressMsg struct {
	Progress ScanProgress
}

// VulnMsg adds a preliminary vulnerability entry during scanning.
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
// Default filter is empty ("") so all findings (including Medium, Low, and Unknown) are visible
// and sorted by policy decision priority (BLOCK > REVIEW > ALLOW).
func NewModel() *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9"))

	columns := []table.Column{
		{Title: "DECISION", Width: 10},
		{Title: "DOMAIN", Width: 8},
		{Title: "SEVERITY", Width: 10},
		{Title: "COMPONENT", Width: 24},
		{Title: "ID / RULE", Width: 18},
		{Title: "SIGNAL & REASON", Width: 34},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(12),
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

	m := &Model{
		activeTab:        TabVulnerabilities,
		activePane:       PaneTable,
		state:            StateScanning,
		startTime:        time.Now(),
		stages:           defaultStages(),
		workerCount:      10,
		markedFixed:      make(map[string]bool),
		revealedSecrets:  make(map[string]bool),
		spinner:          s,
		vulnTable:        t,
		styles:           DefaultStyles(),
		width:            120,
		height:           35,
		filterSeverity:   "", // Show all findings by default
		sortMode:         SortDecisionPriority,
		isDetailExpanded: false,
	}
	m.recalculateLayoutLocked()
	return m
}

// SetTargetMetadata records the scanned project path and lockfile name for the Scan header.
func (m *Model) SetTargetMetadata(projectPath, lockFile string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.projectPath = projectPath
	m.lockFileName = lockFile
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
		if graph == nil && result.Graph != nil {
			graph = result.Graph
		}
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
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles key presses, window resizing, and typed stage transitions.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		m.mu.Lock()
		m.width = msg.Width
		m.height = msg.Height
		m.recalculateLayoutLocked()
		m.mu.Unlock()
		return m, nil
	case StageEventMsg:
		m.mu.Lock()
		m.applyStageEventLocked(msg)
		m.mu.Unlock()
		return m, nil
	case ProgressMsg:
		m.mu.Lock()
		m.progress = msg.Progress
		if msg.Progress.CurrentPkg != "" && msg.Progress.CurrentPkg != "Starting scan..." {
			timestamp := time.Now().Format("15:04:05")
			logLine := fmt.Sprintf("  [%s] Scanned %s (%d/%d)", timestamp, msg.Progress.CurrentPkg, msg.Progress.Current, msg.Progress.Total)
			m.activityLogs = append(m.activityLogs, logLine)
			if len(m.activityLogs) > 8 {
				m.activityLogs = m.activityLogs[len(m.activityLogs)-8:]
			}
		}
		m.mu.Unlock()
		return m, nil
	case VulnMsg:
		m.mu.Lock()
		m.vulns = append(m.vulns, msg.Entry)
		timestamp := time.Now().Format("15:04:05")
		sevUpper := strings.ToUpper(msg.Entry.Severity)
		logLine := fmt.Sprintf("  [%s] Advisory in %s (%s - %s)", timestamp, msg.Entry.Package, sevUpper, msg.Entry.CVE)
		m.activityLogs = append(m.activityLogs, logLine)
		if len(m.activityLogs) > 8 {
			m.activityLogs = m.activityLogs[len(m.activityLogs)-8:]
		}
		m.mu.Unlock()
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
		if m.graph == nil && msg.Result != nil {
			m.graph = msg.Result.Graph
		}
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
		m.recalculateLayoutLocked()
		m.applyFiltersLocked()
		m.mu.Unlock()
		return m, nil
	case ExportDoneMsg:
		m.mu.Lock()
		if msg.Err != nil {
			m.exportStatus = fmt.Sprintf("Export failed: %v", msg.Err)
		} else {
			m.exportStatus = fmt.Sprintf("Exported report to %s", msg.FileName)
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

	if m.isSearching {
		switch key {
		case "enter", "esc":
			m.isSearching = false
			return m, nil
		case "backspace":
			if len(m.searchQuery) > 0 {
				runes := []rune(m.searchQuery)
				m.searchQuery = string(runes[:len(runes)-1])
				m.applyFilters()
			}
			return m, nil
		default:
			if len([]rune(key)) == 1 {
				m.searchQuery += key
				m.applyFilters()
			}
			return m, nil
		}
	}

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
		case "6":
			return m, m.executeExport("sarif")
		}
		return m, nil
	}

	if m.state == StateHelp {
		switch key {
		case "esc", "q", "?":
			m.state = StateExplorer
		}
		return m, nil
	}

	switch m.state {
	case StateScanning:
		switch key {
		case "q", "c":
			if m.cancelFunc != nil {
				m.cancelFunc()
			}
			return m, tea.Quit
		case "?":
			m.state = StateHelp
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
		case "o":
			m.switchToTab(TabOverview)
		case "i":
			m.switchToTab(TabEvidence)
		case "g":
			m.groupMode = (m.groupMode + 1) % 4
			m.applyFilters()
		case "f":
			m.cycleQuickFilter()
			m.applyFilters()
		case "s":
			// If on Secrets tab (or a SECRET finding is selected), toggle reveal for ONLY the selected secret.
			// Otherwise cycle sort order (Decision Priority -> Severity -> CVSS -> Package).
			if m.activeTab == TabSecrets || (m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) && m.filteredItems[m.selectedIdx].Domain == "SECRET") {
				m.toggleSelectedSecretReveal()
			} else {
				m.sortMode = (m.sortMode + 1) % 4
				m.exportStatus = "Sort: " + sortModeLabel(m.sortMode)
				m.applyFilters()
			}
		case "r":
			m.toggleSelectedSecretReveal()
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
			if m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
				item := m.filteredItems[m.selectedIdx]
				if item.IsGroupHeader {
					m.exportStatus = "Group header selected (select a finding row to copy ID)"
					return m, nil
				}
				if copyToClipboard(item.ID) == nil {
					m.exportStatus = "Copied " + item.ID + " to clipboard"
				} else {
					m.exportStatus = "Failed to copy to clipboard"
				}
			}
		case "x":
			if m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
				item := m.filteredItems[m.selectedIdx]
				if item.IsGroupHeader {
					m.exportStatus = "Cannot hide a group header"
					return m, nil
				}
				k := item.Key
				if k == "" {
					k = item.ID + "|" + item.Package + "@" + item.Version
				}
				if m.markedFixed[k] {
					delete(m.markedFixed, k)
					m.exportStatus = "Unhidden locally: " + item.ID + " (" + item.Package + ")"
				} else {
					m.markedFixed[k] = true
					m.exportStatus = "Hidden locally (not remediated): " + item.ID + " (" + item.Package + ")"
				}
				m.applyFilters()
			}
		case "X":
			count := len(m.markedFixed)
			m.markedFixed = make(map[string]bool)
			m.showHidden = false
			m.exportStatus = fmt.Sprintf("Restored %d locally hidden finding(s)", count)
			m.applyFilters()
		case "v":
			m.showHidden = !m.showHidden
			if m.showHidden {
				m.exportStatus = "Showing locally hidden findings (press [x] to unhide)"
			} else {
				m.exportStatus = "Hiding locally hidden findings"
			}
			m.applyFilters()
		case "enter":
			m.isDetailExpanded = !m.isDetailExpanded
			m.mu.Lock()
			m.recalculateLayoutLocked()
			m.mu.Unlock()
		case "a":
			m.filterSeverity = ""
			m.quickFilter = ""
			m.searchQuery = ""
			m.exportStatus = "Cleared all filters"
			m.applyFilters()
		case "esc":
			if m.isDetailExpanded {
				m.isDetailExpanded = false
				m.mu.Lock()
				m.recalculateLayoutLocked()
				m.mu.Unlock()
			} else {
				m.exportStatus = ""
			}
		case "tab", "l":
			m.activePane = (m.activePane + 1) % 4
		case "h":
			m.activePane = (m.activePane + 3) % 4
		case "w":
			m.isMaximized = !m.isMaximized
			m.mu.Lock()
			m.recalculateLayoutLocked()
			m.mu.Unlock()
		case "up", "k", "down", "j":
			// Always navigate the active findings table — never trap j/k focus in an invisible pane.
			var cmd tea.Cmd
			m.vulnTable, cmd = m.vulnTable.Update(msg)
			m.selectedIdx = m.vulnTable.Cursor()
			return m, cmd
		}
	}

	return m, nil
}

func (m *Model) toggleSelectedSecretReveal() {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filteredItems) {
		return
	}
	item := m.filteredItems[m.selectedIdx]
	if item.Domain != "SECRET" {
		m.exportStatus = "Select a secret finding to reveal or mask its value"
		return
	}
	if m.revealedSecrets[item.Key] {
		delete(m.revealedSecrets, item.Key)
		m.exportStatus = "Masked secret in " + item.Package
	} else {
		m.revealedSecrets[item.Key] = true
		m.exportStatus = "Revealed selected secret in " + item.Package + " (press [r] to mask)"
	}
	m.applyFilters()
}

func (m *Model) cycleQuickFilter() {
	order := []string{"", "block", "review", "kev", "critical,high"}
	for i, cur := range order {
		if m.quickFilter == cur {
			m.quickFilter = order[(i+1)%len(order)]
			break
		}
	}
	if m.quickFilter == "" {
		m.exportStatus = "Filter: All findings"
	} else {
		m.exportStatus = "Filter: " + strings.ToUpper(m.quickFilter)
	}
}

func sortModeLabel(mode SortMode) string {
	switch mode {
	case SortSeverity:
		return "Severity"
	case SortCVSS:
		return "CVSS Score"
	case SortPackage:
		return "Component Name"
	default:
		return "Decision Priority (BLOCK > REVIEW > ALLOW)"
	}
}

func (m *Model) applyFilters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyFiltersLocked()
}

func (m *Model) applyFiltersLocked() {
	var items []TUIFinding

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
				if f.KnownExploited {
					signals = append(signals, "KEV")
				}
				if f.EPSSScore > 0 {
					signals = append(signals, fmt.Sprintf("EPSS %.1f%%", f.EPSSScore*100))
				}
				if fd.IsNew {
					signals = append(signals, "NEW")
				}
				if fd.AcceptedRisk {
					signals = append(signals, "Accepted risk")
				}

				reasonParts := append([]string(nil), fd.Reasoning...)
				if f.EffectiveScoreReason != "" {
					reasonParts = append(reasonParts, "Provenance: "+f.EffectiveScoreReason)
				}
				reason := strings.Join(reasonParts, " ")
				if len(signals) > 0 {
					reason = fmt.Sprintf("[%s] %s", strings.Join(signals, " · "), reason)
				}

				depPath := pathByPkg[f.Package+"@"+f.Version]
				if len(depPath) == 0 && m.graph != nil {
					depPath = m.graph.GetVulnerablePath(f.Package + "@" + f.Version)
				}

				decLabel := string(fd.Decision)
				if fd.AcceptedRisk {
					decLabel = "ACCEPTED"
				}

				items = append(items, TUIFinding{
					Key:             f.Key,
					Domain:          "SCA",
					Decision:        decLabel,
					AcceptedRisk:    fd.AcceptedRisk,
					KnownExploited:  f.KnownExploited,
					EPSSScore:       f.EPSSScore,
					MatchedRule:     fd.MatchedRule,
					PURL:            f.PURL,
					Package:         f.Package,
					Version:         f.Version,
					ID:              f.ID,
					Aliases:         f.Aliases,
					Severity:        string(f.Severity),
					CVSS:            f.CVSSScore,
					Title:           f.Summary,
					Description:     f.Summary,
					ReasonFlagged:   reason,
					DependencyPath:  depPath,
					Remediation:     "Review affected versions and upgrade path; verify rule " + fd.MatchedRule,
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

				reason := fmt.Sprintf("%sA vulnerability affects %s (%s). Tracked upstream as %s (CVSS %.1f).", chainPrefix, v.Package, v.Version, cveID, v.CVSS)
				if v.CVEDescription != "" {
					reason = chainPrefix + v.CVEDescription
				}
				items = append(items, TUIFinding{
					Key:            fmt.Sprintf("%s|%s@%s", cveID, v.Package, v.Version),
					Domain:         "SCA",
					Decision:       "REVIEW",
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
			key := fmt.Sprintf("SECRET|%s:%d|%s", s.FilePath, s.LineNumber, s.Type)
			matchDisplay := secrets.MaskSecret(s.Match) + " (masked — press [r] to reveal selected secret)"
			if m.revealedSecrets[key] {
				matchDisplay = s.Match + " (REVEALED — press [r] to mask)"
			}
			items = append(items, TUIFinding{
				Key:           key,
				Domain:        "SECRET",
				Decision:      "BLOCK",
				Package:       relPath,
				ID:            string(s.Type),
				Severity:      "critical",
				Title:         fmt.Sprintf("Detected %s at line %d", s.Type, s.LineNumber),
				Description:   fmt.Sprintf("Credential pattern in %s:%d\nMatch: %s", s.FilePath, s.LineNumber, matchDisplay),
				ReasonFlagged: fmt.Sprintf("Secret pattern matching %s at line %d (Shannon entropy: %.2f)", s.Type, s.LineNumber, s.Entropy),
				Remediation:   "Rotate credential immediately and remove from version control history",
				RawSecret:     s,
			})
		}

	case TabIaC:
		for _, iac := range m.iacIssues {
			relPath := filepath.Base(iac.Source)
			dec := "REVIEW"
			if strings.EqualFold(string(iac.Severity), "critical") || strings.EqualFold(string(iac.Severity), "high") {
				dec = "BLOCK"
			}
			items = append(items, TUIFinding{
				Key:           fmt.Sprintf("IAC|%s:%d|%s", iac.Source, iac.LineNumber, iac.RuleID),
				Domain:        "IaC",
				Decision:      dec,
				Package:       relPath,
				ID:            iac.RuleID,
				Severity:      string(iac.Severity),
				Title:         iac.Title,
				Description:   iac.Message,
				ReasonFlagged: fmt.Sprintf("Rule %s: %s", iac.RuleID, iac.Message),
				Remediation:   "Update container or workflow configuration according to rule guidance",
				RawIaC:        iac,
			})
		}

	case TabLicenses:
		for _, lic := range m.licenseFindings {
			sev := "low"
			dec := "ALLOW"
			reason := "Permissive licence (e.g. MIT/Apache/BSD): review attribution and notice obligations"
			switch lic.Category {
			case license.Copyleft:
				sev = "medium"
				dec = "REVIEW"
				reason = "Reciprocal / copyleft licence (e.g. GPL/AGPL/MPL): review distribution and source disclosure obligations"
			case license.Unknown:
				sev = "unknown"
				dec = "REVIEW"
				reason = "Licence metadata not declared in lockfile (inspect package manifest or upstream registry)"
			}
			items = append(items, TUIFinding{
				Key:           fmt.Sprintf("LICENSE|%s@%s|%s", lic.PackageName, lic.Version, lic.License),
				Domain:        "LICENSE",
				Decision:      dec,
				Package:       lic.PackageName,
				Version:       lic.Version,
				ID:            lic.License,
				Severity:      sev,
				Title:         fmt.Sprintf("%s (%s)", lic.License, lic.Category),
				Description:   fmt.Sprintf("Component %s@%s declares licence %q (classification: %s)", lic.PackageName, lic.Version, lic.License, lic.Category),
				ReasonFlagged: reason,
				Remediation:   "Verify licence compatibility with your distribution model",
				RawLicense:    lic,
			})
		}

	case TabDependencyGraph:
		if m.graph != nil && len(m.graph.Nodes) > 0 {
			keys := make([]string, 0, len(m.graph.Nodes))
			for k := range m.graph.Nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				node := m.graph.Nodes[k]
				dec := string(node.ScanStatus)
				if dec == "" {
					dec = "scanned"
				}
				sev := "low"
				if len(node.Vulnerabilities) > 0 {
					sev = "high"
				} else if node.ScanStatus == types.StatusUnsupported || node.Ambiguous {
					sev = "unknown"
				}
				scopeLabel := "transitive"
				if node.Direct {
					scopeLabel = "direct"
				}
				if node.Ambiguous {
					scopeLabel = "ambiguous-edge"
				}
				items = append(items, TUIFinding{
					Key:            "GRAPH|" + k,
					Domain:         "GRAPH",
					Decision:       strings.ToUpper(dec),
					Package:        node.Name,
					Version:        node.Version,
					ID:             fmt.Sprintf("depth=%d (%s)", node.Depth, scopeLabel),
					Severity:       sev,
					Title:          fmt.Sprintf("%s@%s", node.Name, node.Version),
					Description:    fmt.Sprintf("Ecosystem: %s | Scope: %s (%s) | Depth: %d | Status: %s", node.Ecosystem, node.Type, scopeLabel, node.Depth, node.ScanStatus),
					ReasonFlagged:  fmt.Sprintf("%d advisory match(es) · %d child dep(s)", len(node.Vulnerabilities), len(node.Children)),
					DependencyPath: m.graph.GetVulnerablePath(k),
				})
			}
		} else if m.result != nil {
			for _, dep := range m.result.Dependencies {
				scopeLabel := "transitive"
				if dep.Direct {
					scopeLabel = "direct"
				}
				if dep.Ambiguous {
					scopeLabel = "ambiguous-edge"
				}
				items = append(items, TUIFinding{
					Key:           "GRAPH|" + dep.Name + "@" + dep.Version,
					Domain:        "GRAPH",
					Decision:      strings.ToUpper(string(dep.ScanStatus)),
					Package:       dep.Name,
					Version:       dep.Version,
					ID:            scopeLabel,
					Severity:      "low",
					Title:         fmt.Sprintf("%s@%s", dep.Name, dep.Version),
					Description:   fmt.Sprintf("Ecosystem: %s | Type: %s | Scope: %s | Status: %s", dep.Ecosystem, dep.Type, scopeLabel, dep.ScanStatus),
					ReasonFlagged: fmt.Sprintf("%d advisory match(es) · %d child dep(s)", len(dep.Vulnerabilities), len(dep.DependsOn)),
				})
			}
		}
	}

	var filtered []TUIFinding
	search := strings.ToLower(strings.TrimSpace(m.searchQuery))

	allowedSeverities := make(map[string]bool)
	sevFilter := m.filterSeverity
	if m.quickFilter == "critical,high" && sevFilter == "" {
		sevFilter = "critical,high"
	}
	if sevFilter != "" {
		for _, sev := range strings.Split(sevFilter, ",") {
			allowedSeverities[strings.TrimSpace(strings.ToLower(sev))] = true
		}
	}

	for _, item := range items {
		k := item.Key
		if k == "" {
			k = item.ID + "|" + item.Package + "@" + item.Version
		}
		if m.markedFixed[k] && !m.showHidden {
			continue
		}
		if m.activeTab == TabVulnerabilities && len(allowedSeverities) > 0 && !allowedSeverities[strings.ToLower(item.Severity)] {
			continue
		}
		switch m.quickFilter {
		case "block":
			if !strings.EqualFold(item.Decision, "BLOCK") {
				continue
			}
		case "review":
			if !strings.EqualFold(item.Decision, "REVIEW") {
				continue
			}
		case "kev":
			if !item.KnownExploited {
				continue
			}
		}
		if search != "" {
			haystack := strings.ToLower(item.Package + " " + item.Version + " " + item.PURL + " " + item.ID + " " + item.Decision + " " + item.Title + " " + item.Description + " " + item.ReasonFlagged)
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	sortFindings(filtered, m.sortMode)

	switch m.groupMode {
	case GroupPackage:
		filtered = groupFindingsByPackage(filtered)
	case GroupSeverity:
		filtered = groupFindingsBySeverity(filtered)
	case GroupDecision:
		filtered = groupFindingsByDecision(filtered)
	}

	m.filteredItems = filtered
	if m.selectedIdx >= len(m.filteredItems) {
		m.selectedIdx = 0
		m.vulnTable.SetCursor(0)
	}
	m.updateTableRowsLocked()
}

func sortFindings(items []TUIFinding, mode SortMode) {
	decRank := func(d string) int {
		switch strings.ToUpper(d) {
		case "BLOCK":
			return 4
		case "REVIEW":
			return 3
		case "ACCEPTED":
			return 2
		default:
			return 1
		}
	}
	sevRank := func(s string) int {
		switch strings.ToLower(s) {
		case "critical", "secret":
			return 5
		case "high":
			return 4
		case "medium":
			return 3
		case "low":
			return 2
		default:
			return 1
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		switch mode {
		case SortSeverity:
			if sevRank(a.Severity) != sevRank(b.Severity) {
				return sevRank(a.Severity) > sevRank(b.Severity)
			}
		case SortCVSS:
			if a.CVSS != b.CVSS {
				return a.CVSS > b.CVSS
			}
		case SortPackage:
			if a.Package != b.Package {
				return a.Package < b.Package
			}
		default:
			if decRank(a.Decision) != decRank(b.Decision) {
				return decRank(a.Decision) > decRank(b.Decision)
			}
			if a.KnownExploited != b.KnownExploited {
				return a.KnownExploited
			}
			if sevRank(a.Severity) != sevRank(b.Severity) {
				return sevRank(a.Severity) > sevRank(b.Severity)
			}
			if a.CVSS != b.CVSS {
				return a.CVSS > b.CVSS
			}
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.ID < b.ID
	})
}

func (m *Model) recalculateLayoutLocked() {
	bodyHeight := m.height - 5
	if bodyHeight < 8 {
		bodyHeight = 8
	}
	tableHeight := bodyHeight - 3
	if m.isDetailExpanded {
		tableHeight = (bodyHeight / 2) - 3
	}
	if tableHeight < 4 {
		tableHeight = 4
	}

	availWidth := m.width - 2
	if availWidth < 40 {
		availWidth = 40
	}

	decW, domW, sevW, targetW, idW, reasonW := calculateColumnWidths(availWidth)
	m.tableDecisionWidth = decW
	m.tableDomainWidth = domW
	m.tableSeverityWidth = sevW
	m.tableTargetColWidth = targetW
	m.tableIDColWidth = idW
	m.tableReasonColWidth = reasonW

	m.vulnTable.SetColumns([]table.Column{
		{Title: "DECISION", Width: decW},
		{Title: "DOMAIN", Width: domW},
		{Title: "SEVERITY", Width: sevW},
		{Title: "COMPONENT", Width: targetW},
		{Title: "ID / RULE", Width: idW},
		{Title: "SIGNAL & REASON", Width: reasonW},
	})
	m.vulnTable.SetWidth(availWidth - 4)
	m.vulnTable.SetHeight(tableHeight)
	m.updateTableRowsLocked()
}

func calculateColumnWidths(availWidth int) (decision, domain, severity, target, id, reason int) {
	inner := availWidth - 20
	if inner < 42 {
		inner = 42
	}
	if availWidth <= 85 {
		decision = 8
		domain = 6
		severity = 8
		rem := inner - decision - domain - severity
		target = rem / 3
		id = rem / 3
		reason = rem - target - id
		if reason < 8 {
			reason = 8
		}
		return
	}
	decision = 10
	domain = 8
	severity = 10
	rem := inner - decision - domain - severity
	target = int(float64(rem) * 0.25)
	id = int(float64(rem) * 0.22)
	reason = rem - target - id
	if reason < 12 {
		reason = 12
	}
	return
}

func (m *Model) updateTableRowsLocked() {
	decW := m.tableDecisionWidth
	if decW <= 0 {
		decW = 10
	}
	domW := m.tableDomainWidth
	if domW <= 0 {
		domW = 8
	}
	sevW := m.tableSeverityWidth
	if sevW <= 0 {
		sevW = 10
	}
	targetW := m.tableTargetColWidth
	if targetW <= 0 {
		targetW = 20
	}
	idW := m.tableIDColWidth
	if idW <= 0 {
		idW = 18
	}
	reasonW := m.tableReasonColWidth
	if reasonW <= 0 {
		reasonW = 30
	}

	rows := make([]table.Row, 0, len(m.filteredItems))
	for _, item := range m.filteredItems {
		comp := item.Package
		if item.Version != "" && !strings.Contains(comp, "@") {
			comp = comp + "@" + item.Version
		}
		dec := item.Decision
		if dec == "" {
			dec = "REVIEW"
		}
		rows = append(rows, table.Row{
			truncateRunes(dec, decW),
			truncateRunes(item.Domain, domW),
			truncateRunes(strings.ToUpper(item.Severity), sevW),
			truncateRunes(comp, targetW),
			truncateRunes(item.ID, idW),
			truncateRunes(item.ReasonFlagged, reasonW),
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

func (m *Model) executeExport(fmtName string) tea.Cmd {
	m.mu.Lock()
	res := m.result
	evalPtr := m.evaluation
	if res == nil {
		m.exportStatus = "Error: No scan result available to export"
		m.mu.Unlock()
		return nil
	}
	m.exportStatus = "Exporting " + fmtName + " report..."
	m.mu.Unlock()

	return func() tea.Msg {
		ext := fmtName
		switch fmtName {
		case "cyclonedx":
			ext = "cyclonedx.json"
		case "spdx":
			ext = "spdx.json"
		case "sarif":
			ext = "sarif.json"
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
		case "sarif":
			var eval policy.EvaluationResult
			if evalPtr != nil {
				eval = *evalPtr
			} else {
				eval = policy.Evaluate(res, policy.DefaultPolicy(), nil, time.Now().UTC())
			}
			exportErr = policy.WriteSARIF(file, res.LockFile, eval)
		}
		return ExportDoneMsg{FileName: fileName, Err: exportErr}
	}
}

// View renders the current TUI screen as a pure function of model state.
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
		return m.renderExplorer()
	case StateExportModal:
		return m.renderExportModal()
	case StateHelp:
		return m.renderHelp()
	default:
		return m.renderScanning()
	}
}

func (m *Model) renderExplorer() string {
	var sections []string

	availWidth := m.width - 2
	if availWidth < 40 {
		availWidth = 40
	}
	bodyHeight := m.height - 5
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	// 1. Top Assessment Header
	decisionText := "DECISION: PENDING"
	evidenceText := "EVIDENCE: UNVERIFIED"
	resText := ""
	covText := "Coverage: n/a"
	if m.evaluation != nil {
		decisionText = fmt.Sprintf("DECISION: %s", m.evaluation.OverallDecision)
		evidenceText = fmt.Sprintf("EVIDENCE: %s", m.evaluation.EvidenceState)
		if m.evaluation.Resolution != nil && m.evaluation.Resolution.Completeness != "" {
			resText = fmt.Sprintf(" | RESOLUTION: %s", strings.ToUpper(string(m.evaluation.Resolution.Completeness)))
		}
	}
	if m.result != nil && m.result.Coverage.TotalPackages > 0 {
		covText = fmt.Sprintf("Coverage: %d/%d", m.result.Coverage.ScannedPackages, m.result.Coverage.TotalPackages)
	}
	headerText := fmt.Sprintf("VIGIL / ASSESSMENT | %s | %s%s | %s",
		decisionText, evidenceText, resText, covText)
	sections = append(sections, m.styles.Header.Render(truncateRunes(headerText, availWidth)))

	// 2. Navigation Tabs Bar
	type tabItem struct {
		tab   ActiveTab
		label string
	}
	tabs := []tabItem{
		{TabVulnerabilities, "[1] Findings (SCA)"},
		{TabSecrets, fmt.Sprintf("[2] Secrets (%d)", len(m.secretFindings))},
		{TabIaC, fmt.Sprintf("[3] IaC (%d)", len(m.iacIssues))},
		{TabLicenses, fmt.Sprintf("[4] Licences (%d)", len(m.licenseFindings))},
		{TabDependencyGraph, "[5] Dep Graph"},
		{TabOverview, "[o] Overview"},
		{TabEvidence, "[i] Evidence"},
	}
	var renderedTabs []string
	for _, t := range tabs {
		if t.tab == m.activeTab {
			renderedTabs = append(renderedTabs, m.styles.ActiveTab.Render(t.label))
		} else {
			renderedTabs = append(renderedTabs, m.styles.InactiveTab.Render(t.label))
		}
	}
	sections = append(sections, lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...))

	// 3. Dedicated Overview or Evidence screens
	if m.activeTab == TabOverview {
		sections = append(sections, m.renderOverviewPane(availWidth, bodyHeight))
		sections = append(sections, m.renderFooter(availWidth))
		return strings.Join(sections, "\n")
	}
	if m.activeTab == TabEvidence {
		sections = append(sections, m.renderEvidencePane(availWidth, bodyHeight))
		sections = append(sections, m.renderFooter(availWidth))
		return strings.Join(sections, "\n")
	}

	// 4. Filter, Decision Breakdown & Sort Bar
	countsStr := fmt.Sprintf("Showing: %d", len(m.filteredItems))
	if m.evaluation != nil && m.activeTab == TabVulnerabilities {
		countsStr = fmt.Sprintf("BLOCK: %d · REVIEW: %d · ALLOW: %d (Accepted: %d) | Showing: %d",
			m.evaluation.BlockCount, m.evaluation.ReviewCount, m.evaluation.AllowCount, m.evaluation.SuppressedCount, len(m.filteredItems))
	}
	if len(m.markedFixed) > 0 {
		countsStr += fmt.Sprintf(" | Hidden: %d", len(m.markedFixed))
	}
	if m.quickFilter != "" {
		countsStr += fmt.Sprintf(" | Filter: %s", strings.ToUpper(m.quickFilter))
	}
	if m.searchQuery != "" || m.isSearching {
		countsStr += fmt.Sprintf(" | Search: %q", m.searchQuery)
	}
	sections = append(sections, m.styles.FilterBar.Render(truncateRunes(countsStr, availWidth)))

	// 5. Table + Optional Detail Explanation Pane
	if m.isDetailExpanded {
		tableHeight := bodyHeight / 2
		detailHeight := bodyHeight - tableHeight
		tableBox := RenderPaneBorder("Findings", m.vulnTable.View(), availWidth, tableHeight, true)
		detailBox := RenderPaneBorder("Selected Finding · Decision & Evidence (Enter / Esc to collapse)", m.renderSelectedDetail(availWidth-6), availWidth, detailHeight, false)
		sections = append(sections, lipgloss.JoinVertical(lipgloss.Left, tableBox, detailBox))
	} else {
		tableBox := RenderPaneBorder("Findings (Enter to inspect decision & provenance)", m.vulnTable.View(), availWidth, bodyHeight, true)
		sections = append(sections, tableBox)
	}

	if m.exportStatus != "" {
		sections = append(sections, m.styles.KeyHint.Render(truncateRunes(m.exportStatus, availWidth)))
	}
	sections = append(sections, m.renderFooter(availWidth))

	return strings.Join(sections, "\n")
}

func (m *Model) renderSelectedDetail(maxWidth int) string {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filteredItems) {
		return "No finding selected."
	}
	item := m.filteredItems[m.selectedIdx]
	var b strings.Builder

	riskNote := item.Decision
	if item.AcceptedRisk {
		riskNote = "ALLOW (FORMALLY ACCEPTED RISK via policy exception — not proof of safety)"
	}
	b.WriteString(fmt.Sprintf("Decision: %s | Severity: %s | CVSS: %.1f\n", riskNote, strings.ToUpper(item.Severity), item.CVSS))
	b.WriteString(fmt.Sprintf("Component: %s@%s", item.Package, item.Version))
	if item.PURL != "" {
		b.WriteString(fmt.Sprintf(" (%s)", item.PURL))
	}
	b.WriteString("\n")
	if item.MatchedRule != "" {
		b.WriteString(fmt.Sprintf("Matched Policy Rule: %s\n", item.MatchedRule))
	}
	if len(item.Aliases) > 0 {
		b.WriteString(fmt.Sprintf("Aliases: %s\n", strings.Join(item.Aliases, ", ")))
	}
	b.WriteString(fmt.Sprintf("Why Flagged: %s\n", item.ReasonFlagged))
	if len(item.DependencyPath) > 0 {
		b.WriteString(fmt.Sprintf("Dependency Path: %s\n", strings.Join(item.DependencyPath, " -> ")))
	}
	if len(item.MissingEvidence) > 0 {
		b.WriteString(fmt.Sprintf("Missing Evidence: %s\n", strings.Join(item.MissingEvidence, ", ")))
	}
	b.WriteString(fmt.Sprintf("Description: %s\n", truncateRunes(item.Description, maxWidth*2)))
	b.WriteString(fmt.Sprintf("Action: %s", item.Remediation))
	return b.String()
}

func (m *Model) renderFooter(availWidth int) string {
	if availWidth <= 95 {
		return m.styles.StatusBar.Render("[↑/↓] Move [Enter] Details [/] Search [f] Filter [s] Sort [g] Group [e] Export [?] Help [q] Quit")
	}
	parts := []string{
		"[↑/↓/j/k] Move",
		"[Enter] Details",
		"[/] Search",
		"[f] Filter",
		"[s] Sort",
		"[g] Group",
		"[x/X/v] Hide/Restore",
		"[r] Reveal Secret",
		"[e] Export",
		"[?] Help",
		"[q] Quit",
	}
	return m.styles.StatusBar.Render(strings.Join(parts, " | "))
}

func (m *Model) renderExportModal() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("VIGIL EXPORT REPORT") + "\n\n")
	b.WriteString("Select export format:\n\n")
	b.WriteString("  [1] JSON Report (.json)\n")
	b.WriteString("  [2] CSV Spreadsheet (.csv)\n")
	b.WriteString("  [3] Markdown Report (.md)\n")
	b.WriteString("  [4] CycloneDX v1.5 SBOM (.cyclonedx.json)\n")
	b.WriteString("  [5] SPDX v2.3 SBOM (.spdx.json)\n")
	b.WriteString("  [6] SARIF v2.1.0 Report (.sarif.json)\n\n")
	b.WriteString(m.styles.Subtitle.Render("Press [1-6] to export, or [Esc] to cancel"))

	return m.styles.ModalBox.Render(b.String())
}

func (m *Model) renderHelp() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("VIGIL KEYBOARD SHORTCUTS") + "\n\n")

	b.WriteString(m.styles.Subtitle.Render("Navigation & Views:") + "\n")
	b.WriteString("  j/k or ↓/↑       Move cursor in active table\n")
	b.WriteString("  Enter            Expand/collapse full decision & evidence details\n")
	b.WriteString("  1-5              Switch domain (Findings / Secrets / IaC / Licences / Dep Graph)\n")
	b.WriteString("  o / i            Assessment Overview / Evidence & Pipeline Stages\n\n")

	b.WriteString(m.styles.Subtitle.Render("Triage, Filtering & Sorting:") + "\n")
	b.WriteString("  /                Search by package, CVE, PURL, decision, or text\n")
	b.WriteString("  f                Cycle quick filters (All / BLOCK / REVIEW / KEV / Critical+High)\n")
	b.WriteString("  s                Cycle sort order (Decision Priority / Severity / CVSS / Component)\n")
	b.WriteString("  g                Cycle grouping mode (None / Package / Severity / Decision)\n")
	b.WriteString("  a                Clear all active filters and search\n\n")

	b.WriteString(m.styles.Subtitle.Render("Actions:") + "\n")
	b.WriteString("  y                Copy selected ID to clipboard\n")
	b.WriteString("  x / v / X        Hide selected finding locally / View hidden / Restore all\n")
	b.WriteString("  r                Reveal or mask ONLY the currently selected secret\n")
	b.WriteString("  e                Export report (JSON, CSV, Markdown, CycloneDX, SPDX, SARIF 2.1.0)\n")
	b.WriteString("  q / Ctrl+C       Quit (cancels active scan)\n\n")

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
			Decision:      list[0].Decision,
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
				Decision:      list[0].Decision,
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

func groupFindingsByDecision(items []TUIFinding) []TUIFinding {
	groupedMap := make(map[string][]TUIFinding)
	for _, item := range items {
		dec := strings.ToUpper(strings.TrimSpace(item.Decision))
		if dec == "" {
			dec = "REVIEW"
		}
		groupedMap[dec] = append(groupedMap[dec], item)
	}

	var result []TUIFinding
	order := []string{"BLOCK", "REVIEW", "ACCEPTED", "ALLOW"}
	for _, dec := range order {
		if list, ok := groupedMap[dec]; ok && len(list) > 0 {
			headerFinding := TUIFinding{
				Key:           "GROUP|DEC|" + dec,
				Domain:        "GROUP",
				Decision:      dec,
				Package:       dec,
				ID:            fmt.Sprintf("(%d items)", len(list)),
				Severity:      list[0].Severity,
				ReasonFlagged: fmt.Sprintf("Decision group %s", dec),
				IsGroupHeader: true,
			}
			result = append(result, headerFinding)
			result = append(result, list...)
		}
	}
	return result
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
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
