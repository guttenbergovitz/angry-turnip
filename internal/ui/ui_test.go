package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestModelInitialState verifies initial TUI model state.
func TestModelInitialState(t *testing.T) {
	m := NewModel()
	if m.state != StateScanning {
		t.Errorf("expected initial state StateScanning, got %v", m.state)
	}

	if m.progress.Completed {
		t.Errorf("expected initial progress completed false")
	}
}

// TestModelLazygitMultiPaneDashboard verifies panes, word-wrapping, tabs, secrets, IaC, licenses, reason flagged, and grouping.
func TestModelLazygitMultiPaneDashboard(t *testing.T) {
	m := NewModel()

	// Add test vulnerability
	m.AddVulnerability(VulnEntry{
		Package:        "log4j-core",
		Version:        "2.14.1",
		CVE:            "CVE-2021-44228",
		Severity:       "critical",
		CVSS:           10.0,
		Description:    "Remote code execution in Log4j2 JNDI feature affects certain React Server Components packages for versions 19.0.x",
		CVEDescription: "A vulnerability affects certain React Server Components packages for versions 19.0.x. A specially crafted HTTP request can be sent to any App Router Server Function endpoint.",
		DependencyPath: []string{"my-app", "spring-boot-starter-logging", "log4j-core"},
	})

	secList := []secrets.SecretFinding{
		{
			FilePath:    "config.env",
			LineNumber:  2,
			LineContent: "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
			Type:        secrets.AWSKey,
			Match:       "AKIAIOSFODNN7EXAMPLE",
			Entropy:     4.8,
		},
	}

	iacList := []container.SecurityIssue{
		{
			Source:     "Dockerfile",
			LineNumber: 1,
			RuleID:     "DOCKER-001",
			Title:      "Container Running as Root",
			Message:    "No USER instruction found",
			Severity:   container.High,
		},
	}

	licList := []license.LicenseFinding{
		{
			PackageName: "gpl-lib",
			Version:     "1.0.0",
			License:     "GPL-3.0",
			Category:    license.Copyleft,
		},
	}

	// Mark scan done with graph and full spectrum findings
	m.SetDone(&types.ScanResult{
		TotalVulns:    1,
		CriticalVulns: 1,
	}, nil, secList, iacList, licList)

	if m.state != StateExplorer {
		t.Errorf("expected transition to StateExplorer after SetDone, got %v", m.state)
	}

	// Test Tab 1: Vulnerabilities
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabVulnerabilities, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].ReasonFlagged == "" {
		t.Errorf("expected non-empty ReasonFlagged for SCA vulnerability")
	}

	// Test Lazygit Pane Focus Cycle (Tab)
	if m.activePane != PaneTable {
		t.Errorf("expected default active pane PaneTable, got %v", m.activePane)
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyTab})
	if m.activePane != PaneReason {
		t.Errorf("expected active pane PaneReason after Tab, got %v", m.activePane)
	}

	// Test Window Maximization (w)
	if m.isMaximized {
		t.Errorf("expected default isMaximized false")
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if !m.isMaximized {
		t.Errorf("expected isMaximized true after pressing 'w'")
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if m.isMaximized {
		t.Errorf("expected isMaximized false after pressing 'w' again")
	}

	// Test Tab 2: Secrets
	m.activeTab = TabSecrets
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabSecrets, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].Domain != "SECRET" {
		t.Errorf("expected domain SECRET, got %s", m.filteredItems[0].Domain)
	}

	// Test Tab 3: IaC
	m.activeTab = TabIaC
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabIaC, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].ID != "DOCKER-001" {
		t.Errorf("expected rule ID DOCKER-001, got %s", m.filteredItems[0].ID)
	}

	// Test Tab 4: Licenses
	m.activeTab = TabLicenses
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabLicenses, got %d", len(m.filteredItems))
	}

	// Test Grouping Mode
	m.activeTab = TabVulnerabilities
	m.groupMode = GroupSeverity
	m.applyFilters()
	if len(m.filteredItems) < 2 {
		t.Errorf("expected grouped items including header, got %d", len(m.filteredItems))
	}
}

func TestTUICanonicalEvaluationSecretMaskingAndScopedHide(t *testing.T) {
	m := NewModel()

	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   2,
			ScannedPackages: 2,
		},
		Dependencies: []types.Dependency{
			{
				Name:       "alpha",
				Version:    "1.0.0",
				Ecosystem:  types.EcosystemNPM,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2026-0001", Severity: types.Critical, CVSSScore: 9.8, Summary: "Critical bug in alpha"},
				},
			},
			{
				Name:       "beta",
				Version:    "2.0.0",
				Ecosystem:  types.EcosystemNPM,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2026-0001", Severity: types.Critical, CVSSScore: 9.8, Summary: "Same CVE in beta"},
				},
			},
		},
		TotalVulns:    2,
		CriticalVulns: 2,
	}

	secList := []secrets.SecretFinding{
		{
			FilePath:   "app.env",
			LineNumber: 5,
			Type:       secrets.AWSKey,
			Match:      "AKIAIOSFODNN7EXAMPLE",
			Entropy:    4.7,
		},
	}

	// Deliver complete DoneMsg (simulating cli.Scan completion after all domains finish)
	m.Update(DoneMsg{
		Result:   result,
		Secrets:  secList,
		Licenses: license.AnalyzeResultLicenses(result, nil),
	})

	if m.state != StateExplorer {
		t.Fatalf("expected StateExplorer after DoneMsg, got %v", m.state)
	}
	if m.evaluation == nil || m.evaluation.OverallDecision != "BLOCK" {
		t.Fatalf("expected canonical evaluation with BLOCK decision, got %+v", m.evaluation)
	}
	if len(m.filteredItems) != 2 {
		t.Fatalf("expected 2 canonical SCA findings, got %d", len(m.filteredItems))
	}

	// Hide only the first package's CVE-2026-0001 ('x') — the second package with the same CVE must remain visible.
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected scoped hide to hide only 1 finding (leaving same CVE on other package visible), got %d", len(m.filteredItems))
	}

	// Toggle showHidden ('v') -> both visible; restore all ('X') -> both unhidden.
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if len(m.filteredItems) != 2 {
		t.Errorf("expected 2 items when showHidden is enabled, got %d", len(m.filteredItems))
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'X'}})
	if len(m.markedFixed) != 0 || len(m.filteredItems) != 2 {
		t.Errorf("expected 'X' to restore all hidden items, hidden=%d visible=%d", len(m.markedFixed), len(m.filteredItems))
	}

	// Verify secrets are masked by default in TabSecrets and revealed only after pressing 's'.
	m.switchToTab(TabSecrets)
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 secret finding, got %d", len(m.filteredItems))
	}
	if strings.Contains(m.filteredItems[0].Description, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected secret value to be masked by default, got: %s", m.filteredItems[0].Description)
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if !strings.Contains(m.filteredItems[0].Description, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected secret value to be revealed after pressing 's', got: %s", m.filteredItems[0].Description)
	}
}

func TestTUIGroupingIncludesUnknownAndProtectsHeadersAndCtrlCCancels(t *testing.T) {
	items := []TUIFinding{
		{Key: "k1", Domain: "SCA", Package: "zlib", ID: "GHSA-1", Severity: "unknown"},
		{Key: "k2", Domain: "SCA", Package: "alib", ID: "CVE-1", Severity: "critical"},
	}

	bySev := groupFindingsBySeverity(items)
	if len(bySev) != 4 { // 2 headers + 2 items (critical + unknown)
		t.Fatalf("expected 4 rows (including unknown severity group), got %d", len(bySev))
	}
	if !bySev[0].IsGroupHeader {
		t.Errorf("expected first row to be marked IsGroupHeader")
	}

	byPkg := groupFindingsByPackage(items)
	if byPkg[0].Package != "alib" || byPkg[2].Package != "zlib" {
		t.Errorf("expected deterministic alphabetical package group order (alib then zlib), got %s then %s", byPkg[0].Package, byPkg[2].Package)
	}

	m := NewModel()
	canceled := false
	m.SetCancelFunc(func() { canceled = true })
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !canceled {
		t.Error("expected ctrl+c to invoke cancelFunc")
	}
}

func TestTUIV2ObservableStagesDefaultAllFindingsPerSecretRevealAnd80x24Layout(t *testing.T) {
	m := NewModel()
	m.SetTargetMetadata("~/work/service", "package-lock.json")

	// 1. Emit observable stage events and verify Scan View renders stages & workers without mutating table.
	tot := 10
	m.Update(StageEventMsg{
		Stage:   "sca",
		Status:  "running",
		Current: 4,
		Total:   &tot,
		Queued:  4,
		Active:  2,
		Workers: 16,
		Message: "Querying lodash@4.17.20",
	})
	scanView := m.View()
	if !strings.Contains(scanView, "Workers: 16") || !strings.Contains(scanView, "4/10 processed") {
		t.Errorf("expected scan view to display real worker count and stage queue stats, got:\n%s", scanView)
	}

	// 2. Verify Medium, Low, and Unknown findings are visible by default (not hidden by Critical+High filter)
	// and Dependency Graph tab is populated from result.Graph.
	g := types.NewDependencyGraph()
	g.Ecosystem = types.EcosystemNPM
	g.AddNode("express", "4.18.2", types.Production, true)
	g.Root = []string{"express@4.18.2"}
	g.CalculateDepths()

	res := &types.ScanResult{
		LockFile: "package-lock.json",
		Graph:    g,
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{
				Name:       "express",
				Version:    "4.18.2",
				Ecosystem:  types.EcosystemNPM,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2026-5000", Severity: types.Medium, CVSSScore: 5.3, Summary: "Medium issue"},
					{ID: "GHSA-0000-0000-0001", Severity: types.Unknown, Summary: "Unknown severity issue"},
				},
			},
		},
		TotalVulns:   2,
		MediumVulns:  1,
		UnknownVulns: 1,
	}

	secList := []secrets.SecretFinding{
		{FilePath: "a.env", LineNumber: 1, Type: secrets.AWSKey, Match: "AKIA1111111111111111", Entropy: 4.5},
		{FilePath: "b.env", LineNumber: 2, Type: secrets.AWSKey, Match: "AKIA2222222222222222", Entropy: 4.5},
	}

	m.Update(DoneMsg{Result: res, Secrets: secList})
	if len(m.filteredItems) != 2 {
		t.Fatalf("expected both Medium and Unknown findings visible by default, got %d", len(m.filteredItems))
	}

	// 3. Per-item secret reveal ('r'): revealing secret #1 must NOT reveal secret #2.
	m.switchToTab(TabSecrets)
	if len(m.filteredItems) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(m.filteredItems))
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if !strings.Contains(m.filteredItems[0].Description, "AKIA1111111111111111") {
		t.Errorf("expected first secret to be revealed after pressing 'r'")
	}
	if strings.Contains(m.filteredItems[1].Description, "AKIA2222222222222222") {
		t.Errorf("expected second secret to remain masked when only first secret was revealed")
	}

	// 4. Verify Dependency Graph tab [5] is populated from result.Graph (never empty).
	m.switchToTab(TabDependencyGraph)
	if len(m.filteredItems) != 1 || m.filteredItems[0].Package != "express" {
		t.Errorf("expected Dependency Graph tab to show express node from result.Graph, got %+v", m.filteredItems)
	}

	// 5. Verify 80x24, 120x35, and 160x45 terminal sizes render cleanly with visible navigation.
	m.switchToTab(TabVulnerabilities)
	for _, size := range []struct{ w, h int }{{80, 24}, {120, 35}, {160, 45}} {
		m.Update(tea.WindowSizeMsg{Width: size.w, Height: size.h})
		view := m.View()
		if !strings.Contains(view, "Quit") || !strings.Contains(view, "DECISION:") {
			t.Errorf("terminal %dx%d missing header or footer navigation:\n%s", size.w, size.h, view)
		}
	}
}
