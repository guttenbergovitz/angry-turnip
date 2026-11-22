package ui

import (
	"fmt"
	"strings"
	"time"
)

// StageEventMsg delivers a typed stage transition or counter update from the scan pipeline.
type StageEventMsg struct {
	Stage     string
	Status    string
	Current   int
	Total     *int
	Queued    int
	Active    int
	Failed    int
	Skipped   int
	Workers   int
	Message   string
	Error     string
	Timestamp time.Time
}

func defaultStages() []StageState {
	return []StageState{
		{Stage: "discovery", Label: "Discover & parse", Status: "pending"},
		{Stage: "resolution", Label: "Dependency resolution", Status: "pending"},
		{Stage: "sca", Label: "Vulnerability lookup", Status: "pending"},
		{Stage: "enrichment", Label: "NVD / GHSA enrichment", Status: "pending"},
		{Stage: "threat-intel", Label: "CISA KEV / FIRST EPSS", Status: "pending"},
		{Stage: "secrets", Label: "Secrets scan", Status: "pending"},
		{Stage: "iac", Label: "IaC / Container audit", Status: "pending"},
		{Stage: "licences", Label: "Licence analysis", Status: "pending"},
		{Stage: "policy", Label: "Policy evaluation", Status: "pending"},
	}
}

func (m *Model) applyStageEventLocked(msg StageEventMsg) {
	if len(m.stages) == 0 {
		m.stages = defaultStages()
	}
	if msg.Workers > 0 {
		m.workerCount = msg.Workers
	}
	for i := range m.stages {
		if m.stages[i].Stage == msg.Stage {
			m.stages[i].Status = msg.Status
			m.stages[i].Current = msg.Current
			m.stages[i].Total = msg.Total
			m.stages[i].Queued = msg.Queued
			m.stages[i].Active = msg.Active
			m.stages[i].Failed = msg.Failed
			m.stages[i].Skipped = msg.Skipped
			m.stages[i].Workers = msg.Workers
			if msg.Message != "" {
				m.stages[i].Message = msg.Message
			}
			if msg.Error != "" {
				m.stages[i].Error = msg.Error
			}
			m.stages[i].UpdatedAt = msg.Timestamp
			break
		}
	}
	if msg.Stage == "sca" && msg.Total != nil {
		m.progress.Current = msg.Current
		m.progress.Total = *msg.Total
		m.progress.CurrentPkg = msg.Message
	}
	if msg.Message != "" && (msg.Status == "completed" || msg.Status == "partial" || msg.Status == "failed") {
		ts := msg.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		line := fmt.Sprintf("  [%s] %s: %s", ts.Format("15:04:05"), msg.Stage, msg.Message)
		if msg.Error != "" {
			line += " (" + msg.Error + ")"
		}
		m.activityLogs = append(m.activityLogs, line)
		if len(m.activityLogs) > 8 {
			m.activityLogs = m.activityLogs[len(m.activityLogs)-8:]
		}
	}
}

// renderScanning renders the observable multi-stage scan progress view without mutating model state.
func (m *Model) renderScanning() string {
	availWidth := m.width - 2
	if availWidth < 40 {
		availWidth = 40
	}
	bodyHeight := m.height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	elapsed := time.Since(m.startTime).Round(time.Second)
	workers := m.workerCount
	if workers <= 0 {
		workers = 10
	}

	targetInfo := "Local project"
	if m.projectPath != "" {
		targetInfo = m.projectPath
	}
	if m.lockFileName != "" {
		targetInfo += " · " + m.lockFileName
	}

	header := m.styles.Header.Render(fmt.Sprintf("VIGIL / SCAN RUNNING %s | %s | Workers: %d | Elapsed: %s",
		m.spinner.View(), targetInfo, workers, elapsed))

	var body []string
	body = append(body, m.styles.Title.Render("Scan Stages:"))

	stages := m.stages
	if len(stages) == 0 {
		stages = defaultStages()
	}
	for _, st := range stages {
		badge := stageBadge(st.Status)
		detail := st.Message
		if st.Stage == "sca" && st.Total != nil && *st.Total > 0 {
			detail = fmt.Sprintf("%d/%d processed · %d queued · %d active · %d failed · %d skipped",
				st.Current, *st.Total, st.Queued, st.Active, st.Failed, st.Skipped)
		} else if detail == "" {
			detail = st.Status
		}
		if st.Error != "" {
			detail += " [error: " + st.Error + "]"
		}
		line := fmt.Sprintf("  %s %-24s %s", badge, st.Label, truncateRunes(detail, availWidth-34))
		body = append(body, line)
	}

	if m.progress.Total > 0 {
		pct := float64(m.progress.Current) / float64(m.progress.Total)
		if pct > 1.0 {
			pct = 1.0
		}
		barWidth := 28
		if availWidth < 80 {
			barWidth = 16
		}
		filled := int(pct * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		body = append(body, "", fmt.Sprintf("Vulnerability Lookup: [%s] %d%% (%d/%d packages)",
			bar, int(pct*100), m.progress.Current, m.progress.Total))
	}

	// Preliminary finding counts by severity
	var crit, high, med, low, unk int
	for _, v := range m.vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		default:
			unk++
		}
	}
	body = append(body,
		"",
		fmt.Sprintf("Findings so far: %d total (Critical: %d · High: %d · Medium: %d · Low: %d · Unknown: %d)",
			len(m.vulns), crit, high, med, low, unk),
		m.styles.Subtitle.Render("Note: Live findings are preliminary until enrichment, deduplication, and policy evaluation finish."),
	)

	if len(m.activityLogs) > 0 {
		body = append(body, "", m.styles.Title.Render("Recent Activity:"))
		maxLogs := 5
		if bodyHeight < 22 {
			maxLogs = 2
		}
		start := 0
		if len(m.activityLogs) > maxLogs {
			start = len(m.activityLogs) - maxLogs
		}
		for _, l := range m.activityLogs[start:] {
			body = append(body, truncateRunes(l, availWidth-6))
		}
	}

	pane := RenderPaneBorder("Observable Scan Pipeline", strings.Join(body, "\n"), availWidth, bodyHeight, true)
	footer := m.styles.StatusBar.Render("[q / Ctrl+C] Cancel scan   [?] Help")
	return strings.Join([]string{header, pane, footer}, "\n")
}

func stageBadge(status string) string {
	switch status {
	case "completed":
		return "[OK]"
	case "running":
		return "[..]"
	case "partial":
		return "[!!]"
	case "failed":
		return "[XX]"
	case "skipped":
		return "[--]"
	default:
		return "[  ]"
	}
}

func (m *Model) renderOverviewPane(availWidth, bodyHeight int) string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Security Assessment Overview") + "\n\n")

	if m.evaluation != nil {
		b.WriteString(fmt.Sprintf("Overall Policy Decision:  %s\n", m.evaluation.OverallDecision))
		b.WriteString(fmt.Sprintf("Evidence Completeness:    %s\n", m.evaluation.EvidenceState))
		if m.evaluation.Resolution != nil {
			b.WriteString(fmt.Sprintf("Resolution Completeness:  %s (input: %s)\n",
				m.evaluation.Resolution.Completeness, m.evaluation.Resolution.InputKind))
		}
		b.WriteString(fmt.Sprintf("Decision Breakdown:       %d BLOCK · %d REVIEW · %d ALLOW (%d accepted risk via exception)\n\n",
			m.evaluation.BlockCount, m.evaluation.ReviewCount, m.evaluation.AllowCount, m.evaluation.SuppressedCount))
	}

	if m.result != nil {
		c := m.result.Coverage
		b.WriteString(fmt.Sprintf("Package Coverage:         %d/%d scanned (%d failed, %d skipped, %d unsupported)\n",
			c.ScannedPackages, c.TotalPackages, c.FailedPackages, c.SkippedPackages, c.UnsupportedPackages))
		b.WriteString(fmt.Sprintf("Threat Intelligence:      CISA KEV=%s · FIRST EPSS=%s (model date: %s)\n",
			m.result.ThreatIntel.KEV.Status, m.result.ThreatIntel.EPSS.Status, m.result.ThreatIntel.EPSS.ModelDate))
		b.WriteString(fmt.Sprintf("Secondary Scanners:       Secrets=%d · IaC=%d · Licences=%d\n\n",
			len(m.secretFindings), len(m.iacIssues), len(m.licenseFindings)))
	}

	if m.evaluation != nil && len(m.evaluation.EvidenceNotes) > 0 {
		b.WriteString(m.styles.Title.Render("Evidence Notes & Limitations:") + "\n")
		for _, note := range m.evaluation.EvidenceNotes {
			b.WriteString("  • " + note + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString(m.styles.Subtitle.Render("Press [1] to triage Findings, [5] to inspect Dependency Graph, [i] for Evidence & Stages, or [e] to Export."))
	return RenderPaneBorder("Assessment Overview", b.String(), availWidth, bodyHeight, true)
}

func (m *Model) renderEvidencePane(availWidth, bodyHeight int) string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Pipeline Stage Statuses & Evidence Audit") + "\n\n")

	for _, st := range m.stages {
		line := fmt.Sprintf("  %s %-24s %s", stageBadge(st.Status), st.Label, st.Message)
		if st.Error != "" {
			line += " [error: " + st.Error + "]"
		}
		b.WriteString(truncateRunes(line, availWidth-6) + "\n")
	}

	if m.result != nil {
		if len(m.result.Resolution.Unresolved) > 0 {
			b.WriteString("\n" + m.styles.Title.Render("Unresolved Dependencies:") + "\n")
			for _, u := range m.result.Resolution.Unresolved {
				b.WriteString(fmt.Sprintf("  • %s: %s\n", u.Package, u.Reason))
			}
		}
		if len(m.result.Resolution.Ambiguous) > 0 {
			b.WriteString("\n" + m.styles.Title.Render("Ambiguous Multi-Version Edges:") + "\n")
			for _, a := range m.result.Resolution.Ambiguous {
				b.WriteString(fmt.Sprintf("  • %s -> %s (candidates: %s): %s\n",
					a.Parent, a.Dependency, strings.Join(a.Candidates, ", "), a.Reason))
			}
		}
	}

	if len(m.activityLogs) > 0 {
		b.WriteString("\n" + m.styles.Title.Render("Recent Activity Log:") + "\n")
		for _, l := range m.activityLogs {
			b.WriteString(truncateRunes(l, availWidth-6) + "\n")
		}
	}

	return RenderPaneBorder("Evidence & Pipeline Activity", b.String(), availWidth, bodyHeight, true)
}
