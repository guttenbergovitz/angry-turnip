package ui

import (
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
)

// ActiveTab represents the selected tab in the fullscreen TUI.
type ActiveTab int

const (
	TabVulnerabilities ActiveTab = iota
	TabSecrets
	TabIaC
	TabLicenses
	TabDependencyGraph
)

// ActivePane represents the focused pane in the Lazygit multi-pane grid layout.
type ActivePane int

const (
	PaneTable ActivePane = iota
	PaneReason
	PaneDetails
	PaneChain
)

// GroupMode represents grouping in the TUI lists.
type GroupMode int

const (
	GroupFlat GroupMode = iota
	GroupPackage
	GroupSeverity
)

// TUIFinding represents a unified security finding across all security domains.
type TUIFinding struct {
	Key             string   // Canonical finding identity (e.g. "<ID>|<PURL>" or "<Domain>|<Target>|<ID>")
	Domain          string   // "SCA", "Secret", "IaC", "License"
	Decision        string   // Policy decision ("BLOCK", "REVIEW", "ALLOW") when applicable
	Package         string   // Package or File Name
	Version         string   // Version if applicable
	ID              string   // CVE ID, Rule ID, or Secret Type
	Severity        string   // "critical", "high", "medium", "low", "unknown"
	CVSS            float64  // CVSS score if applicable
	Title           string   // Short title
	Description     string   // Full description
	ReasonFlagged   string   // Explicit explanation why this was flagged
	DependencyPath  []string // Path from root to target
	Remediation     string   // Concrete fix advice
	MissingEvidence []string // Missing evidence items from canonical Finding
	IsGroupHeader   bool     // True if this row is a non-actionable group header
	RawSecret       secrets.SecretFinding
	RawIaC          container.SecurityIssue
	RawLicense      license.LicenseFinding
}
