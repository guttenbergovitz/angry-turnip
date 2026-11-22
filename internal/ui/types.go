package ui

import (
	"time"

	"github.com/guttenbergovitz/angry-turnip/internal/container"
	"github.com/guttenbergovitz/angry-turnip/internal/license"
	"github.com/guttenbergovitz/angry-turnip/internal/secrets"
)

// ActiveTab represents the selected top-level view or domain tab in the TUI.
type ActiveTab int

const (
	TabVulnerabilities ActiveTab = iota // Findings view (all domains or filtered)
	TabSecrets                          // Secrets domain view
	TabIaC                              // IaC security view
	TabLicenses                         // Licences view
	TabDependencyGraph                  // Dependencies & Graph view
	TabOverview                         // Assessment Overview (decision, coverage, sources)
	TabEvidence                         // Evidence, stage statuses, limitations & activity log
)

// ActivePane is retained for backwards compatibility with legacy tests.
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
	GroupDecision
)

// SortMode represents deterministic sorting in the Findings table.
type SortMode int

const (
	SortDecisionPriority SortMode = iota
	SortSeverity
	SortCVSS
	SortPackage
)

// StageState tracks observable status and counters for a single pipeline stage in the Scan & Evidence views.
type StageState struct {
	Stage     string
	Label     string
	Status    string // "pending", "running", "completed", "partial", "failed", "skipped"
	Current   int
	Total     *int
	Queued    int
	Active    int
	Failed    int
	Skipped   int
	Workers   int
	Message   string
	Error     string
	UpdatedAt time.Time
}

// TUIFinding represents a unified security finding across all security domains.
type TUIFinding struct {
	Key             string   // Canonical finding identity (e.g. "<ID>|<PURL>" or "<Domain>|<Target>|<ID>")
	Domain          string   // "SCA", "SECRET", "IaC", "LICENSE", "GRAPH"
	Decision        string   // Policy decision ("BLOCK", "REVIEW", "ALLOW")
	AcceptedRisk    bool     // True when ALLOW is due to a formal policy exception (accepted risk, not proof of safety)
	KnownExploited  bool     // True when listed in CISA KEV
	EPSSScore       float64  // FIRST EPSS 30-day probability
	MatchedRule     string   // Policy rule or exception ID that produced the decision
	PURL            string   // Canonical component PURL
	Package         string   // Package or File Name
	Version         string   // Version if applicable
	ID              string   // CVE ID, Rule ID, or Secret Type
	Aliases         []string // Advisory aliases (GHSA/CVE)
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
