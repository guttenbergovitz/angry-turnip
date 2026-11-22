package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/report"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Finding is the canonical, normalised security finding produced from scan evidence.
// It separates observed advisory provenance from unverified runtime assumptions.
type Finding struct {
	Key               string                          `json:"key"`
	ID                string                          `json:"id"`
	Aliases           []string                        `json:"aliases,omitempty"`
	Package           string                          `json:"package"`
	Version           string                          `json:"version"`
	Ecosystem         types.Ecosystem                 `json:"ecosystem"`
	DependencyType    types.DependencyType            `json:"dependency_type"`
	Direct            bool                            `json:"direct"`
	Severity          types.Severity                  `json:"severity"`
	CVSSScore         float64                         `json:"cvss_score"`
	CVSSVector        string                          `json:"cvss_vector,omitempty"`
	Sources           []string                        `json:"sources,omitempty"`
	PublishedAt       *time.Time                      `json:"published_at,omitempty"`
	PackageReleasedAt *time.Time                      `json:"package_released_at,omitempty"`
	ExploitType       report.ExploitType              `json:"exploit_type"`
	Exploitability    report.ExploitabilityAssessment `json:"exploitability"`
	Summary           string                          `json:"summary"`
	MissingEvidence   []string                        `json:"missing_evidence"`
}

// BuildFindings converts a ScanResult into a deterministically ordered slice of canonical Findings.
func BuildFindings(result *types.ScanResult) []Finding {
	if result == nil {
		return nil
	}

	findings := make([]Finding, 0, result.TotalVulns)

	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			primaryID := vuln.ID
			var aliases []string
			if vuln.CVEID != "" && vuln.CVEID != vuln.ID {
				primaryID = vuln.CVEID
				aliases = append(aliases, vuln.ID)
			}

			sev := vuln.Severity
			if vuln.CVESeverity != "" && vuln.CVESeverity != types.Unknown {
				sev = vuln.CVESeverity
			}
			sev = types.NormaliseSeverity(sev)

			exploitType := report.ClassifyExploitType(vuln)
			assessment := report.AssessRuntimeExploitability(vuln, exploitType)

			sources := append([]string(nil), vuln.Sources...)
			sort.Strings(sources)

			summary := vuln.Summary
			if summary == "" {
				summary = vuln.CVETitle
			}
			if summary == "" {
				summary = "No advisory summary available"
			}

			missing := collectMissingEvidence(sev, vuln, assessment)

			findings = append(findings, Finding{
				Key:               fmt.Sprintf("%s|%s@%s", primaryID, dep.Name, dep.Version),
				ID:                primaryID,
				Aliases:           aliases,
				Package:           dep.Name,
				Version:           dep.Version,
				Ecosystem:         dep.Ecosystem,
				DependencyType:    dep.Type,
				Direct:            dep.Direct,
				Severity:          sev,
				CVSSScore:         vuln.CVSSScore,
				CVSSVector:        vuln.CVSSVector,
				Sources:           sources,
				PublishedAt:       vuln.PublishedAt,
				PackageReleasedAt: dep.ReleasedAt,
				ExploitType:       exploitType,
				Exploitability:    assessment,
				Summary:           summary,
				MissingEvidence:   missing,
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Key != findings[j].Key {
			return findings[i].Key < findings[j].Key
		}
		return findings[i].ID < findings[j].ID
	})

	return findings
}

// MatchesID returns true if query matches the finding's primary ID or any alias (case-insensitive).
func (f Finding) MatchesID(query string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return false
	}
	if strings.EqualFold(f.ID, q) {
		return true
	}
	for _, alias := range f.Aliases {
		if strings.EqualFold(alias, q) {
			return true
		}
	}
	return false
}

func collectMissingEvidence(sev types.Severity, vuln types.Vulnerability, assessment report.ExploitabilityAssessment) []string {
	var missing []string

	if assessment.Status != report.ExploitabilityConfirmedNotAffected {
		missing = append(missing, "call-graph reachability", "runtime deployment exposure")
	}
	if sev == types.Unknown {
		missing = append(missing, "upstream severity rating")
	}
	if vuln.CVSSScore <= 0 {
		missing = append(missing, "CVSS score")
	}
	if strings.TrimSpace(vuln.CVSSVector) == "" {
		missing = append(missing, "CVSS vector")
	}
	return missing
}
