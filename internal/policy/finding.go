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
// Components are uniquely identified by PURL (including ecosystem) so packages across
// different ecosystems never collide in baselines or policy evaluations.
type Finding struct {
	Key               string                          `json:"key"`
	ID                string                          `json:"id"`
	Aliases           []string                        `json:"aliases,omitempty"`
	PURL              string                          `json:"purl"`
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

// BuildPURL constructs a canonical Package URL (PURL) for a dependency.
func BuildPURL(eco types.Ecosystem, pkg, ver string) string {
	switch eco {
	case types.EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", pkg, ver)
	case types.EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", pkg, ver)
	case types.EcosystemCargo:
		return fmt.Sprintf("pkg:cargo/%s@%s", pkg, ver)
	case types.EcosystemPackagist:
		return fmt.Sprintf("pkg:composer/%s@%s", pkg, ver)
	case types.EcosystemMaven:
		if groupID, artifactID, ok := strings.Cut(pkg, ":"); ok {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, ver)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", pkg, ver)
	case types.EcosystemNPM:
		cleanPkg := pkg
		if strings.HasPrefix(pkg, "@") {
			cleanPkg = strings.ReplaceAll(pkg, "@", "%40")
		}
		return fmt.Sprintf("pkg:npm/%s@%s", cleanPkg, ver)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", pkg, ver)
	}
}

// BuildFindings converts a ScanResult into a deterministically ordered slice of canonical Findings.
func BuildFindings(result *types.ScanResult) []Finding {
	if result == nil {
		return nil
	}

	findings := make([]Finding, 0, result.TotalVulns)

	for _, dep := range result.Dependencies {
		purl := BuildPURL(dep.Ecosystem, dep.Name, dep.Version)
		for _, vuln := range dep.Vulnerabilities {
			primaryID := vuln.ID
			var aliases []string
			if vuln.CVEID != "" && vuln.CVEID != vuln.ID {
				primaryID = vuln.CVEID
				aliases = append(aliases, vuln.ID)
			}
			sort.Strings(aliases)

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
				Key:               fmt.Sprintf("%s|%s", primaryID, purl),
				ID:                primaryID,
				Aliases:           aliases,
				PURL:              purl,
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

// AllKeys returns the finding's canonical key plus alias-derived keys so identity remains
// stable if an advisory transitions between GHSA and CVE identifiers across scans.
func (f Finding) AllKeys() []string {
	keys := make([]string, 0, 1+len(f.Aliases))
	keys = append(keys, f.Key)
	for _, alias := range f.Aliases {
		keys = append(keys, fmt.Sprintf("%s|%s", alias, f.PURL))
	}
	return keys
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
