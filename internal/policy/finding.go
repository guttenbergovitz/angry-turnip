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
// Components are uniquely identified by PURL (including ecosystem) and overlapping
// advisory records (such as GHSA and CVE aliases for the same component) are merged
// into a single canonical finding.
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

// BuildFindings converts a ScanResult into a deterministically ordered, deduplicated slice
// of canonical Findings. Records referring to the same component PURL with overlapping
// advisory IDs or aliases are merged.
func BuildFindings(result *types.ScanResult) []Finding {
	if result == nil {
		return nil
	}

	raw := make([]Finding, 0, result.TotalVulns)

	for _, dep := range result.Dependencies {
		purl := BuildPURL(dep.Ecosystem, dep.Name, dep.Version)
		for _, vuln := range dep.Vulnerabilities {
			primaryID, aliases := normaliseAdvisoryIDs(vuln.ID, vuln.CVEID)

			sev := vuln.Severity
			if vuln.CVESeverity != "" && vuln.CVESeverity != types.Unknown {
				sev = vuln.CVESeverity
			}
			sev = types.NormaliseSeverity(sev)

			exploitType := report.ClassifyExploitType(vuln)
			assessment := report.AssessRuntimeExploitability(vuln, exploitType)

			sources := dedupeSortedStrings(vuln.Sources)

			summary := vuln.Summary
			if summary == "" {
				summary = vuln.CVETitle
			}
			if summary == "" {
				summary = "No advisory summary available"
			}

			raw = append(raw, Finding{
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
				MissingEvidence:   collectMissingEvidence(sev, vuln.CVSSScore, vuln.CVSSVector, assessment),
			})
		}
	}

	findings := deduplicateFindings(raw)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Key != findings[j].Key {
			return findings[i].Key < findings[j].Key
		}
		return findings[i].ID < findings[j].ID
	})

	return findings
}

func normaliseAdvisoryIDs(id, cveID string) (string, []string) {
	id = strings.TrimSpace(id)
	cveID = strings.TrimSpace(cveID)

	if cveID != "" && !strings.EqualFold(cveID, id) {
		if id != "" {
			return cveID, []string{id}
		}
		return cveID, nil
	}
	return id, nil
}

// deduplicateFindings merges findings for the same PURL that share any advisory identifier or alias.
func deduplicateFindings(raw []Finding) []Finding {
	merged := make([]Finding, 0, len(raw))

	for _, candidate := range raw {
		idx := -1
		for i := range merged {
			if merged[i].PURL == candidate.PURL && findingsOverlapAdvisory(merged[i], candidate) {
				idx = i
				break
			}
		}
		if idx == -1 {
			merged = append(merged, candidate)
		} else {
			merged[idx] = mergeFindings(merged[idx], candidate)
		}
	}

	return merged
}

func findingsOverlapAdvisory(a, b Finding) bool {
	for _, idA := range a.allAdvisoryIDs() {
		for _, idB := range b.allAdvisoryIDs() {
			if strings.EqualFold(idA, idB) {
				return true
			}
		}
	}
	return false
}

func mergeFindings(a, b Finding) Finding {
	out := a

	// Prefer a CVE-* primary identifier when merging GHSA and CVE records.
	allIDs := dedupeSortedStrings(append(a.allAdvisoryIDs(), b.allAdvisoryIDs()...))
	primary := out.ID
	for _, id := range allIDs {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			primary = id
			break
		}
	}
	out.ID = primary
	out.Aliases = nil
	for _, id := range allIDs {
		if !strings.EqualFold(id, primary) {
			out.Aliases = append(out.Aliases, id)
		}
	}
	out.Key = fmt.Sprintf("%s|%s", out.ID, out.PURL)

	// Keep the higher severity and higher CVSS score.
	if b.Severity != types.Unknown && (out.Severity == types.Unknown || b.Severity.HigherOrEqualThan(out.Severity)) {
		out.Severity = b.Severity
	}
	if b.CVSSScore > out.CVSSScore {
		out.CVSSScore = b.CVSSScore
		if b.CVSSVector != "" {
			out.CVSSVector = b.CVSSVector
		}
	} else if out.CVSSVector == "" && b.CVSSVector != "" {
		out.CVSSVector = b.CVSSVector
	}

	out.Sources = dedupeSortedStrings(append(out.Sources, b.Sources...))
	if out.Summary == "No advisory summary available" && b.Summary != "" {
		out.Summary = b.Summary
	}
	if out.PublishedAt == nil && b.PublishedAt != nil {
		out.PublishedAt = b.PublishedAt
	}
	if out.DependencyType != types.Production && b.DependencyType == types.Production {
		out.DependencyType = types.Production
	}
	out.Direct = out.Direct || b.Direct
	out.MissingEvidence = collectMissingEvidence(out.Severity, out.CVSSScore, out.CVSSVector, out.Exploitability)

	return out
}

func (f Finding) allAdvisoryIDs() []string {
	ids := make([]string, 0, 1+len(f.Aliases))
	if f.ID != "" {
		ids = append(ids, f.ID)
	}
	ids = append(ids, f.Aliases...)
	return ids
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

func collectMissingEvidence(sev types.Severity, cvssScore float64, cvssVector string, assessment report.ExploitabilityAssessment) []string {
	var missing []string

	if assessment.Status != report.ExploitabilityConfirmedNotAffected {
		missing = append(missing, "call-graph reachability", "runtime deployment exposure")
	}
	if sev == types.Unknown {
		missing = append(missing, "upstream severity rating")
	}
	if cvssScore <= 0 {
		missing = append(missing, "CVSS score")
	}
	if strings.TrimSpace(cvssVector) == "" {
		missing = append(missing, "CVSS vector")
	}
	return missing
}

func dedupeSortedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	cp := make([]string, 0, len(items))
	for _, item := range items {
		if s := strings.TrimSpace(item); s != "" {
			cp = append(cp, s)
		}
	}
	sort.Strings(cp)
	out := make([]string, 0, len(cp))
	for _, s := range cp {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
