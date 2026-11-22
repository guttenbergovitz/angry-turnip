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
// Components are uniquely identified by PURL (including ecosystem) and transitively
// overlapping advisory records (such as GHSA and CVE aliases for the same component)
// are merged into a single canonical finding independently of input ordering.
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

// BuildFindings converts a ScanResult into a deterministically ordered, transitively
// deduplicated slice of canonical Findings. Records referring to the same component PURL
// with transitively overlapping advisory IDs or aliases are merged using union-find, and
// all derived fields (ExploitType, Exploitability, MissingEvidence) are recomputed from
// the merged canonical evidence.
func BuildFindings(result *types.ScanResult) []Finding {
	if result == nil {
		return nil
	}

	byPURL := make(map[string][]Finding)

	for _, dep := range result.Dependencies {
		purl := BuildPURL(dep.Ecosystem, dep.Name, dep.Version)
		for _, vuln := range dep.Vulnerabilities {
			primaryID, aliases := normaliseAdvisoryIDs(vuln.ID, vuln.CVEID)

			sev := vuln.Severity
			if vuln.CVESeverity != "" && vuln.CVESeverity != types.Unknown {
				sev = vuln.CVESeverity
			}
			sev = types.NormaliseSeverity(sev)

			sources := dedupeSortedStrings(vuln.Sources)

			summary := strings.TrimSpace(vuln.Summary)
			if summary == "" {
				summary = strings.TrimSpace(vuln.CVETitle)
			}

			byPURL[purl] = append(byPURL[purl], Finding{
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
				CVSSVector:        strings.TrimSpace(vuln.CVSSVector),
				Sources:           sources,
				PublishedAt:       vuln.PublishedAt,
				PackageReleasedAt: dep.ReleasedAt,
				Summary:           summary,
			})
		}
	}

	purls := make([]string, 0, len(byPURL))
	for purl := range byPURL {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	findings := make([]Finding, 0)
	for _, purl := range purls {
		findings = append(findings, deduplicatePURLFindings(byPURL[purl])...)
	}

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

// deduplicatePURLFindings partitions findings for a single PURL into connected components
// by shared advisory IDs/aliases using union-find, ensuring transitive, permutation-invariant
// deduplication.
func deduplicatePURLFindings(items []Finding) []Finding {
	n := len(items)
	if n == 0 {
		return nil
	}

	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}

	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	}

	idToFirst := make(map[string]int)
	for i, item := range items {
		for _, id := range item.allAdvisoryIDs() {
			key := strings.ToLower(strings.TrimSpace(id))
			if key == "" {
				continue
			}
			if prev, exists := idToFirst[key]; exists {
				union(i, prev)
			} else {
				idToFirst[key] = i
			}
		}
	}

	groups := make(map[int][]Finding)
	for i, item := range items {
		root := find(i)
		groups[root] = append(groups[root], item)
	}

	merged := make([]Finding, 0, len(groups))
	for _, group := range groups {
		merged = append(merged, mergeComponentFindings(group))
	}

	return merged
}

// mergeComponentFindings deterministically merges a connected component of overlapping
// advisory records and recomputes all derived fields (ExploitType, Exploitability,
// MissingEvidence) from the canonical merged evidence.
func mergeComponentFindings(group []Finding) Finding {
	// Sort members canonically first so output is strictly permutation-invariant.
	sorted := append([]Finding(nil), group...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		if sorted[i].CVSSScore != sorted[j].CVSSScore {
			return sorted[i].CVSSScore > sorted[j].CVSSScore
		}
		if sorted[i].CVSSVector != sorted[j].CVSSVector {
			return sorted[i].CVSSVector < sorted[j].CVSSVector
		}
		return sorted[i].Summary < sorted[j].Summary
	})

	var allIDs []string
	var allSources []string
	var summaries []string
	var publishedAt *time.Time
	var releasedAt *time.Time

	out := sorted[0]
	out.Severity = types.Unknown
	out.CVSSScore = 0
	out.CVSSVector = ""
	out.Direct = false
	out.DependencyType = types.Development

	for _, m := range sorted {
		allIDs = append(allIDs, m.allAdvisoryIDs()...)
		allSources = append(allSources, m.Sources...)
		if m.Summary != "" {
			summaries = append(summaries, m.Summary)
		}
		if m.Severity != types.Unknown && (out.Severity == types.Unknown || m.Severity.HigherOrEqualThan(out.Severity)) {
			out.Severity = m.Severity
		}
		if m.CVSSScore > out.CVSSScore {
			out.CVSSScore = m.CVSSScore
			out.CVSSVector = m.CVSSVector
		} else if m.CVSSScore == out.CVSSScore && out.CVSSVector == "" && m.CVSSVector != "" {
			out.CVSSVector = m.CVSSVector
		}
		if m.PublishedAt != nil && (publishedAt == nil || m.PublishedAt.Before(*publishedAt)) {
			t := *m.PublishedAt
			publishedAt = &t
		}
		if m.PackageReleasedAt != nil && (releasedAt == nil || m.PackageReleasedAt.Before(*releasedAt)) {
			t := *m.PackageReleasedAt
			releasedAt = &t
		}
		if m.DependencyType == types.Production {
			out.DependencyType = types.Production
		}
		if m.Direct {
			out.Direct = true
		}
	}

	// Choose primary ID: lexicographically first CVE-* if present, otherwise first ID.
	uniqueIDs := dedupeSortedStrings(allIDs)
	primary := ""
	for _, id := range uniqueIDs {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			primary = id
			break
		}
	}
	if primary == "" && len(uniqueIDs) > 0 {
		primary = uniqueIDs[0]
	}

	out.ID = primary
	out.Aliases = nil
	for _, id := range uniqueIDs {
		if !strings.EqualFold(id, primary) {
			out.Aliases = append(out.Aliases, id)
		}
	}
	out.Key = fmt.Sprintf("%s|%s", out.ID, out.PURL)
	out.Sources = dedupeSortedStrings(allSources)
	out.PublishedAt = publishedAt
	out.PackageReleasedAt = releasedAt

	// Pick canonical summary deterministically (longest non-empty, tie-broken alphabetically).
	uniqueSummaries := dedupeSortedStrings(summaries)
	if len(uniqueSummaries) > 0 {
		best := uniqueSummaries[0]
		for _, s := range uniqueSummaries[1:] {
			if len(s) > len(best) || (len(s) == len(best) && s < best) {
				best = s
			}
		}
		out.Summary = best
	} else {
		out.Summary = "No advisory summary available"
	}

	// Recompute ALL derived fields from canonical merged evidence.
	canonicalVuln := types.Vulnerability{
		ID:         out.ID,
		Summary:    out.Summary,
		Severity:   out.Severity,
		CVSSScore:  out.CVSSScore,
		CVSSVector: out.CVSSVector,
	}
	out.ExploitType = report.ClassifyExploitType(canonicalVuln)
	out.Exploitability = report.AssessRuntimeExploitability(canonicalVuln, out.ExploitType)
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
