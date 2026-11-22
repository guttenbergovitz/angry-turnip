package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Baseline stores a verified snapshot of known finding keys for delta analysis.
// A baseline records what was previously observed; it does not constitute formal risk acceptance.
type Baseline struct {
	Version      int       `json:"version"`
	GeneratedAt  time.Time `json:"generated_at"`
	LockFile     string    `json:"lock_file"`
	LockFileHash string    `json:"lock_file_hash"`
	FindingKeys  []string  `json:"finding_keys"`
}

// DeltaReport summarises changes between current findings and a Baseline.
// Resolved only includes findings whose package was still successfully scanned;
// findings whose package was not scanned, failed, or unsupported are recorded under NotObserved.
type DeltaReport struct {
	New         []Finding `json:"new"`
	Existing    []Finding `json:"existing"`
	Resolved    []string  `json:"resolved"`
	NotObserved []string  `json:"not_observed"`
}

// ValidateForBaseline verifies that a ScanResult has complete scan coverage and is safe
// to persist as a baseline snapshot.
func ValidateForBaseline(result *types.ScanResult) error {
	if result == nil {
		return fmt.Errorf("cannot build baseline from nil scan result")
	}
	if result.Coverage.FailedPackages > 0 {
		return fmt.Errorf("cannot build baseline from incomplete scan: %d package(s) failed vulnerability lookup", result.Coverage.FailedPackages)
	}
	if result.Coverage.UnsupportedPackages > 0 {
		return fmt.Errorf("cannot build baseline from incomplete scan: %d package(s) have unresolved or unsupported metadata", result.Coverage.UnsupportedPackages)
	}
	return nil
}

// BuildBaseline constructs a deterministic Baseline snapshot from a ScanResult.
func BuildBaseline(result *types.ScanResult) *Baseline {
	findings := BuildFindings(result)
	seen := make(map[string]bool, len(findings))
	keys := make([]string, 0, len(findings))

	for _, f := range findings {
		if !seen[f.Key] {
			seen[f.Key] = true
			keys = append(keys, f.Key)
		}
	}
	sort.Strings(keys)

	return &Baseline{
		Version:      1,
		GeneratedAt:  time.Now().UTC(),
		LockFile:     result.LockFile,
		LockFileHash: result.LockFileHash,
		FindingKeys:  keys,
	}
}

// SaveBaseline writes a Baseline snapshot to disk as indented JSON.
func SaveBaseline(path string, b *Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

// LoadBaseline loads a Baseline snapshot from disk.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return &b, nil
}

// ScannedPURLSet returns the set of component PURLs that were successfully scanned in result.
func ScannedPURLSet(result *types.ScanResult) map[string]bool {
	set := make(map[string]bool)
	if result == nil {
		return set
	}
	for _, dep := range result.Dependencies {
		// Treat explicitly StatusScanned (or legacy results where ScanStatus is empty and FailedPackages==0) as scanned.
		if dep.ScanStatus == types.StatusScanned || (dep.ScanStatus == "" && result.Coverage.FailedPackages == 0 && result.Coverage.UnsupportedPackages == 0) {
			set[BuildPURL(dep.Ecosystem, dep.Name, dep.Version)] = true
		}
	}
	return set
}

// ComputeDelta classifies findings as new or existing relative to baseline, matching across
// primary IDs and aliases, and distinguishes Resolved (component scanned and clean) from
// NotObserved (component not scanned, failed, or unsupported).
func ComputeDelta(findings []Finding, scannedPURLs map[string]bool, baseline *Baseline) DeltaReport {
	if baseline == nil {
		return DeltaReport{
			New: append([]Finding(nil), findings...),
		}
	}

	baselineSet := make(map[string]bool, len(baseline.FindingKeys))
	for _, k := range baseline.FindingKeys {
		baselineSet[k] = true
	}

	matchedBaselineKeys := make(map[string]bool)
	var report DeltaReport

	for _, f := range findings {
		matched := false
		for _, k := range f.AllKeys() {
			if baselineSet[k] {
				matched = true
				matchedBaselineKeys[k] = true
			}
		}
		if matched {
			report.Existing = append(report.Existing, f)
		} else {
			report.New = append(report.New, f)
		}
	}

	for _, k := range baseline.FindingKeys {
		if matchedBaselineKeys[k] {
			continue
		}
		_, purl, hasPURL := strings.Cut(k, "|")
		if hasPURL && scannedPURLs != nil && scannedPURLs[purl] {
			report.Resolved = append(report.Resolved, k)
		} else {
			report.NotObserved = append(report.NotObserved, k)
		}
	}
	sort.Strings(report.Resolved)
	sort.Strings(report.NotObserved)

	return report
}
