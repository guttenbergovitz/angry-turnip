package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Baseline stores an accepted snapshot of known finding keys for delta analysis.
type Baseline struct {
	Version      int       `json:"version"`
	GeneratedAt  time.Time `json:"generated_at"`
	LockFile     string    `json:"lock_file"`
	LockFileHash string    `json:"lock_file_hash"`
	FindingKeys  []string  `json:"finding_keys"`
}

// DeltaReport summarises changes between a current set of findings and a Baseline.
type DeltaReport struct {
	New      []Finding `json:"new"`
	Existing []Finding `json:"existing"`
	Resolved []string  `json:"resolved"`
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

// ComputeDelta classifies findings as new or existing relative to baseline,
// and lists baseline finding keys that have been resolved.
func ComputeDelta(findings []Finding, baseline *Baseline) DeltaReport {
	if baseline == nil {
		return DeltaReport{
			New: append([]Finding(nil), findings...),
		}
	}

	baselineSet := make(map[string]bool, len(baseline.FindingKeys))
	for _, k := range baseline.FindingKeys {
		baselineSet[k] = true
	}

	currentSet := make(map[string]bool, len(findings))
	var report DeltaReport

	for _, f := range findings {
		currentSet[f.Key] = true
		if baselineSet[f.Key] {
			report.Existing = append(report.Existing, f)
		} else {
			report.New = append(report.New, f)
		}
	}

	for _, k := range baseline.FindingKeys {
		if !currentSet[k] {
			report.Resolved = append(report.Resolved, k)
		}
	}
	sort.Strings(report.Resolved)

	return report
}
