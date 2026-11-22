package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func sampleScanResult() *types.ScanResult {
	return &types.ScanResult{
		Version:      1,
		ProjectPath:  "/tmp/app",
		ScannedAt:    time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC),
		LockFile:     "go.mod",
		LockFileHash: "hash-1",
		Coverage: types.ScanCoverage{
			TotalPackages:   2,
			ScannedPackages: 2,
		},
		Dependencies: []types.Dependency{
			{
				Name:      "github.com/example/web",
				Version:   "v1.2.0",
				Ecosystem: types.EcosystemGo,
				Type:      types.Production,
				Direct:    true,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:         "GHSA-1111-2222-3333",
						CVEID:      "CVE-2026-0001",
						Severity:   types.High,
						CVSSScore:  7.8,
						CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Summary:    "Remote denial of service",
						Sources:    []string{"osv", "nvd"},
					},
				},
			},
			{
				Name:      "github.com/example/legacy",
				Version:   "v0.9.0",
				Ecosystem: types.EcosystemGo,
				Type:      types.Production,
				Direct:    false,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:       "CVE-2025-9999",
						Severity: types.Critical,
						Summary:  "Critical deserialisation bug",
						Sources:  []string{"osv"},
					},
				},
			},
		},
		TotalVulns:    2,
		CriticalVulns: 1,
		HighVulns:     1,
	}
}

func TestBaselineSaveLoadAndDelta(t *testing.T) {
	result := sampleScanResult()
	baseline := BuildBaseline(result)

	tmpPath := filepath.Join(t.TempDir(), ".vigil.baseline.json")
	if err := SaveBaseline(tmpPath, baseline); err != nil {
		t.Fatalf("SaveBaseline error: %v", err)
	}

	loaded, err := LoadBaseline(tmpPath)
	if err != nil {
		t.Fatalf("LoadBaseline error: %v", err)
	}
	if len(loaded.FindingKeys) != 2 {
		t.Fatalf("expected 2 finding keys in baseline, got %d", len(loaded.FindingKeys))
	}

	// Remove one finding and add a new one.
	current := sampleScanResult()
	current.Dependencies[0].Vulnerabilities = nil
	current.Dependencies[1].Vulnerabilities = append(current.Dependencies[1].Vulnerabilities, types.Vulnerability{
		ID:       "CVE-2026-5555",
		Severity: types.High,
		Summary:  "New vulnerability",
	})

	delta := ComputeDelta(BuildFindings(current), loaded)
	if len(delta.New) != 1 || delta.New[0].ID != "CVE-2026-5555" {
		t.Errorf("expected 1 new finding CVE-2026-5555, got %+v", delta.New)
	}
	if len(delta.Existing) != 1 || delta.Existing[0].ID != "CVE-2025-9999" {
		t.Errorf("expected 1 existing finding CVE-2025-9999, got %+v", delta.Existing)
	}
	if len(delta.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %+v", delta.Resolved)
	}
}

func TestPolicyEvaluateWithActiveAndExpiredExceptions(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	result := sampleScanResult()

	yamlPolicy := `
version: 1
fail_on_scan_error: true
rules:
  - name: production/critical-block
    decision: BLOCK
    min_severity: critical
    production_only: true
    description: Block critical issues in production
  - name: production/high-new
    decision: REVIEW
    min_severity: high
    production_only: true
    new_only: true
    description: Review new high issues in production
exceptions:
  - id: CVE-2025-9999
    owner: security-team
    reason: Mitigated by WAF until migration completes
    expires_at: 2026-12-31
  - id: CVE-2026-0001
    owner: platform-team
    reason: Temporary waiver
    expires_at: 2026-11-01
`

	pol, err := ParsePolicy([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}

	eval := Evaluate(result, pol, nil, now)

	// CVE-2025-9999 is suppressed by an active exception; CVE-2026-0001 has an expired exception so it triggers REVIEW.
	if eval.OverallDecision != DecisionReview {
		t.Errorf("OverallDecision = %q, want %q", eval.OverallDecision, DecisionReview)
	}
	if eval.SuppressedCount != 1 {
		t.Errorf("SuppressedCount = %d, want 1", eval.SuppressedCount)
	}
	if eval.ExpiredExceptions != 1 {
		t.Errorf("ExpiredExceptions = %d, want 1", eval.ExpiredExceptions)
	}
	if eval.ReviewCount != 1 || eval.AllowCount != 1 || eval.BlockCount != 0 {
		t.Errorf("counts block=%d review=%d allow=%d, want 0/1/1", eval.BlockCount, eval.ReviewCount, eval.AllowCount)
	}
}

func TestPolicyRejectsInvalidExceptionMetadata(t *testing.T) {
	invalidYAML := `
version: 1
rules: []
exceptions:
  - id: CVE-2026-0001
    reason: Missing owner and expiry
`
	if _, err := ParsePolicy([]byte(invalidYAML)); err == nil {
		t.Fatal("expected ParsePolicy to reject exception missing owner and expires_at")
	}
}

func TestPolicyBlocksOnIncompleteScan(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   3,
			ScannedPackages: 2,
			FailedPackages:  1,
		},
	}

	eval := Evaluate(result, DefaultPolicy(), nil, time.Now().UTC())
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("OverallDecision = %q, want %q when scan is incomplete", eval.OverallDecision, DecisionBlock)
	}
}
