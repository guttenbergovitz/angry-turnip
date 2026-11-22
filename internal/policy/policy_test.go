package policy

import (
	"encoding/json"
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
				Name:       "github.com/example/web",
				Version:    "v1.2.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
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
				Name:       "github.com/example/legacy",
				Version:    "v0.9.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				Direct:     false,
				ScanStatus: types.StatusScanned,
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

// Invariant 1: UnsupportedPackages > 0 must never lead to unconditional ALLOW.
func TestInvariantUnsupportedPackagesBlocksPolicy(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:       2,
			ScannedPackages:     1,
			UnsupportedPackages: 1,
		},
		Dependencies: []types.Dependency{
			{Name: "org.apache.logging.log4j:log4j-core", Version: "2.20.0", Ecosystem: types.EcosystemMaven, ScanStatus: types.StatusScanned},
			{Name: "org.springframework.boot:spring-boot-starter-web", Version: "", Ecosystem: types.EcosystemMaven, ScanStatus: types.StatusUnsupported},
		},
	}

	eval := Evaluate(result, DefaultPolicy(), nil, time.Now().UTC())
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("OverallDecision = %q, want %q when UnsupportedPackages > 0", eval.OverallDecision, DecisionBlock)
	}
	if eval.EvidenceState != EvidencePartial {
		t.Errorf("EvidenceState = %q, want %q", eval.EvidenceState, EvidencePartial)
	}
	if !eval.ScanIncomplete {
		t.Error("expected ScanIncomplete=true when UnsupportedPackages > 0")
	}
}

// Invariant 2: Incomplete snapshot must not mark missing findings as Resolved (must be NotObserved),
// and ValidateForBaseline must reject incomplete scans.
func TestInvariantIncompleteSnapshotReportsNotObservedNotResolved(t *testing.T) {
	initial := sampleScanResult()
	baseline := BuildBaseline(initial)

	// Second scan: web failed to scan, legacy was scanned and cleaned up.
	next := sampleScanResult()
	next.Coverage.ScannedPackages = 1
	next.Coverage.FailedPackages = 1
	next.Dependencies[0].ScanStatus = types.StatusFailed
	next.Dependencies[0].Vulnerabilities = nil
	next.Dependencies[1].ScanStatus = types.StatusScanned
	next.Dependencies[1].Vulnerabilities = nil

	if err := ValidateForBaseline(next); err == nil {
		t.Error("expected ValidateForBaseline to reject scan with FailedPackages > 0")
	}

	delta := ComputeDelta(BuildFindings(next), ScannedPURLSet(next), baseline)
	if len(delta.Resolved) != 1 || delta.Resolved[0] != "CVE-2025-9999|pkg:golang/github.com/example/legacy@v0.9.0" {
		t.Errorf("expected only scanned clean legacy finding in Resolved, got %v", delta.Resolved)
	}
	if len(delta.NotObserved) != 1 || delta.NotObserved[0] != "CVE-2026-0001|pkg:golang/github.com/example/web@v1.2.0" {
		t.Errorf("expected failed web finding in NotObserved (not Resolved), got %v", delta.NotObserved)
	}
}

// Invariant 3: Scoped exceptions must not accept a changed version/ecosystem or higher severity,
// and must never mask incomplete scan coverage.
func TestInvariantScopedExceptionCannotAcceptChangedRisk(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	result := sampleScanResult()

	yamlPolicy := `
version: 1
rules:
  - name: prod-high-block
    decision: BLOCK
    min_severity: high
    production_only: true
exceptions:
  - id: CVE-2026-0001
    package: github.com/example/web
    version: v1.1.0
    ecosystem: Go
    owner: sec-team
    reason: Approved for v1.1.0 only
    expires_at: 2026-12-31
  - id: CVE-2025-9999
    max_severity: high
    owner: sec-team
    reason: Approved only if severity stays at most high
    expires_at: 2026-12-31
`
	pol, err := ParsePolicy([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}

	eval := Evaluate(result, pol, nil, now)
	if eval.SuppressedCount != 0 {
		t.Errorf("expected 0 suppressions (version mismatch and max_severity exceeded), got %d", eval.SuppressedCount)
	}
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("OverallDecision = %q, want %q", eval.OverallDecision, DecisionBlock)
	}
}

// Invariant 4: Unknown YAML fields, missing version, empty rules, and invalid ranges must be rejected.
func TestInvariantStrictPolicyYAMLValidation(t *testing.T) {
	invalidPolicies := map[string]string{
		"unknown_field_typo": `
version: 1
rules:
  - name: test
    decision: BLOCK
    min_sevrity: high
`,
		"missing_version": `
rules:
  - name: test
    decision: BLOCK
    min_severity: high
`,
		"empty_rules": `
version: 1
rules: []
`,
		"cvss_out_of_range": `
version: 1
rules:
  - name: test
    decision: BLOCK
    min_cvss: 12.5
`,
		"exception_missing_owner": `
version: 1
rules:
  - name: test
    decision: BLOCK
    min_severity: high
exceptions:
  - id: CVE-2026-0001
    reason: missing owner
    expires_at: 2026-12-31
`,
	}

	for name, raw := range invalidPolicies {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(raw)); err == nil {
				t.Errorf("expected ParsePolicy to reject %s", name)
			}
		})
	}
}

// Invariant 5: Same vulnerability reported as GHSA in baseline and CVE (with GHSA alias) in current
// scan must keep stable identity and not appear as New + Resolved.
func TestInvariantGHSAAndCVEAliasStability(t *testing.T) {
	baseline := &Baseline{
		Version:     1,
		FindingKeys: []string{"GHSA-1111-2222-3333|pkg:golang/github.com/example/web@v1.2.0"},
	}

	current := sampleScanResult()
	current.Dependencies = current.Dependencies[:1] // only web with CVE-2026-0001 + alias GHSA-1111-2222-3333
	delta := ComputeDelta(BuildFindings(current), ScannedPURLSet(current), baseline)

	if len(delta.New) != 0 {
		t.Errorf("expected 0 new findings when GHSA alias matches baseline, got %+v", delta.New)
	}
	if len(delta.Existing) != 1 {
		t.Errorf("expected 1 existing finding, got %+v", delta.Existing)
	}
	if len(delta.Resolved) != 0 || len(delta.NotObserved) != 0 {
		t.Errorf("expected 0 resolved/not_observed, got resolved=%v not_observed=%v", delta.Resolved, delta.NotObserved)
	}
}

// Invariant 6: Identical snapshot, policy, and timestamp must yield byte-for-byte identical output.
func TestInvariantDeterministicEvaluation(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	result := sampleScanResult()
	pol := DefaultPolicy()

	eval1 := Evaluate(result, pol, nil, now)
	eval2 := Evaluate(result, pol, nil, now)

	b1, err := json.Marshal(eval1)
	if err != nil {
		t.Fatalf("marshal eval1: %v", err)
	}
	b2, err := json.Marshal(eval2)
	if err != nil {
		t.Fatalf("marshal eval2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Errorf("expected deterministic evaluation output, got diff:\n%s\nvs\n%s", b1, b2)
	}
}

// Verify DefaultPolicy does NOT unconditionally allow known HIGH vulnerabilities in baseline.
func TestDefaultPolicyRequiresReviewForExistingHigh(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	result := sampleScanResult()
	result.Dependencies = result.Dependencies[:1] // only HIGH prod finding
	result.TotalVulns = 1
	result.CriticalVulns = 0
	result.HighVulns = 1

	baseline := BuildBaseline(result)
	eval := Evaluate(result, DefaultPolicy(), baseline, now)

	if eval.OverallDecision != DecisionReview {
		t.Errorf("OverallDecision = %q, want %q for existing HIGH in production without formal exception", eval.OverallDecision, DecisionReview)
	}
}

func TestBaselineSaveLoadRoundTrip(t *testing.T) {
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
		t.Fatalf("expected 2 PURL-qualified keys, got %v", loaded.FindingKeys)
	}
}
