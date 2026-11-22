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

func TestInvariantUnverifiedEvidenceCannotPassAsAllow(t *testing.T) {
	emptyResult := &types.ScanResult{}
	eval := Evaluate(emptyResult, DefaultPolicy(), nil, time.Now().UTC())

	if eval.EvidenceState != EvidenceUnverified {
		t.Errorf("EvidenceState = %q, want %q", eval.EvidenceState, EvidenceUnverified)
	}
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("OverallDecision = %q, want %q for UNVERIFIED evidence", eval.OverallDecision, DecisionBlock)
	}
	if err := ValidateForBaseline(emptyResult); err == nil {
		t.Error("expected ValidateForBaseline to reject UNVERIFIED scan")
	}
}

func TestInvariantInconsistentCoverageCountersMarkedInvalid(t *testing.T) {
	inconsistent := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   5,
			ScannedPackages: 2, // Missing 3 packages from status counters
		},
		Dependencies: []types.Dependency{
			{Name: "a", Version: "1.0.0", ScanStatus: types.StatusScanned},
		},
	}

	eval := Evaluate(inconsistent, DefaultPolicy(), nil, time.Now().UTC())
	if eval.EvidenceState != EvidenceInvalid {
		t.Errorf("EvidenceState = %q, want %q", eval.EvidenceState, EvidenceInvalid)
	}
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("OverallDecision = %q, want %q for INVALID evidence", eval.OverallDecision, DecisionBlock)
	}
	if err := ValidateForBaseline(inconsistent); err == nil {
		t.Error("expected ValidateForBaseline to reject INVALID coverage counters")
	}
}

func TestInvariantScopeExclusionsSeparatedFromCoverageFailures(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   2,
			ScannedPackages: 1,
			SkippedPackages: 1,
		},
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2", Ecosystem: types.EcosystemNPM, Type: types.Production, ScanStatus: types.StatusScanned},
			{Name: "jest", Version: "29.0.0", Ecosystem: types.EcosystemNPM, Type: types.Development, ScanStatus: types.StatusSkipped},
		},
	}

	eval := Evaluate(result, DefaultPolicy(), nil, time.Now().UTC())
	if eval.EvidenceState != EvidenceComplete {
		t.Errorf("EvidenceState = %q, want %q when only intentional scope exclusions exist", eval.EvidenceState, EvidenceComplete)
	}
	if eval.ScopeExclusions != 1 {
		t.Errorf("ScopeExclusions = %d, want 1", eval.ScopeExclusions)
	}
	if eval.OverallDecision != DecisionAllow {
		t.Errorf("OverallDecision = %q, want %q", eval.OverallDecision, DecisionAllow)
	}
}

func TestInvariantIncompleteSnapshotReportsNotObservedNotResolved(t *testing.T) {
	initial := sampleScanResult()
	baseline := BuildBaseline(initial)

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
    package: github.com/example/legacy
    version: v0.9.0
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
    global: true
    reason: missing owner
    expires_at: 2026-12-31
`,
		"exception_missing_scope": `
version: 1
rules:
  - name: test
    decision: BLOCK
    min_severity: high
exceptions:
  - id: CVE-2026-0001
    owner: sec-team
    reason: accidentally omitted package and global
    expires_at: 2026-12-31
`,
		"exception_missing_version_without_all_versions": `
version: 1
rules:
  - name: test
    decision: BLOCK
    min_severity: high
exceptions:
  - id: CVE-2026-0001
    package: github.com/example/web
    owner: sec-team
    reason: omitted version without all_versions
    expires_at: 2026-12-31
`,
		"strict_exception_missing_approval_id": `
version: 1
strict_exceptions: true
rules:
  - name: test
    decision: BLOCK
    min_severity: high
exceptions:
  - id: CVE-2026-0001
    package: github.com/example/web
    version: v1.2.0
    owner: sec-team
    reason: missing approval id
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

func TestInvariantBuildFindingsDeduplicatesOverlappingAliases(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{
				Name:       "github.com/example/web",
				Version:    "v1.2.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:       "GHSA-1111-2222-3333",
						Severity: types.Medium,
						Sources:  []string{"github"},
					},
					{
						ID:        "GHSA-1111-2222-3333",
						CVEID:     "CVE-2026-0001",
						Severity:  types.High,
						CVSSScore: 7.8,
						Sources:   []string{"osv", "nvd"},
					},
				},
			},
		},
	}

	findings := BuildFindings(result)
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].ID != "CVE-2026-0001" {
		t.Errorf("primary ID = %q, want CVE-2026-0001", findings[0].ID)
	}
	if findings[0].Severity != types.High || findings[0].CVSSScore != 7.8 {
		t.Errorf("expected highest severity/CVSS preserved, got sev=%s cvss=%.1f", findings[0].Severity, findings[0].CVSSScore)
	}
	if len(findings[0].Sources) != 3 {
		t.Errorf("expected 3 merged sources (github, nvd, osv), got %v", findings[0].Sources)
	}
}

func TestInvariantGHSAAndCVEAliasStability(t *testing.T) {
	baseline := &Baseline{
		Version:     1,
		FindingKeys: []string{"GHSA-1111-2222-3333|pkg:golang/github.com/example/web@v1.2.0"},
	}

	current := sampleScanResult()
	current.Dependencies = current.Dependencies[:1]
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

func TestDefaultPolicyRequiresReviewForExistingHigh(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	result := sampleScanResult()
	result.Dependencies = result.Dependencies[:1]
	result.Coverage.TotalPackages = 1
	result.Coverage.ScannedPackages = 1
	result.TotalVulns = 1
	result.CriticalVulns = 0
	result.HighVulns = 1

	baseline := BuildBaseline(result)
	eval := Evaluate(result, DefaultPolicy(), baseline, now)

	if eval.OverallDecision != DecisionReview {
		t.Errorf("OverallDecision = %q, want %q for existing HIGH in production without formal exception", eval.OverallDecision, DecisionReview)
	}
}

func TestBaselineSaveLoadRoundTripAndScope(t *testing.T) {
	result := sampleScanResult()
	baseline := BuildBaseline(result)
	if baseline.Scope.TotalPackages != 2 || baseline.Scope.ScannedPackages != 2 {
		t.Errorf("unexpected baseline scope: %+v", baseline.Scope)
	}

	tmpPath := filepath.Join(t.TempDir(), ".vigil.baseline.json")
	if err := SaveBaseline(tmpPath, baseline); err != nil {
		t.Fatalf("SaveBaseline error: %v", err)
	}
	loaded, err := LoadBaseline(tmpPath)
	if err != nil {
		t.Fatalf("LoadBaseline error: %v", err)
	}
	if len(loaded.FindingKeys) != 2 || loaded.Scope.ScannedPackages != 2 {
		t.Fatalf("unexpected loaded baseline: %+v", loaded)
	}
}

// Property 1: Coverage consistency — every dependency belongs to exactly one valid status,
// no duplicate PURLs, counters match actual statuses, and all-skipped yields UNVERIFIED.
func TestPropertyCoverageConsistency(t *testing.T) {
	t.Run("more_dependencies_than_total_packages_is_invalid", func(t *testing.T) {
		res := &types.ScanResult{
			Coverage: types.ScanCoverage{TotalPackages: 2, ScannedPackages: 2},
			Dependencies: []types.Dependency{
				{Name: "a", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: types.StatusScanned},
				{Name: "b", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: types.StatusScanned},
				{Name: "c", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: types.StatusScanned},
			},
		}
		state, _ := ValidateEvidence(res)
		if state != EvidenceInvalid {
			t.Errorf("ValidateEvidence() = %q, want %q", state, EvidenceInvalid)
		}
	})

	t.Run("unknown_scan_status_is_invalid", func(t *testing.T) {
		res := &types.ScanResult{
			Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
			Dependencies: []types.Dependency{
				{Name: "a", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: "bogus"},
			},
		}
		state, _ := ValidateEvidence(res)
		if state != EvidenceInvalid {
			t.Errorf("ValidateEvidence() = %q, want %q", state, EvidenceInvalid)
		}
	})

	t.Run("duplicate_purl_is_invalid", func(t *testing.T) {
		res := &types.ScanResult{
			Coverage: types.ScanCoverage{TotalPackages: 2, ScannedPackages: 2},
			Dependencies: []types.Dependency{
				{Name: "a", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: types.StatusScanned},
				{Name: "a", Version: "1.0.0", Ecosystem: types.EcosystemNPM, ScanStatus: types.StatusScanned},
			},
		}
		state, _ := ValidateEvidence(res)
		if state != EvidenceInvalid {
			t.Errorf("ValidateEvidence() = %q, want %q", state, EvidenceInvalid)
		}
	})

	t.Run("all_skipped_zero_scanned_is_unverified_not_complete", func(t *testing.T) {
		res := &types.ScanResult{
			Coverage: types.ScanCoverage{TotalPackages: 1, SkippedPackages: 1},
			Dependencies: []types.Dependency{
				{Name: "jest", Version: "29.0.0", Ecosystem: types.EcosystemNPM, Type: types.Development, ScanStatus: types.StatusSkipped},
			},
		}
		eval := Evaluate(res, DefaultPolicy(), nil, time.Now().UTC())
		if eval.EvidenceState != EvidenceUnverified {
			t.Errorf("EvidenceState = %q, want %q for all-skipped scan", eval.EvidenceState, EvidenceUnverified)
		}
		if eval.OverallDecision != DecisionBlock {
			t.Errorf("OverallDecision = %q, want %q for all-skipped scan", eval.OverallDecision, DecisionBlock)
		}
	})
}

// Property 2: Permutation invariance — any ordering of transitively linked advisory records
// (A: GHSA-1111, B: CVE-2026-1234, C: GHSA-1111 + CVE-2026-1234) produces identical output.
func TestPropertyPermutationInvariance(t *testing.T) {
	a := types.Vulnerability{ID: "GHSA-1111", Severity: types.Medium, Summary: "Short note", Sources: []string{"github"}}
	b := types.Vulnerability{ID: "CVE-2026-1234", Severity: types.High, CVSSScore: 8.1, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", Summary: "Remote code execution via malformed header", Sources: []string{"nvd"}}
	c := types.Vulnerability{ID: "GHSA-1111", CVEID: "CVE-2026-1234", Severity: types.High, Sources: []string{"osv"}}

	perms := [][]types.Vulnerability{
		{a, b, c},
		{a, c, b},
		{b, a, c},
		{b, c, a},
		{c, a, b},
		{c, b, a},
	}

	var baselineJSON string
	for idx, perm := range perms {
		res := &types.ScanResult{
			Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
			Dependencies: []types.Dependency{
				{
					Name:            "github.com/example/web",
					Version:         "v1.2.0",
					Ecosystem:       types.EcosystemGo,
					Type:            types.Production,
					ScanStatus:      types.StatusScanned,
					Vulnerabilities: perm,
				},
			},
		}

		findings := BuildFindings(res)
		if len(findings) != 1 {
			t.Fatalf("permutation %d: expected 1 transitively merged finding, got %d", idx, len(findings))
		}
		raw, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("marshal permutation %d: %v", idx, err)
		}
		if idx == 0 {
			baselineJSON = string(raw)
		} else if string(raw) != baselineJSON {
			t.Errorf("permutation %d produced different output:\ngot:  %s\nwant: %s", idx, raw, baselineJSON)
		}
	}
}

// Property 3: Merge consistency — derived ExploitType, Exploitability, and MissingEvidence
// are recomputed from the canonical merged vulnerability data.
func TestPropertyMergeConsistency(t *testing.T) {
	res := &types.ScanResult{
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{
				Name:       "github.com/example/web",
				Version:    "v1.2.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					// Low-evidence record first (no vector, generic summary).
					{ID: "GHSA-9999", Severity: types.Unknown, Summary: "Issue", Sources: []string{"github"}},
					// Rich record second (RCE + AV:N/AC:L vector).
					{ID: "GHSA-9999", CVEID: "CVE-2026-9999", Severity: types.Critical, CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Summary: "Remote code execution in parser", Sources: []string{"nvd"}},
				},
			},
		},
	}

	findings := BuildFindings(res)
	if len(findings) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ExploitType != "RCE" {
		t.Errorf("ExploitType = %q, want RCE (recomputed from merged summary)", f.ExploitType)
	}
	if f.Exploitability.Status != "potentially_exploitable" {
		t.Errorf("Exploitability.Status = %q, want potentially_exploitable (recomputed from merged CVSSVector)", f.Exploitability.Status)
	}
}

// Property 4: Scope reproducibility — identical package counts over different PURLs produce
// distinct ScopeFingerprints, while identical PURL manifests produce identical fingerprints.
func TestPropertyScopeReproducibility(t *testing.T) {
	resA := &types.ScanResult{
		LockFile: "go.mod",
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{Name: "example.com/alpha", Version: "v1.0.0", Ecosystem: types.EcosystemGo, ScanStatus: types.StatusScanned},
		},
	}
	resB := &types.ScanResult{
		LockFile: "go.mod",
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{Name: "example.com/beta", Version: "v1.0.0", Ecosystem: types.EcosystemGo, ScanStatus: types.StatusScanned},
		},
	}

	bA1 := BuildBaseline(resA)
	bA2 := BuildBaseline(resA)
	bB := BuildBaseline(resB)

	if bA1.Scope.ScopeFingerprint == "" {
		t.Fatal("expected non-empty ScopeFingerprint")
	}
	if bA1.Scope.ScopeFingerprint != bA2.Scope.ScopeFingerprint {
		t.Errorf("identical scopes produced different fingerprints: %s vs %s", bA1.Scope.ScopeFingerprint, bA2.Scope.ScopeFingerprint)
	}
	if bA1.Scope.ScopeFingerprint == bB.Scope.ScopeFingerprint {
		t.Errorf("different PURL manifests produced identical fingerprint: %s", bA1.Scope.ScopeFingerprint)
	}
}

func TestThreatIntelPolicyRulesKEVAndEPSS(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// A MEDIUM severity CVE in CISA KEV must be blocked by DefaultPolicy.
	kevResult := &types.ScanResult{
		LockFile: "go.mod",
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{
				Name:       "github.com/example/pkg",
				Version:    "v1.0.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:             "CVE-2026-1001",
						Severity:       types.Medium,
						CVSSScore:      5.3,
						KnownExploited: true,
						KEVStatus:      types.EnrichmentAvailable,
						EPSSScore:      0.82,
						EPSSPercentile: 0.99,
						EPSSStatus:     types.EnrichmentAvailable,
						Sources:        []string{"osv", "cisa-kev", "epss"},
					},
				},
			},
		},
	}

	eval := Evaluate(kevResult, DefaultPolicy(), nil, now)
	if eval.OverallDecision != DecisionBlock {
		t.Errorf("expected CISA KEV medium finding to be BLOCKED by DefaultPolicy, got %s", eval.OverallDecision)
	}
	if len(eval.Decisions) != 1 || eval.Decisions[0].MatchedRule != "threat-intel/kev-block" {
		t.Errorf("expected matched rule threat-intel/kev-block, got %+v", eval.Decisions)
	}

	// Custom EPSS rule blocks findings above min_epss.
	epssPolicyYAML := `
version: 1
rules:
  - name: high-epss-block
    decision: BLOCK
    min_epss: 0.5
`
	pol, err := ParsePolicy([]byte(epssPolicyYAML))
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}
	evalEPSS := Evaluate(kevResult, pol, nil, now)
	if evalEPSS.OverallDecision != DecisionBlock {
		t.Errorf("expected EPSS 0.82 >= 0.5 to BLOCK, got %s", evalEPSS.OverallDecision)
	}

	// Out-of-range min_epss must be rejected.
	if _, err := ParsePolicy([]byte("version: 1\nrules:\n  - name: bad\n    decision: BLOCK\n    min_epss: 1.5\n")); err == nil {
		t.Error("expected out-of-range min_epss to fail strict YAML validation")
	}
}

func TestThreatIntelUnavailableEscalatesOnlyWhenConfigured(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	fetched := now
	result := &types.ScanResult{
		LockFile: "go.mod",
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		ThreatIntel: types.ThreatIntelMetadata{
			KEV:  types.SourceEnrichmentStatus{Status: types.EnrichmentFailed, FetchedAt: &fetched, Error: "network timeout"},
			EPSS: types.SourceEnrichmentStatus{Status: types.EnrichmentFailed, FetchedAt: &fetched, Error: "network timeout"},
		},
		Dependencies: []types.Dependency{
			{
				Name:       "github.com/example/pkg",
				Version:    "v1.0.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				Direct:     true,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:         "CVE-2026-2002",
						Severity:   types.Medium,
						CVSSScore:  5.0,
						KEVStatus:  types.EnrichmentFailed,
						EPSSStatus: types.EnrichmentFailed,
						Sources:    []string{"osv"},
					},
				},
			},
		},
	}

	// DefaultPolicy does not fail basic SCA when optional TI is unavailable, but records EvidenceNotes and MissingEvidence.
	evalDefault := Evaluate(result, DefaultPolicy(), nil, now)
	if evalDefault.OverallDecision != DecisionAllow {
		t.Errorf("expected DefaultPolicy not to block medium vuln solely due to TI timeout, got %s", evalDefault.OverallDecision)
	}
	if len(evalDefault.EvidenceNotes) < 2 {
		t.Errorf("expected EvidenceNotes to record KEV & EPSS failures, got %v", evalDefault.EvidenceNotes)
	}
	hasMissingKEV := false
	for _, m := range evalDefault.Decisions[0].Finding.MissingEvidence {
		if m == "CISA KEV lookup (failed)" {
			hasMissingKEV = true
		}
	}
	if !hasMissingKEV {
		t.Errorf("expected MissingEvidence to include failed KEV lookup, got %v", evalDefault.Decisions[0].Finding.MissingEvidence)
	}

	// Strict TI policy escalates to REVIEW when KEV/EPSS is unavailable.
	strictTI, err := ParsePolicy([]byte(`
version: 1
on_threat_intel_unavailable: REVIEW
rules:
  - name: kev-block
    decision: BLOCK
    known_exploited: true
`))
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}
	evalStrict := Evaluate(result, strictTI, nil, now)
	if evalStrict.OverallDecision != DecisionReview {
		t.Errorf("expected REVIEW when on_threat_intel_unavailable=REVIEW, got %s", evalStrict.OverallDecision)
	}
}

func TestBaselineScopeComparabilityDistinguishesConfigVsComponents(t *testing.T) {
	baseScan := &types.ScanResult{
		LockFile:    "package-lock.json",
		SkipDevDeps: false,
		Coverage:    types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2", Ecosystem: types.EcosystemNPM, Type: types.Production, ScanStatus: types.StatusScanned},
		},
	}
	baseline := BuildBaseline(baseScan)

	// Same config, added component -> compatible = true, added = 1.
	addedScan := &types.ScanResult{
		LockFile:    "package-lock.json",
		SkipDevDeps: false,
		Coverage:    types.ScanCoverage{TotalPackages: 2, ScannedPackages: 2},
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2", Ecosystem: types.EcosystemNPM, Type: types.Production, ScanStatus: types.StatusScanned},
			{Name: "lodash", Version: "4.17.21", Ecosystem: types.EcosystemNPM, Type: types.Production, ScanStatus: types.StatusScanned},
		},
	}
	compat, warnings, added, removed := CompareBaselineScope(addedScan, baseline)
	if !compat || added != 1 || removed != 0 || len(warnings) == 0 {
		t.Errorf("expected compatible=true, added=1, removed=0; got compat=%v added=%d removed=%d warnings=%v", compat, added, removed, warnings)
	}

	// Changed SkipDevDeps -> incompatible = false with explicit warning.
	changedConfigScan := &types.ScanResult{
		LockFile:    "package-lock.json",
		SkipDevDeps: true,
		Coverage:    types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2", Ecosystem: types.EcosystemNPM, Type: types.Production, ScanStatus: types.StatusScanned},
		},
	}
	eval := Evaluate(changedConfigScan, DefaultPolicy(), baseline, time.Now().UTC())
	if eval.BaselineScopeCompatible == nil || *eval.BaselineScopeCompatible {
		t.Errorf("expected BaselineScopeCompatible=false when skip_dev_deps changed, got %v", eval.BaselineScopeCompatible)
	}
}

func TestSourceEvidencePreservedThroughMerge(t *testing.T) {
	res := &types.ScanResult{
		Coverage: types.ScanCoverage{TotalPackages: 1, ScannedPackages: 1},
		Dependencies: []types.Dependency{
			{
				Name:       "example",
				Version:    "1.0.0",
				Ecosystem:  types.EcosystemNPM,
				Type:       types.Production,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:        "GHSA-1111-2222-3333",
						CVEID:     "CVE-2026-4444",
						Severity:  types.High,
						CVSSScore: 7.5,
						Sources:   []string{"github"},
					},
					{
						ID:        "CVE-2026-4444",
						Severity:  types.Critical,
						CVSSScore: 9.8,
						Sources:   []string{"nvd"},
					},
				},
			},
		},
	}

	findings := BuildFindings(res)
	if len(findings) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(findings))
	}
	f := findings[0]
	if len(f.SourceEvidence) != 2 {
		t.Fatalf("expected 2 per-source evidence entries (github & nvd), got %+v", f.SourceEvidence)
	}
	if f.EffectiveScoreReason == "" {
		t.Error("expected non-empty EffectiveScoreReason explaining conservative max selection")
	}
}
