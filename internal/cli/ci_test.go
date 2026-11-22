package cli

import (
	"testing"
	"time"

	"github.com/guttenbergovitz/angry-turnip/internal/policy"
	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

func TestEvaluateCIGateFailOnScanErrorAndUnsupported(t *testing.T) {
	failedResult := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   2,
			ScannedPackages: 1,
			FailedPackages:  1,
		},
		Dependencies: []types.Dependency{
			{Name: "a", Version: "1.0.0", ScanStatus: types.StatusScanned},
			{Name: "b", Version: "1.0.0", ScanStatus: types.StatusFailed},
		},
	}

	outcome := EvaluateCIGate(failedResult, CIGateOptions{
		MinSeverity:       types.High,
		FailOnScanError:   true,
		FailOnUnsupported: true,
	})
	if outcome.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 when FailOnScanError=true and FailedPackages=1", outcome.ExitCode)
	}
	if outcome.Evaluation.EvidenceState != policy.EvidencePartial {
		t.Errorf("EvidenceState = %q, want %q", outcome.Evaluation.EvidenceState, policy.EvidencePartial)
	}

	// UnsupportedPackages > 0 must also fail by default.
	unsupportedResult := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:       2,
			ScannedPackages:     1,
			UnsupportedPackages: 1,
		},
		Dependencies: []types.Dependency{
			{Name: "a", Version: "1.0.0", ScanStatus: types.StatusScanned},
			{Name: "b", Version: "", ScanStatus: types.StatusUnsupported},
		},
	}
	unsupportedOutcome := EvaluateCIGate(unsupportedResult, CIGateOptions{
		MinSeverity:       types.High,
		FailOnScanError:   true,
		FailOnUnsupported: true,
	})
	if unsupportedOutcome.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 when FailOnUnsupported=true and UnsupportedPackages=1", unsupportedOutcome.ExitCode)
	}

	// Unverified empty scan must return exit code 2 (never silently pass).
	unverifiedOutcome := EvaluateCIGate(&types.ScanResult{}, CIGateOptions{
		MinSeverity:       types.High,
		FailOnScanError:   true,
		FailOnUnsupported: true,
	})
	if unverifiedOutcome.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 for UNVERIFIED scan", unverifiedOutcome.ExitCode)
	}

	// Explicit opt-out allows gate to pass if no threshold violations occurred.
	outcomeOptOut := EvaluateCIGate(failedResult, CIGateOptions{
		MinSeverity:       types.High,
		FailOnScanError:   false,
		FailOnUnsupported: false,
	})
	if outcomeOptOut.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 when both opt-outs disabled and no vulns", outcomeOptOut.ExitCode)
	}
}

func TestEvaluateCIGateSeverityAndCVSSThresholds(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   1,
			ScannedPackages: 1,
		},
		Dependencies: []types.Dependency{
			{
				Name:       "express",
				Version:    "4.18.0",
				Ecosystem:  types.EcosystemNPM,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2024-0001", Severity: types.High, CVSSScore: 7.5},
					{ID: "CVE-2024-0002", Severity: types.Low, CVSSScore: 2.5},
				},
			},
		},
	}

	outcome := EvaluateCIGate(result, CIGateOptions{
		MinSeverity:       types.High,
		FailOnCVSS:        8.0,
		FailOnScanError:   true,
		FailOnUnsupported: true,
	})
	if outcome.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", outcome.ExitCode)
	}
	if outcome.SeverityViolations != 1 {
		t.Errorf("SeverityViolations = %d, want 1", outcome.SeverityViolations)
	}
	if outcome.CVSSViolations != 0 {
		t.Errorf("CVSSViolations = %d, want 0", outcome.CVSSViolations)
	}
}

func TestValidateCachedResult(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	fresh := &types.ScanResult{
		LockFile:     "go.mod",
		LockFileHash: "sha256-good",
		ScannedAt:    now.Add(-2 * time.Hour),
	}

	if err := validateCachedResult(fresh, "go.mod", "sha256-good", 24*time.Hour, now); err != nil {
		t.Errorf("expected valid fresh cache, got error: %v", err)
	}

	if err := validateCachedResult(fresh, "go.mod", "sha256-changed", 24*time.Hour, now); err == nil {
		t.Error("expected error when lock file hash changed")
	}

	if err := validateCachedResult(fresh, "package-lock.json", "sha256-good", 24*time.Hour, now); err == nil {
		t.Error("expected error when lock file name changed")
	}

	expired := &types.ScanResult{
		LockFile:     "go.mod",
		LockFileHash: "sha256-good",
		ScannedAt:    now.Add(-48 * time.Hour),
	}
	if err := validateCachedResult(expired, "go.mod", "sha256-good", 24*time.Hour, now); err == nil {
		t.Error("expected error when cache age exceeds maxAge")
	}
}
