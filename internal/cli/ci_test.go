package cli

import (
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestEvaluateCIGateFailOnScanError(t *testing.T) {
	result := &types.ScanResult{
		Coverage: types.ScanCoverage{
			TotalPackages:   5,
			ScannedPackages: 4,
			FailedPackages:  1,
		},
	}

	// Default policy: fail when scan is incomplete even if 0 vulnerabilities were reported.
	outcome := EvaluateCIGate(result, CIGateOptions{
		MinSeverity:     types.High,
		FailOnScanError: true,
	})
	if outcome.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 when FailOnScanError=true and FailedPackages=1", outcome.ExitCode)
	}

	// Explicit opt-out allows gate to pass if no threshold violations occurred.
	outcomeOptOut := EvaluateCIGate(result, CIGateOptions{
		MinSeverity:     types.High,
		FailOnScanError: false,
	})
	if outcomeOptOut.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 when FailOnScanError=false and no vulns", outcomeOptOut.ExitCode)
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
				Name:    "express",
				Version: "4.18.0",
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2024-0001", Severity: types.High, CVSSScore: 7.5},
					{ID: "CVE-2024-0002", Severity: types.Low, CVSSScore: 2.5},
				},
			},
		},
	}

	outcome := EvaluateCIGate(result, CIGateOptions{
		MinSeverity:     types.High,
		FailOnCVSS:      8.0,
		FailOnScanError: true,
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
