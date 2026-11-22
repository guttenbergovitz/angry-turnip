package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestReorderFlagsFirstSupportsFlagsAfterPositionalArgs(t *testing.T) {
	args := []string{"CVE-2026-0001", ".", "--policy", "vigil.yaml", "--baseline", ".vigil.baseline.json", "--format=json"}
	got := reorderFlagsFirst(args, map[string]bool{"policy": true, "baseline": true, "format": true})
	want := []string{"--policy", "vigil.yaml", "--baseline", ".vigil.baseline.json", "--format=json", "CVE-2026-0001", "."}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reorderFlagsFirst() = %v, want %v", got, want)
	}
}

func TestRenderExplanationsIncludesDecisionReasoningAndMissingEvidence(t *testing.T) {
	result := &types.ScanResult{
		Version:     1,
		ProjectPath: "/tmp/app",
		ScannedAt:   time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC),
		LockFile:    "go.mod",
		Coverage: types.ScanCoverage{
			TotalPackages:   1,
			ScannedPackages: 1,
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
						ID:         "GHSA-aaaa-bbbb-cccc",
						CVEID:      "CVE-2026-0001",
						Severity:   types.High,
						CVSSScore:  7.5,
						CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Summary:    "Test high vulnerability",
						Sources:    []string{"osv", "nvd"},
					},
				},
			},
		},
		TotalVulns: 1,
		HighVulns:  1,
	}

	eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC))

	var buf bytes.Buffer
	renderExplanations(&buf, eval.Decisions, eval.EvidenceState, []string{"Cached scan is stale."})
	out := buf.String()

	for _, expected := range []string{
		"WARNING: Cached scan is stale.",
		"CVE-2026-0001  [REVIEW]",
		"Evidence State:      COMPLETE",
		"Component PURL:      pkg:golang/github.com/example/web@v1.2.0",
		"Policy Rule:         production/high-review",
		"Decision Reasoning:",
		"Missing Evidence:",
		"call-graph reachability",
		"runtime deployment exposure",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("explain output missing %q:\n%s", expected, out)
		}
	}
}

func TestBaselineCommandValidatesHashFreshnessAndCompleteness(t *testing.T) {
	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module example.com/app\n\ngo 1.27.0\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	lockHash, err := lockfile.HashFile(goModPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	cachePath := filepath.Join(dir, ".vigil.cache")
	outFile := filepath.Join(dir, ".vigil.baseline.json")

	// 1. Incomplete scan must be rejected by vigil baseline.
	incomplete := &types.ScanResult{
		Version:      1,
		ProjectPath:  dir,
		ScannedAt:    time.Now().UTC(),
		LockFile:     "go.mod",
		LockFileHash: lockHash,
		Coverage: types.ScanCoverage{
			TotalPackages:       2,
			ScannedPackages:     1,
			UnsupportedPackages: 1,
		},
	}
	if err := lockfile.SaveCache(cachePath, incomplete); err != nil {
		t.Fatalf("SaveCache error: %v", err)
	}
	if err := Baseline([]string{"--output", outFile, dir}); err == nil {
		t.Fatal("expected Baseline() to reject incomplete scan cache")
	}

	// 2. Complete fresh scan with matching hash succeeds and stores PURL-qualified key.
	complete := &types.ScanResult{
		Version:      1,
		ProjectPath:  dir,
		ScannedAt:    time.Now().UTC(),
		LockFile:     "go.mod",
		LockFileHash: lockHash,
		Coverage: types.ScanCoverage{
			TotalPackages:   1,
			ScannedPackages: 1,
		},
		Dependencies: []types.Dependency{
			{
				Name:       "example.com/lib",
				Version:    "v1.0.0",
				Ecosystem:  types.EcosystemGo,
				Type:       types.Production,
				ScanStatus: types.StatusScanned,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2026-1234", Severity: types.Medium},
				},
			},
		},
		TotalVulns:  1,
		MediumVulns: 1,
	}
	if err := lockfile.SaveCache(cachePath, complete); err != nil {
		t.Fatalf("SaveCache error: %v", err)
	}

	if err := Baseline([]string{dir, "--output", outFile}); err != nil {
		t.Fatalf("Baseline() returned error: %v", err)
	}

	loaded, err := policy.LoadBaseline(outFile)
	if err != nil {
		t.Fatalf("LoadBaseline error: %v", err)
	}
	if len(loaded.FindingKeys) != 1 || loaded.FindingKeys[0] != "CVE-2026-1234|pkg:golang/example.com/lib@v1.0.0" {
		t.Errorf("unexpected baseline keys: %v", loaded.FindingKeys)
	}
}
