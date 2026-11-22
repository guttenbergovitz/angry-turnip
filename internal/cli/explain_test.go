package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestRenderExplanationsIncludesDecisionReasoningAndMissingEvidence(t *testing.T) {
	result := &types.ScanResult{
		Version:     1,
		ProjectPath: "/tmp/app",
		ScannedAt:   time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC),
		LockFile:    "go.mod",
		Dependencies: []types.Dependency{
			{
				Name:      "github.com/example/web",
				Version:   "v1.2.0",
				Ecosystem: types.EcosystemGo,
				Type:      types.Production,
				Direct:    true,
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
	renderExplanations(&buf, eval.Decisions)
	out := buf.String()

	for _, expected := range []string{
		"CVE-2026-0001  [REVIEW]",
		"github.com/example/web@v1.2.0",
		"Policy Rule:         production/high-new",
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

func TestBaselineCommandCreatesSnapshot(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, ".vigil.cache")
	result := &types.ScanResult{
		Version:      1,
		ProjectPath:  dir,
		ScannedAt:    time.Now().UTC(),
		LockFile:     "go.mod",
		LockFileHash: "hash123",
		Dependencies: []types.Dependency{
			{
				Name:    "example.com/lib",
				Version: "v1.0.0",
				Type:    types.Production,
				Vulnerabilities: []types.Vulnerability{
					{ID: "CVE-2026-1234", Severity: types.Medium},
				},
			},
		},
		TotalVulns:  1,
		MediumVulns: 1,
	}
	if err := lockfile.SaveCache(cachePath, result); err != nil {
		t.Fatalf("SaveCache error: %v", err)
	}

	outFile := filepath.Join(dir, ".vigil.baseline.json")
	if err := Baseline([]string{"--output", outFile, dir}); err != nil {
		t.Fatalf("Baseline() returned error: %v", err)
	}

	loaded, err := policy.LoadBaseline(outFile)
	if err != nil {
		t.Fatalf("LoadBaseline error: %v", err)
	}
	if len(loaded.FindingKeys) != 1 || loaded.FindingKeys[0] != "CVE-2026-1234|example.com/lib@v1.0.0" {
		t.Errorf("unexpected baseline keys: %v", loaded.FindingKeys)
	}
}
