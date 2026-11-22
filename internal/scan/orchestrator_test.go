package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type recordingReporter struct {
	vulns []types.Vulnerability
}

func (r *recordingReporter) Error(string)                                        {}
func (r *recordingReporter) Progress(int, int, string, int)                      {}
func (r *recordingReporter) Done(*types.ScanResult)                              {}
func (r *recordingReporter) Vulnerability(v types.Vulnerability, _ string, _ []string) {
	r.vulns = append(r.vulns, v)
}

func TestScanGraphTracksFailuresAndCoverageExplicitly(t *testing.T) {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemNPM
	n1 := graph.AddNode("express", "4.18.0", types.Production, true)
	n2 := graph.AddNode("lodash", "4.17.20", types.Production, true)
	n3 := graph.AddNode("jest", "29.0.0", types.Development, true)
	graph.Root = []string{n1.Name + "@" + n1.Version, n2.Name + "@" + n2.Version, n3.Name + "@" + n3.Version}
	graph.CalculateDepths()

	apiErr := errors.New("osv timeout")
	result := scanGraph(
		context.Background(),
		"/tmp/project",
		"package-lock.json",
		"abc123",
		graph,
		lockfile.NPMLock,
		true, // skip dev deps
		nil,
		func(_ context.Context, node *types.DependencyNode, _ string) ([]types.Vulnerability, error) {
			if node.Name == "lodash" {
				return nil, apiErr
			}
			return nil, nil
		},
	)

	if result.Coverage.TotalPackages != 3 {
		t.Errorf("TotalPackages = %d, want 3", result.Coverage.TotalPackages)
	}
	if result.Coverage.ScannedPackages != 1 {
		t.Errorf("ScannedPackages = %d, want 1", result.Coverage.ScannedPackages)
	}
	if result.Coverage.FailedPackages != 1 {
		t.Errorf("FailedPackages = %d, want 1", result.Coverage.FailedPackages)
	}
	if result.Coverage.SkippedPackages != 1 {
		t.Errorf("SkippedPackages = %d, want 1", result.Coverage.SkippedPackages)
	}
	if len(result.Coverage.Errors) != 1 || result.Coverage.Errors[0].Package != "lodash" {
		t.Errorf("expected single error for lodash, got %+v", result.Coverage.Errors)
	}

	statusByPkg := make(map[string]types.PackageScanStatus)
	for _, dep := range result.Dependencies {
		statusByPkg[dep.Name] = dep.ScanStatus
	}
	if statusByPkg["express"] != types.StatusScanned {
		t.Errorf("express status = %q, want %q", statusByPkg["express"], types.StatusScanned)
	}
	if statusByPkg["lodash"] != types.StatusFailed {
		t.Errorf("lodash status = %q, want %q", statusByPkg["lodash"], types.StatusFailed)
	}
	if statusByPkg["jest"] != types.StatusSkipped {
		t.Errorf("jest status = %q, want %q", statusByPkg["jest"], types.StatusSkipped)
	}
}

func TestScanGraphDoesNotDropPreReleaseDisclosedVulnsAndCountsUnknownSeverity(t *testing.T) {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemNPM
	node := graph.AddNode("example", "1.2.0", types.Production, true)
	released := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	disclosedBeforeRelease := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	node.ReleasedAt = &released
	graph.Root = []string{"example@1.2.0"}
	graph.CalculateDepths()

	reporter := &recordingReporter{}
	result := scanGraph(
		context.Background(),
		"/tmp/project",
		"package-lock.json",
		"hash",
		graph,
		lockfile.NPMLock,
		false,
		reporter,
		func(_ context.Context, _ *types.DependencyNode, _ string) ([]types.Vulnerability, error) {
			return []types.Vulnerability{
				{
					ID:          "CVE-2024-0001",
					Severity:    types.High,
					PublishedAt: &disclosedBeforeRelease,
				},
				{
					ID:       "GHSA-0000-0000-0001",
					Severity: "", // Unknown severity must NOT be counted as Low
				},
			}, nil
		},
	)

	if result.TotalVulns != 2 {
		t.Fatalf("TotalVulns = %d, want 2 (pre-release disclosed vuln must not be dropped)", result.TotalVulns)
	}
	if result.HighVulns != 1 {
		t.Errorf("HighVulns = %d, want 1", result.HighVulns)
	}
	if result.UnknownVulns != 1 {
		t.Errorf("UnknownVulns = %d, want 1", result.UnknownVulns)
	}
	if result.LowVulns != 0 {
		t.Errorf("LowVulns = %d, want 0 (unknown severity must not be mapped to low)", result.LowVulns)
	}
	if len(reporter.vulns) != result.TotalVulns {
		t.Errorf("reporter received %d vulns, want %d (must match final ScanResult)", len(reporter.vulns), result.TotalVulns)
	}
}
