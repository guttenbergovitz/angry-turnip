package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/epss"
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

func TestBuildGraphFromDepsPreservesUnresolvedAsUnsupported(t *testing.T) {
	deps := &lockfile.Dependencies{
		Production: map[string]string{"org.apache.logging.log4j:log4j-core": "2.14.1"},
		Unresolved: []string{"org.springframework.boot:spring-boot-starter-web"},
	}

	graph := buildGraphFromDeps(deps, types.EcosystemMaven)
	result := scanGraph(
		context.Background(),
		"/tmp/java-app",
		"pom.xml",
		"hash",
		graph,
		lockfile.PomXml,
		false,
		nil,
		func(_ context.Context, _ *types.DependencyNode, _ string) ([]types.Vulnerability, error) {
			return nil, nil
		},
	)

	if result.Coverage.ScannedPackages != 1 {
		t.Errorf("ScannedPackages = %d, want 1", result.Coverage.ScannedPackages)
	}
	if result.Coverage.UnsupportedPackages != 1 {
		t.Errorf("UnsupportedPackages = %d, want 1", result.Coverage.UnsupportedPackages)
	}
}

func TestRateLimiterHonoursIntervalAndCancellation(t *testing.T) {
	limiter := NewRateLimiter(20 * time.Millisecond)

	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait returned error: %v", err)
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("second Wait returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("expected at least ~20ms elapsed between ticks, got %v", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Error("expected Wait with cancelled context to return error")
	}
}

type stubKEVEnricher struct {
	matches map[string]bool
	err     error
	calls   int
}

func (s *stubKEVEnricher) LookupKEV(_ context.Context, _ []string) (map[string]bool, error) {
	s.calls++
	return s.matches, s.err
}

type stubEPSSEnricher struct {
	scores map[string]epss.Score
	err    error
	calls  int
}

func (s *stubEPSSEnricher) LookupEPSS(_ context.Context, _ []string) (map[string]epss.Score, error) {
	s.calls++
	return s.scores, s.err
}

func TestEnrichThreatIntelAttachesKEVAndEPSS(t *testing.T) {
	kevStub := &stubKEVEnricher{
		matches: map[string]bool{"CVE-2021-44228": true},
	}
	epssStub := &stubEPSSEnricher{
		scores: map[string]epss.Score{
			"CVE-2021-44228": {EPSS: 0.975, Percentile: 0.999},
		},
	}

	scanner := &Scanner{
		KEVEnricher:  kevStub,
		EPSSEnricher: epssStub,
	}

	result := &types.ScanResult{
		Dependencies: []types.Dependency{
			{
				Name:    "log4j-core",
				Version: "2.14.1",
				Vulnerabilities: []types.Vulnerability{
					{
						ID:      "GHSA-jfh8-c2jp-5v3q",
						CVEID:   "CVE-2021-44228",
						Sources: []string{"osv"},
					},
				},
			},
		},
	}

	scanner.enrichThreatIntel(context.Background(), result)

	v := result.Dependencies[0].Vulnerabilities[0]
	if !v.KnownExploited {
		t.Errorf("expected KnownExploited = true")
	}
	if v.EPSSScore != 0.975 || v.EPSSPercentile != 0.999 {
		t.Errorf("unexpected EPSS values: score=%v pct=%v", v.EPSSScore, v.EPSSPercentile)
	}
	if len(v.Sources) != 3 {
		t.Errorf("expected sources [osv cisa-kev epss], got %v", v.Sources)
	}
}

func TestEnrichThreatIntelSkipsNetworkWhenNoCVEs(t *testing.T) {
	kevStub := &stubKEVEnricher{}
	epssStub := &stubEPSSEnricher{}
	scanner := &Scanner{KEVEnricher: kevStub, EPSSEnricher: epssStub}

	result := &types.ScanResult{
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2"},
		},
	}

	scanner.enrichThreatIntel(context.Background(), result)

	if kevStub.calls != 0 || epssStub.calls != 0 {
		t.Errorf("expected 0 threat-intel calls on clean scan, got kev=%d epss=%d", kevStub.calls, epssStub.calls)
	}
}
