package reference_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/scan"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type expectedComponent struct {
	PURL       string `json:"purl"`
	Type       string `json:"type"`
	Direct     bool   `json:"direct"`
	ScanStatus string `json:"scan_status"`
}

type expectedCVE struct {
	PURL string `json:"purl"`
	CVE  string `json:"cve"`
}

type expectedFixture struct {
	Ecosystem             string              `json:"ecosystem"`
	LockFile              string              `json:"lock_file"`
	ExpectedEvidenceState string              `json:"expected_evidence_state"`
	ExpectedComponents    []expectedComponent `json:"expected_components"`
	KnownHistoricalCVEs   []expectedCVE       `json:"known_historical_cves"`
}

// fixtureVulnSource deterministically returns the known historical CVEs keyed by canonical PURL
// so reference fixtures validate full end-to-end resolution, coverage, and finding generation offline.
type fixtureVulnSource struct {
	cvesByPURL map[string][]string
}

func (f *fixtureVulnSource) QueryWithEcosystemContext(_ context.Context, pkg, version string, ecosystem types.Ecosystem) ([]types.Vulnerability, error) {
	purl := policy.BuildPURL(ecosystem, pkg, version)
	cves := f.cvesByPURL[purl]
	out := make([]types.Vulnerability, 0, len(cves))
	for _, cve := range cves {
		out = append(out, types.Vulnerability{
			ID:        cve,
			CVEID:     cve,
			Severity:  types.High,
			CVSSScore: 7.5,
			Summary:   "Reference historical vulnerability " + cve,
			Sources:   []string{"osv"},
		})
	}
	return out, nil
}

func TestReferenceFixturesGroundTruth(t *testing.T) {
	ecosystems := []string{"npm", "go", "maven", "python", "cargo", "composer"}

	for _, eco := range ecosystems {
		t.Run(eco, func(t *testing.T) {
			fixtureDir := filepath.Join(".", eco)

			rawExpected, err := os.ReadFile(filepath.Join(fixtureDir, "expected.json"))
			if err != nil {
				t.Fatalf("read expected.json: %v", err)
			}
			var expected expectedFixture
			if err := json.Unmarshal(rawExpected, &expected); err != nil {
				t.Fatalf("parse expected.json: %v", err)
			}

			// Copy lock file into an isolated temporary workspace so .vigil.cache is never written to git tree.
			tmpDir := t.TempDir()
			srcLock := filepath.Join(fixtureDir, expected.LockFile)
			dstLock := filepath.Join(tmpDir, expected.LockFile)
			lockBytes, err := os.ReadFile(srcLock)
			if err != nil {
				t.Fatalf("read fixture lockfile %s: %v", srcLock, err)
			}
			if err := os.WriteFile(dstLock, lockBytes, 0644); err != nil {
				t.Fatalf("write temp lockfile: %v", err)
			}

			detectedFile, lockType, err := lockfile.FindLockFile(tmpDir)
			if err != nil {
				t.Fatalf("FindLockFile(%s): %v", tmpDir, err)
			}
			if detectedFile != expected.LockFile {
				t.Fatalf("detected lock file = %q, want %q", detectedFile, expected.LockFile)
			}

			cvesByPURL := make(map[string][]string)
			for _, item := range expected.KnownHistoricalCVEs {
				cvesByPURL[item.PURL] = append(cvesByPURL[item.PURL], item.CVE)
			}

			scanner := &scan.Scanner{
				VulnSource: &fixtureVulnSource{cvesByPURL: cvesByPURL},
			}

			result, err := scanner.Scan(
				context.Background(),
				tmpDir,
				detectedFile,
				lockType,
				"ref-hash",
				dstLock,
				false,
				nil,
			)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// 1. Verify EvidenceState matches ground truth.
			state, notes := policy.ValidateEvidence(result)
			if string(state) != expected.ExpectedEvidenceState {
				t.Errorf("EvidenceState = %q, want %q (notes: %v)", state, expected.ExpectedEvidenceState, notes)
			}

			// 2. Verify 100% precision and 100% recall on component PURLs and metadata.
			actualByPURL := make(map[string]types.Dependency, len(result.Dependencies))
			for _, dep := range result.Dependencies {
				purl := policy.BuildPURL(dep.Ecosystem, dep.Name, dep.Version)
				if _, dup := actualByPURL[purl]; dup {
					t.Errorf("duplicate PURL resolved: %s", purl)
				}
				actualByPURL[purl] = dep
			}

			expectedByPURL := make(map[string]expectedComponent, len(expected.ExpectedComponents))
			for _, exp := range expected.ExpectedComponents {
				expectedByPURL[exp.PURL] = exp
				dep, ok := actualByPURL[exp.PURL]
				if !ok {
					t.Errorf("RECALL MISS: expected component %s was not resolved", exp.PURL)
					continue
				}
				if string(dep.Type) != exp.Type {
					t.Errorf("component %s Type = %q, want %q", exp.PURL, dep.Type, exp.Type)
				}
				if dep.Direct != exp.Direct {
					t.Errorf("component %s Direct = %v, want %v", exp.PURL, dep.Direct, exp.Direct)
				}
				if string(dep.ScanStatus) != exp.ScanStatus {
					t.Errorf("component %s ScanStatus = %q, want %q", exp.PURL, dep.ScanStatus, exp.ScanStatus)
				}
			}

			for purl := range actualByPURL {
				if _, ok := expectedByPURL[purl]; !ok {
					t.Errorf("PRECISION MISS: unexpected component resolved: %s", purl)
				}
			}

			// 3. Verify all expected historical CVEs appear as canonical findings.
			eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Now().UTC())
			foundKeys := make(map[string]bool, len(eval.Decisions))
			for _, fd := range eval.Decisions {
				foundKeys[fd.Finding.Key] = true
			}
			for _, expCVE := range expected.KnownHistoricalCVEs {
				wantKey := expCVE.CVE + "|" + expCVE.PURL
				if !foundKeys[wantKey] {
					t.Errorf("expected canonical finding %s not found in evaluation (got %v)", wantKey, foundKeys)
				}
			}
		})
	}
}
