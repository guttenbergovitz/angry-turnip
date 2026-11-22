package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/osv"
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

// TestReferenceFixturesResolutionAndCoverage independently verifies dependency resolution
// (100% PURL precision and recall, direct/transitive classification, dev/prod scope, and
// ScanStatus/EvidenceState) across all six supported ecosystems against expected.json.
func TestReferenceFixturesResolutionAndCoverage(t *testing.T) {
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestReferenceAdvisoryMatchingFromFrozenOSVSnapshot verifies actual OSV response parsing,
// CVSS v3.1 vector score calculation, GHSA-to-CVE alias normalization, and canonical finding
// evaluation against a frozen upstream OSV API payload (independent of expected.json mocks).
func TestReferenceAdvisoryMatchingFromFrozenOSVSnapshot(t *testing.T) {
	const frozenLog4jOSVPayload = `{
		"vulns": [
			{
				"id": "GHSA-jfh8-c2jp-5v3q",
				"summary": "Remote code execution in Apache Log4j2 JNDI lookup",
				"details": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
				"aliases": ["CVE-2021-44228"],
				"published": "2021-12-10T00:00:00Z",
				"modified": "2023-11-07T00:00:00Z",
				"severity": [
					{
						"type": "CVSS_V3",
						"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
					}
				],
				"database_specific": {
					"severity": "CRITICAL"
				},
				"references": [
					{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
				]
			}
		]
	}`

	osvClient := osv.New("https://osv.snapshot.test/v1/query", 5)
	osvClient.SetHTTPTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		bodyBytes, _ := io.ReadAll(r.Body)
		if strings.Contains(string(bodyBytes), "log4j-core") && strings.Contains(string(bodyBytes), "2.14.1") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(frozenLog4jOSVPayload)),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"vulns":[]}`)),
		}, nil
	}))

	tmpDir := t.TempDir()
	srcLock := filepath.Join(".", "maven", "pom.xml")
	dstLock := filepath.Join(tmpDir, "pom.xml")
	lockBytes, err := os.ReadFile(srcLock)
	if err != nil {
		t.Fatalf("read maven fixture: %v", err)
	}
	if err := os.WriteFile(dstLock, lockBytes, 0644); err != nil {
		t.Fatalf("write temp pom.xml: %v", err)
	}

	scanner := &scan.Scanner{
		VulnSource: osvClient,
	}
	result, err := scanner.Scan(context.Background(), tmpDir, "pom.xml", lockfile.PomXml, "snap-hash", dstLock, false, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	findings := policy.BuildFindings(result)
	if len(findings) != 1 {
		t.Fatalf("expected 1 canonical finding from frozen OSV snapshot, got %d: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.ID != "CVE-2021-44228" {
		t.Errorf("canonical finding ID = %q, want CVE-2021-44228", got.ID)
	}
	if got.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("canonical finding PURL = %q, want pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", got.PURL)
	}
	if got.Severity != types.Critical || got.CVSSScore < 9.5 || got.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("expected CRITICAL / CVSS >= 9.5 / CVSS:3.1 vector, got %s / %.1f / %q", got.Severity, got.CVSSScore, got.CVSSVector)
	}
}
