package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/scan"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type expectedCVE struct {
	PURL string `json:"purl"`
	CVE  string `json:"cve"`
}

type expectedFixture struct {
	Ecosystem            string        `json:"ecosystem"`
	KnownHistoricalCVEs  []expectedCVE `json:"known_historical_cves"`
	VerifiedNegativeCVEs []expectedCVE `json:"verified_negative_cves"`
}

// scannerRun captures the execution state, total canonical finding count, and normalized (ID|PURL) keys.
type scannerRun struct {
	Status        string          // "OK", "OK(COMPLETE)", "OK(PARTIAL)", "FAILED", "N/A"
	TotalFindings int             // Deduplicated finding count reported by the scanner
	CanonicalKeys map[string]bool // Primary "<CANONICAL_ID>|<PURL>" per deduplicated finding
	Findings      map[string]bool // All "<CVE_OR_ALIAS>|<PURL>" keys for recall and set-overlap matching
}

func main() {
	ecosystems := []string{"npm", "go", "maven", "python", "cargo", "composer"}

	fmt.Printf("%-10s | %-24s | %-24s | %-24s | %-24s\n", "Ecosystem", "Vigil (status/rec)", "OSV-Scanner (status/rec)", "Trivy (status/rec)", "Grype (status/rec)")
	fmt.Println(strings.Repeat("-", 120))

	for _, eco := range ecosystems {
		fixtureDir := filepath.Join("benchmarks", "reference", eco)
		rawExp, err := os.ReadFile(filepath.Join(fixtureDir, "expected.json"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read expected.json for %s: %v\n", eco, err)
			os.Exit(1)
		}
		var exp expectedFixture
		if err := json.Unmarshal(rawExp, &exp); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse expected.json for %s: %v\n", eco, err)
			os.Exit(1)
		}

		expectedPos := make(map[string]bool, len(exp.KnownHistoricalCVEs))
		for _, item := range exp.KnownHistoricalCVEs {
			expectedPos[strings.ToUpper(item.CVE)+"|"+item.PURL] = true
		}
		expectedNeg := make(map[string]bool, len(exp.VerifiedNegativeCVEs))
		for _, item := range exp.VerifiedNegativeCVEs {
			expectedNeg[strings.ToUpper(item.CVE)+"|"+item.PURL] = true
		}

		vigilRun := runVigil(fixtureDir)
		osvRun := runOSVScanner(fixtureDir, types.Ecosystem(exp.Ecosystem))
		trivyRun := runTrivy(fixtureDir, types.Ecosystem(exp.Ecosystem))
		grypeRun := runGrype(fixtureDir, types.Ecosystem(exp.Ecosystem))

		fmt.Printf("%-10s | %-24s | %-24s | %-24s | %-24s\n",
			eco,
			formatScore(vigilRun, expectedPos, expectedNeg),
			formatScoreWithOverlap(osvRun, vigilRun, expectedPos, expectedNeg),
			formatScoreWithOverlap(trivyRun, vigilRun, expectedPos, expectedNeg),
			formatScoreWithOverlap(grypeRun, vigilRun, expectedPos, expectedNeg),
		)
	}
}

func formatScore(run scannerRun, expectedPos, expectedNeg map[string]bool) string {
	if !strings.HasPrefix(run.Status, "OK") {
		return run.Status
	}
	tp := 0
	for k := range expectedPos {
		if run.Findings[k] {
			tp++
		}
	}
	fp := 0
	for k := range expectedNeg {
		if run.Findings[k] {
			fp++
		}
	}
	tot := run.TotalFindings
	if tot == 0 {
		tot = len(run.Findings)
	}
	unlabelled := tot - tp - fp
	if unlabelled < 0 {
		unlabelled = 0
	}
	lblPrecPct := 100
	if tp+fp > 0 {
		lblPrecPct = (tp * 100) / (tp + fp)
	}
	return fmt.Sprintf("%s (rec %d/%d, lbl-prec %d%%, unlbl %d, tot %d)", run.Status, tp, len(expectedPos), lblPrecPct, unlabelled, tot)
}

func formatScoreWithOverlap(run, vigilRun scannerRun, expectedPos, expectedNeg map[string]bool) string {
	base := formatScore(run, expectedPos, expectedNeg)
	if !strings.HasPrefix(run.Status, "OK") || !strings.HasPrefix(vigilRun.Status, "OK") {
		return base
	}
	shared := 0
	for k := range vigilRun.CanonicalKeys {
		if run.Findings[k] {
			shared++
		}
	}
	return fmt.Sprintf("%s [shared:%d]", base, shared)
}

func runVigil(fixtureDir string) scannerRun {
	tmpDir, err := os.MkdirTemp("", "vigil-bench-*")
	if err != nil {
		return scannerRun{Status: "FAILED"}
	}
	defer os.RemoveAll(tmpDir)
	if copyDir(fixtureDir, tmpDir) != nil {
		return scannerRun{Status: "FAILED"}
	}

	lockFile, lockType, err := lockfile.FindLockFile(tmpDir)
	if err != nil {
		return scannerRun{Status: "FAILED"}
	}
	lockFilePath := filepath.Join(tmpDir, lockFile)
	lockHash, err := lockfile.HashFile(lockFilePath)
	if err != nil {
		return scannerRun{Status: "FAILED"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := scan.Scan(ctx, tmpDir, lockFile, lockType, lockHash, lockFilePath, false, nil)
	if err != nil || result == nil {
		return scannerRun{Status: "FAILED"}
	}

	state, _ := policy.ValidateEvidence(result)
	if state == policy.EvidenceInvalid || state == policy.EvidenceUnverified || result.Coverage.FailedPackages > 0 {
		return scannerRun{Status: "FAILED(" + string(state) + ")"}
	}

	findings := policy.BuildFindings(result)
	canonical := make(map[string]bool, len(findings))
	keys := make(map[string]bool, len(findings)*2)
	for _, f := range findings {
		id, purl, ok := strings.Cut(f.Key, "|")
		if ok {
			canonical[strings.ToUpper(id)+"|"+purl] = true
		}
		for _, k := range f.AllKeys() {
			aid, apurl, aok := strings.Cut(k, "|")
			if aok {
				keys[strings.ToUpper(aid)+"|"+apurl] = true
			}
		}
	}
	return scannerRun{Status: "OK(" + string(state) + ")", TotalFindings: len(findings), CanonicalKeys: canonical, Findings: keys}
}

func runOSVScanner(fixtureDir string, eco types.Ecosystem) scannerRun {
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		return scannerRun{Status: "N/A"}
	}
	cmd := exec.Command("osv-scanner", "--format", "json", fixtureDir)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return scannerRun{Status: "FAILED"}
	}
	var payload struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID      string   `json:"id"`
					Aliases []string `json:"aliases"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if json.Unmarshal(out, &payload) != nil {
		return scannerRun{Status: "FAILED"}
	}
	keys := make(map[string]bool)
	for _, r := range payload.Results {
		for _, p := range r.Packages {
			purl := policy.BuildPURL(eco, p.Package.Name, p.Package.Version)
			for _, v := range p.Vulnerabilities {
				keys[strings.ToUpper(v.ID)+"|"+purl] = true
				for _, a := range v.Aliases {
					keys[strings.ToUpper(a)+"|"+purl] = true
				}
			}
		}
	}
	return scannerRun{Status: "OK", Findings: keys}
}

func runTrivy(fixtureDir string, eco types.Ecosystem) scannerRun {
	if _, err := exec.LookPath("trivy"); err != nil {
		return scannerRun{Status: "N/A"}
	}
	cmd := exec.Command("trivy", "fs", "--format", "json", "--quiet", fixtureDir)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return scannerRun{Status: "FAILED"}
	}
	var payload struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if json.Unmarshal(out, &payload) != nil {
		return scannerRun{Status: "FAILED"}
	}
	keys := make(map[string]bool)
	for _, r := range payload.Results {
		for _, v := range r.Vulnerabilities {
			purl := policy.BuildPURL(eco, v.PkgName, v.InstalledVersion)
			keys[strings.ToUpper(v.VulnerabilityID)+"|"+purl] = true
		}
	}
	return scannerRun{Status: "OK", Findings: keys}
}

func runGrype(fixtureDir string, eco types.Ecosystem) scannerRun {
	if _, err := exec.LookPath("grype"); err != nil {
		return scannerRun{Status: "N/A"}
	}
	cmd := exec.Command("grype", "dir:"+fixtureDir, "-o", "json", "-q")
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return scannerRun{Status: "FAILED"}
	}
	var payload struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
			RelatedVulnerabilities []struct {
				ID string `json:"id"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if json.Unmarshal(out, &payload) != nil {
		return scannerRun{Status: "FAILED"}
	}
	keys := make(map[string]bool)
	for _, m := range payload.Matches {
		purl := m.Artifact.PURL
		if purl == "" {
			purl = policy.BuildPURL(eco, m.Artifact.Name, m.Artifact.Version)
		}
		keys[strings.ToUpper(m.Vulnerability.ID)+"|"+purl] = true
		for _, rel := range m.RelatedVulnerabilities {
			keys[strings.ToUpper(rel.ID)+"|"+purl] = true
		}
	}
	return scannerRun{Status: "OK", Findings: keys}
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0644); err != nil {
			return err
		}
	}
	return nil
}
