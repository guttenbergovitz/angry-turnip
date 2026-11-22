package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type expectedCVE struct {
	PURL string `json:"purl"`
	CVE  string `json:"cve"`
}

type expectedFixture struct {
	Ecosystem           string        `json:"ecosystem"`
	KnownHistoricalCVEs []expectedCVE `json:"known_historical_cves"`
}

// scannerRun captures both the execution state and normalized (CVE|PURL) finding keys.
type scannerRun struct {
	Status   string          // "OK", "FAILED", "N/A"
	Findings map[string]bool // canonical "<CVE>|<PURL>" or "<ID>|<PURL>"
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

		expectedKeys := make(map[string]bool, len(exp.KnownHistoricalCVEs))
		for _, item := range exp.KnownHistoricalCVEs {
			expectedKeys[strings.ToUpper(item.CVE)+"|"+item.PURL] = true
		}

		vigilRun := runVigil(fixtureDir)
		osvRun := runOSVScanner(fixtureDir, types.Ecosystem(exp.Ecosystem))
		trivyRun := runTrivy(fixtureDir, types.Ecosystem(exp.Ecosystem))
		grypeRun := runGrype(fixtureDir, types.Ecosystem(exp.Ecosystem))

		fmt.Printf("%-10s | %-24s | %-24s | %-24s | %-24s\n",
			eco,
			formatScore(vigilRun, expectedKeys),
			formatScore(osvRun, expectedKeys),
			formatScore(trivyRun, expectedKeys),
			formatScore(grypeRun, expectedKeys),
		)
	}
}

func formatScore(run scannerRun, expected map[string]bool) string {
	if run.Status != "OK" {
		return run.Status
	}
	hits := 0
	for k := range expected {
		if run.Findings[k] {
			hits++
		}
	}
	return fmt.Sprintf("OK (rec %d/%d, tot %d)", hits, len(expected), len(run.Findings))
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

	// Execute `vigil scan --no-tui --output json` first; then evaluate canonical findings.
	scanCmd := exec.Command("go", "run", "./cmd/vigil", "scan", "--no-tui", "--output", "json", tmpDir)
	out, err := scanCmd.Output()
	if err != nil {
		// Exit code 1 indicates vulnerabilities were found (valid scan completion); check JSON payload.
		if len(out) == 0 {
			return scannerRun{Status: "FAILED"}
		}
	}

	var result types.ScanResult
	if json.Unmarshal(out, &result) != nil {
		return scannerRun{Status: "FAILED"}
	}
	state, _ := policy.ValidateEvidence(&result)
	if state == policy.EvidenceInvalid || state == policy.EvidenceUnverified {
		return scannerRun{Status: "FAILED(" + string(state) + ")"}
	}

	findings := policy.BuildFindings(&result)
	keys := make(map[string]bool, len(findings))
	for _, f := range findings {
		for _, k := range f.AllKeys() {
			id, purl, ok := strings.Cut(k, "|")
			if ok {
				keys[strings.ToUpper(id)+"|"+purl] = true
			}
		}
	}
	return scannerRun{Status: "OK", Findings: keys}
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
