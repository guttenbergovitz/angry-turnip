package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/github"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/npm"
	"github.com/guttenbergovitz/vigil-cli/internal/nvd"
	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ProgressReporter defines how the orchestrator reports progress to the UI.
type ProgressReporter interface {
	Error(msg string)
	Progress(current, total int, currentPkg string, currentVulns int)
	Vulnerability(vuln types.Vulnerability, pkg string, path []string)
	Done(result *types.ScanResult)
}

// Scan performs the vulnerability scan for a project lock file.
func Scan(ctx context.Context, absPath, lockFile string, lockType lockfile.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, reporter ProgressReporter) (*types.ScanResult, error) {
	if lockFilePath == "" || lockFile == "" {
		errMsg := "No lock file found. Please run this in a project with a supported lock file."
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	lockf, err := os.Open(lockFilePath)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to open lock file: %v", err)
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockf.Close()

	var graph *types.DependencyGraph

	parseLockFile := func(fileName string, parseErr error) error {
		if parseErr == nil {
			return nil
		}
		errMsg := fmt.Sprintf("Failed to parse %s: %v", fileName, parseErr)
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return fmt.Errorf("failed to parse %s: %w", fileName, parseErr)
	}

	switch lockType {
	case lockfile.PnpmLock:
		graph, err = lockfile.ParsePnpmLockGraph(lockf)
		if err = parseLockFile("pnpm-lock.yaml", err); err != nil {
			return nil, err
		}
	case lockfile.NPMLock:
		graph, err = lockfile.ParseNPMLockGraph(lockf)
		if err = parseLockFile("package-lock.json", err); err != nil {
			return nil, err
		}
	case lockfile.YarnLock:
		graph, err = lockfile.ParseYarnLockGraph(lockf)
		if err = parseLockFile("yarn.lock", err); err != nil {
			return nil, err
		}
	case lockfile.UVLock:
		graph, err = lockfile.ParseUVLockGraph(lockf)
		if err = parseLockFile("uv.lock", err); err != nil {
			return nil, err
		}
	case lockfile.PoetryLock:
		var deps *lockfile.Dependencies
		deps, err = lockfile.ParsePoetryLock(lockf)
		if err = parseLockFile("poetry.lock", err); err != nil {
			return nil, err
		}
		graph = buildGraphFromDeps(deps, lockType.Ecosystem())
	case lockfile.PipfileLock:
		var deps *lockfile.Dependencies
		deps, err = lockfile.ParsePipfileLock(lockf)
		if err = parseLockFile("Pipfile.lock", err); err != nil {
			return nil, err
		}
		graph = buildGraphFromDeps(deps, lockType.Ecosystem())
	case lockfile.RequirementsTxt:
		var deps *lockfile.Dependencies
		deps, err = lockfile.ParseRequirementsTxt(lockf)
		if err = parseLockFile("requirements.txt", err); err != nil {
			return nil, err
		}
		graph = buildGraphFromDeps(deps, lockType.Ecosystem())
	case lockfile.CargoLock:
		graph, err = lockfile.ParseCargoLockGraph(lockf)
		if err = parseLockFile("Cargo.lock", err); err != nil {
			return nil, err
		}
	case lockfile.ComposerLock:
		graph, err = lockfile.ParseComposerLockGraph(lockf)
		if err = parseLockFile("composer.lock", err); err != nil {
			return nil, err
		}
	case lockfile.GoModLock:
		graph, err = lockfile.ParseGoModGraph(lockf)
		if err = parseLockFile("go.mod", err); err != nil {
			return nil, err
		}
	case lockfile.PomXml:
		var deps *lockfile.Dependencies
		deps, err = lockfile.ParsePomXml(lockf)
		if err = parseLockFile("pom.xml", err); err != nil {
			return nil, err
		}
		graph = buildGraphFromDeps(deps, lockType.Ecosystem())
	case lockfile.GradleLock:
		var deps *lockfile.Dependencies
		deps, err = lockfile.ParseGradleLockfile(lockf)
		if err = parseLockFile("gradle.lockfile", err); err != nil {
			return nil, err
		}
		graph = buildGraphFromDeps(deps, lockType.Ecosystem())
	default:
		return nil, fmt.Errorf("unsupported lock file type: %s", lockType)
	}

	if len(graph.Nodes) == 0 {
		errMsg := "No dependencies found in lock file. The project may have no dependencies or the lock file is empty."
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	osvClient := osv.New("https://api.osv.dev/v1/query", 10)
	nvdAPIKey := os.Getenv("NVD_API_KEY")
	nvdClient := nvd.New("https://services.nvd.nist.gov/rest/json/cves/2.0", nvdAPIKey, 10)
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubClient := github.New(githubToken, 10)
	npmClient := npm.New("https://registry.npmjs.org", 10)

	scanFn := func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		vulns, err := osvClient.QueryWithEcosystemContext(queryCtx, node.Name, node.Version, graph.Ecosystem)
		if err != nil {
			return nil, err
		}

		// Optionally fetch release date as informational metadata for npm packages.
		// Release dates are never used to filter or discard vulnerabilities.
		if len(vulns) > 0 && graph.Ecosystem == types.EcosystemNPM {
			if releasedAt, relErr := npmClient.GetReleaseDate(node.Name, node.Version); relErr == nil {
				node.ReleasedAt = releasedAt
			}
		}

		for j := range vulns {
			enrichVulnerability(&vulns[j], node, nvdAPIKey, nvdClient, githubClient)
		}

		return vulns, nil
	}

	result := scanGraph(ctx, absPath, lockFile, lockHash, graph, lockType, skipDevDeps, reporter, scanFn)

	if reporter != nil {
		reporter.Done(result)
	}

	cachePath := filepath.Join(absPath, ".vigil.cache")
	if err := lockfile.SaveCache(cachePath, result); err != nil {
		return nil, fmt.Errorf("save cache: %w", err)
	}

	return result, nil
}

// enrichVulnerability enriches a single vulnerability with NVD/GHSA CVSS data and risk score.
func enrichVulnerability(
	vuln *types.Vulnerability,
	node *types.DependencyNode,
	nvdAPIKey string,
	nvdClient *nvd.Client,
	githubClient *github.Client,
) {
	originalCVSS := vuln.CVSSScore

	// 1. Try NVD API for CVE-* IDs when NVD_API_KEY is configured.
	if vuln.CVEID != "" && strings.HasPrefix(vuln.CVEID, "CVE-") && nvdAPIKey != "" {
		nvdVuln, err := nvdClient.QueryCVE(vuln.CVEID)
		if err == nil && nvdVuln != nil {
			vuln.CVETitle = nvdVuln.CVETitle
			vuln.CVEDescription = nvdVuln.CVEDescription
			if nvdVuln.CVESeverity != "" {
				vuln.CVESeverity = types.NormaliseSeverity(nvdVuln.CVESeverity)
				vuln.Severity = vuln.CVESeverity
			}
			if nvdVuln.CVSSScore > 0 {
				vuln.CVSSScore = nvdVuln.CVSSScore
				vuln.CVSSVector = nvdVuln.CVSSVector
			}
		}

		time.Sleep(600 * time.Millisecond)
	}

	// 2. If still no CVSS and it is a GHSA-*, try GitHub Security Advisories API.
	if vuln.CVSSScore == 0 && strings.HasPrefix(vuln.ID, "GHSA-") && githubClient != nil {
		ghsaVuln, err := githubClient.QueryGHSA(vuln.ID)
		if err == nil && ghsaVuln != nil && ghsaVuln.CVSSScore > 0 {
			vuln.CVSSScore = ghsaVuln.CVSSScore
			vuln.CVSSVector = ghsaVuln.CVSSVector
			if vuln.CVETitle == "" {
				vuln.CVETitle = ghsaVuln.Summary
			}
			if vuln.CVEDescription == "" {
				vuln.CVEDescription = ghsaVuln.Description
			}
			if ghsaVuln.Severity != "" {
				normalised := types.NormaliseSeverity(ghsaVuln.Severity)
				vuln.Severity = normalised
				vuln.CVESeverity = normalised
			}
		}
	}

	// 3. Preserve original OSV CVSS score if available.
	if vuln.CVSSScore == 0 && originalCVSS > 0 {
		vuln.CVSSScore = originalCVSS
	}

	// 4. Derive fallback CVSS only when severity is explicitly known.
	vuln.Severity = types.NormaliseSeverity(vuln.Severity)
	if vuln.CVSSScore == 0 && vuln.Severity != types.Unknown {
		vuln.CVSSScore = types.DeriveCVSSFromSeverity(vuln.Severity)
	}

	// 5. Derive severity from CVSS when CVSS is present and severity is missing/unknown.
	if vuln.CVSSScore > 0 {
		derivedSev := types.SeverityFromCVSS(vuln.CVSSScore)
		if vuln.Severity == types.Unknown {
			vuln.Severity = derivedSev
		}
		if vuln.CVESeverity == "" {
			vuln.CVESeverity = derivedSev
		}
	}

	vuln.RiskScore = osv.CalculateRiskScoreWithDepth(
		vuln.Severity,
		node.Type == types.Production,
		node.Depth,
	)
}

// scanGraph executes concurrent vulnerability scanning over a dependency graph using scanFn.
// Every node receives an explicit ScanStatus (scanned, failed, skipped, or unsupported) so that
// API errors are never silently disguised as zero vulnerabilities.
func scanGraph(
	ctx context.Context,
	projectPath, lockFile, lockHash string,
	graph *types.DependencyGraph,
	lockType lockfile.LockFileType,
	skipDevDeps bool,
	reporter ProgressReporter,
	scanFn ScanFunc,
) *types.ScanResult {
	// Sort node keys deterministically before queueing work.
	nodeKeys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		nodeKeys = append(nodeKeys, key)
	}
	sort.Strings(nodeKeys)

	nodesToScanList := make([]*types.DependencyNode, 0, len(graph.Nodes))
	for _, key := range nodeKeys {
		node := graph.Nodes[key]
		if lockType == lockfile.PnpmLock && node.Depth == -1 {
			node.ScanStatus = types.StatusSkipped
			continue
		}
		if skipDevDeps && node.Type == types.Development {
			node.ScanStatus = types.StatusSkipped
			continue
		}
		if strings.TrimSpace(node.Name) == "" || strings.TrimSpace(node.Version) == "" {
			node.ScanStatus = types.StatusUnsupported
			node.ScanError = "missing package name or version"
			continue
		}
		nodesToScanList = append(nodesToScanList, node)
	}

	nodesToScan := len(nodesToScanList)

	if reporter != nil {
		reporter.Progress(0, nodesToScan, "Starting scan...", 0)
	}

	var totalVulns atomic.Int32
	var processed atomic.Int32
	var resultMu sync.Mutex

	numWorkers := getWorkerCount()
	pool := NewWorkerPool(ctx, numWorkers, func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		if reporter != nil {
			reporter.Progress(int(processed.Load()), nodesToScan, nodeKey, int(totalVulns.Load()))
		}
		return scanFn(ctx, node, nodeKey)
	})

	doneCollecting := make(chan struct{})
	go func() {
		defer close(doneCollecting)
		for res := range pool.Results() {
			resultMu.Lock()
			if res.Error != nil {
				res.Node.ScanStatus = types.StatusFailed
				res.Node.ScanError = res.Error.Error()
			} else {
				res.Node.ScanStatus = types.StatusScanned
				res.Node.ScanError = ""
				res.Node.Vulnerabilities = res.Vulns
				totalVulns.Add(int32(len(res.Vulns)))

				// Emit vulnerabilities to reporter only after final processing so TUI matches ScanResult.
				if reporter != nil {
					dependencyPath := graph.GetVulnerablePath(res.NodeKey)
					for _, vuln := range res.Vulns {
						reporter.Vulnerability(vuln, res.NodeKey, dependencyPath)
					}
				}
			}

			current := processed.Add(1)
			if reporter != nil {
				reporter.Progress(int(current), nodesToScan, res.NodeKey, int(totalVulns.Load()))
			}
			resultMu.Unlock()
		}
	}()

	pool.Start()

	for _, node := range nodesToScanList {
		nodeKey := node.Name + "@" + node.Version
		if !pool.Submit(ScanJob{
			Node:    node,
			NodeKey: nodeKey,
		}) {
			// Context cancelled before submission: mark remaining nodes as failed.
			node.ScanStatus = types.StatusFailed
			if ctx.Err() != nil {
				node.ScanError = ctx.Err().Error()
			} else {
				node.ScanError = "scan cancelled before package was queued"
			}
		}
	}

	pool.Close()
	<-doneCollecting

	// Any node submitted to the pool that never produced a result (e.g. context cancelled mid-flight)
	// must be recorded as failed rather than silently omitted.
	for _, node := range nodesToScanList {
		if node.ScanStatus == "" {
			node.ScanStatus = types.StatusFailed
			if ctx.Err() != nil {
				node.ScanError = ctx.Err().Error()
			} else {
				node.ScanError = "scan aborted before completion"
			}
		}
	}

	return buildScanResultFromGraph(projectPath, lockFile, lockHash, graph, lockType)
}

func buildScanResultFromGraph(projectPath, lockFile, lockHash string, graph *types.DependencyGraph, lockType lockfile.LockFileType) *types.ScanResult {
	nodeKeys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		nodeKeys = append(nodeKeys, key)
	}
	sort.Strings(nodeKeys)

	deps := make([]types.Dependency, 0, len(graph.Nodes))
	var coverage types.ScanCoverage

	for _, key := range nodeKeys {
		node := graph.Nodes[key]

		// Exclude orphaned pnpm nodes from the dependency list, but count them in skipped coverage.
		if lockType == lockfile.PnpmLock && node.Depth == -1 {
			coverage.TotalPackages++
			coverage.SkippedPackages++
			continue
		}

		coverage.TotalPackages++
		switch node.ScanStatus {
		case types.StatusScanned:
			coverage.ScannedPackages++
		case types.StatusFailed:
			coverage.FailedPackages++
			coverage.Errors = append(coverage.Errors, types.PackageScanError{
				Package: node.Name,
				Version: node.Version,
				Error:   node.ScanError,
			})
		case types.StatusSkipped:
			coverage.SkippedPackages++
		case types.StatusUnsupported:
			coverage.UnsupportedPackages++
		default:
			coverage.FailedPackages++
			coverage.Errors = append(coverage.Errors, types.PackageScanError{
				Package: node.Name,
				Version: node.Version,
				Error:   "package was not evaluated",
			})
		}

		dep := types.Dependency{
			Name:            node.Name,
			Version:         node.Version,
			Ecosystem:       lockType.Ecosystem(),
			Type:            node.Type,
			Direct:          node.Direct,
			ReleasedAt:      node.ReleasedAt,
			ScanStatus:      node.ScanStatus,
			ScanError:       node.ScanError,
			Vulnerabilities: node.Vulnerabilities,
		}
		deps = append(deps, dep)
	}

	result := &types.ScanResult{
		Version:      1,
		ProjectPath:  projectPath,
		ScannedAt:    time.Now().UTC(),
		LockFile:     lockFile,
		LockFileHash: lockHash,
		Dependencies: deps,
		Coverage:     coverage,
	}

	for _, dep := range deps {
		for _, vuln := range dep.Vulnerabilities {
			result.TotalVulns++
			severity := vuln.Severity
			if vuln.CVESeverity != "" {
				severity = vuln.CVESeverity
			}

			switch types.NormaliseSeverity(severity) {
			case types.Critical:
				result.CriticalVulns++
			case types.High:
				result.HighVulns++
			case types.Medium:
				result.MediumVulns++
			case types.Low:
				result.LowVulns++
			default:
				result.UnknownVulns++
			}
		}
	}

	return result
}

// buildGraphFromDeps constructs a DependencyGraph from flat Dependencies for lockfiles without native graph support.
func buildGraphFromDeps(deps *lockfile.Dependencies, ecosystem types.Ecosystem) *types.DependencyGraph {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = ecosystem

	for name, version := range deps.Production {
		node := graph.AddNode(name, version, types.Production, true)
		graph.Root = append(graph.Root, node.Name+"@"+node.Version)
	}
	for name, version := range deps.Development {
		node := graph.AddNode(name, version, types.Development, true)
		graph.Root = append(graph.Root, node.Name+"@"+node.Version)
	}

	graph.CalculateDepths()
	return graph
}

// getWorkerCount returns the number of parallel workers from VIGIL_WORKERS (default 10, max 100).
func getWorkerCount() int {
	workers := os.Getenv("VIGIL_WORKERS")
	if workers == "" {
		return 10
	}

	count := 0
	_, err := fmt.Sscanf(workers, "%d", &count)
	if err != nil || count <= 0 || count > 100 {
		return 10
	}
	return count
}
