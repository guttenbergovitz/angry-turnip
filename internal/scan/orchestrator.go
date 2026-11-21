package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// ProgressReporter defines how the orchestrator reports progress to the UI
type ProgressReporter interface {
	Error(msg string)
	Progress(current, total int, currentPkg string, currentVulns int)
	Vulnerability(vuln types.Vulnerability, pkg string, path []string)
	Done(result *types.ScanResult)
}

// Scan performs the vulnerability scan
func Scan(ctx context.Context, absPath, lockFile string, lockType lockfile.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, reporter ProgressReporter) (*types.ScanResult, error) {
	// Check if lock file path is valid
	if lockFilePath == "" || lockFile == "" {
		errMsg := "No lock file found. Please run this in a Node.js/TypeScript project with package-lock.json, yarn.lock, or pnpm-lock.yaml"
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Parse lock file and build dependency graph
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

	// parseLockFile handles parse error reporting pattern
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

	// Parse lock file based on type
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

	// Check if graph has any nodes
	if len(graph.Nodes) == 0 {
		errMsg := "No dependencies found in lock file. The project may have no dependencies or the lock file is empty."
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Scan all dependencies sequentially to respect API rate limits
	osvClient := osv.New("https://api.osv.dev/v1/query", 10)

	// Initialize NVD client with API key from environment
	nvdAPIKey := os.Getenv("NVD_API_KEY")
	nvdClient := nvd.New("https://services.nvd.nist.gov/rest/json/cves/2.0", nvdAPIKey, 10)

	// Initialize GitHub client (token optional; falls back to public API)
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubClient := github.New(githubToken, 10)

	// Initialize npm registry client for temporal filtering
	npmClient := npm.New("https://registry.npmjs.org", 10)

	// Count nodes to scan and collect them (pre-allocate)
	nodesToScanList := make([]*types.DependencyNode, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		// Skip orphaned nodes (not reachable from root) ONLY for pnpm
		// For npm/yarn, we don't have proper graph structure (all nodes are marked as root)
		if lockType == lockfile.PnpmLock && node.Depth == -1 {
			continue
		}
		if skipDevDeps && node.Type == types.Development {
			continue
		}
		nodesToScanList = append(nodesToScanList, node)
	}

	nodesToScan := len(nodesToScanList)

	// Send initial progress with total
	if reporter != nil {
		reporter.Progress(0, nodesToScan, "Starting scan...", 0)
	}

	var totalVulns atomic.Int32
	var scanned atomic.Int32
	var resultMu sync.Mutex

	// Parallel scanning with worker pool
	numWorkers := getWorkerCount()
	pool := NewWorkerPool(ctx, numWorkers, func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		// Send live progress update when worker begins inspecting package
		if reporter != nil {
			reporter.Progress(int(scanned.Load()), nodesToScan, nodeKey, int(totalVulns.Load()))
		}

		// Query OSV API for this package
		vulns, err := osvClient.QueryWithEcosystem(node.Name, node.Version, graph.Ecosystem)
		if err != nil {
			return nil, err
		}

		// Fetch package release date for temporal filtering ONLY if vulnerabilities exist and ecosystem is NPM
		var releasedAt *time.Time
		if len(vulns) > 0 && graph.Ecosystem == types.EcosystemNPM {
			releasedAt, _ = npmClient.GetReleaseDate(node.Name, node.Version)
		}

		// Process vulnerabilities
		for j := range vulns {
			vulns[j].RiskScore = osv.CalculateRiskScoreWithDepth(
				vulns[j].Severity,
				node.Type == types.Production,
				node.Depth,
			)

			// Get full dependency path from root
			dependencyPath := graph.GetVulnerablePath(nodeKey)

			// Try multiple sources for CVSS score (priority: NVD > GitHub > OSV > derived from severity)
			originalCVSS := vulns[j].CVSSScore

			// 1. Try NVD API for CVE-* IDs (only when NVD_API_KEY is set to avoid 6s rate-limit delays)
			if vulns[j].CVEID != "" && strings.HasPrefix(vulns[j].CVEID, "CVE-") && nvdAPIKey != "" {
				nvdVuln, err := nvdClient.QueryCVE(vulns[j].CVEID)
				if err == nil && nvdVuln != nil {
					// Enrich with NVD data
					vulns[j].CVETitle = nvdVuln.CVETitle
					vulns[j].CVEDescription = nvdVuln.CVEDescription
					// Use NVD severity if available (it's more authoritative for CVE)
					if nvdVuln.CVESeverity != "" {
						vulns[j].CVESeverity = nvdVuln.CVESeverity
						vulns[j].Severity = nvdVuln.CVESeverity // Override with NVD severity
					}
					// Always use NVD CVSS score if available (NVD is authoritative for CVE)
					if nvdVuln.CVSSScore > 0 {
						vulns[j].CVSSScore = nvdVuln.CVSSScore
						vulns[j].CVSSVector = nvdVuln.CVSSVector
					}
				}

				time.Sleep(600 * time.Millisecond) // 50 req/30s = 600ms between requests with API key
			}

			// 2. If still no CVSS and it's a GHSA-*, try GitHub Security Advisories API
			if vulns[j].CVSSScore == 0 && strings.HasPrefix(vulns[j].ID, "GHSA-") {
				if githubClient != nil {
					ghsaVuln, err := githubClient.QueryGHSA(vulns[j].ID)
					if err == nil && ghsaVuln != nil && ghsaVuln.CVSSScore > 0 {
						vulns[j].CVSSScore = ghsaVuln.CVSSScore
						vulns[j].CVSSVector = ghsaVuln.CVSSVector
						if vulns[j].CVETitle == "" {
							vulns[j].CVETitle = ghsaVuln.Summary
						}
						if vulns[j].CVEDescription == "" {
							vulns[j].CVEDescription = ghsaVuln.Description
						}
						// Use GHSA severity if we don't have a better one
						if ghsaVuln.Severity != "" {
							vulns[j].Severity = ghsaVuln.Severity
							vulns[j].CVESeverity = ghsaVuln.Severity
						}
					}
				}
			}

			// 3. If still no CVSS, use OSV CVSS (should already be set, but ensure it's used)
			if vulns[j].CVSSScore == 0 && originalCVSS > 0 {
				vulns[j].CVSSScore = originalCVSS
			}

			// 4. If still no CVSS, derive from severity as last resort
			if vulns[j].CVSSScore == 0 {
				vulns[j].CVSSScore = types.DeriveCVSSFromSeverity(vulns[j].Severity)
			}

			// 5. If CVSS is present but severity is weak/unknown, derive severity from CVSS
			if vulns[j].CVSSScore > 0 {
				derivedSev := types.SeverityFromCVSS(vulns[j].CVSSScore)
				if vulns[j].Severity == "" || strings.EqualFold(string(vulns[j].Severity), "medium") || strings.EqualFold(string(vulns[j].Severity), "unknown") {
					vulns[j].Severity = derivedSev
				}
				if vulns[j].CVESeverity == "" {
					vulns[j].CVESeverity = derivedSev
				}
			}

			// Send vulnerability to TUI for dynamic display
			if reporter != nil {
				reporter.Vulnerability(vulns[j], nodeKey, dependencyPath)
			}
		}

		// Apply temporal filtering (remove vulnerabilities published before package release)
		vulns = types.FilterTemporalFalsePositives(releasedAt, vulns)

		return vulns, nil
	})

	// Collect results in background goroutine started before submitting jobs to avoid deadlock
	doneCollecting := make(chan struct{})
	go func() {
		defer close(doneCollecting)
		for result := range pool.Results() {
			resultMu.Lock()
			if result.Error == nil {
				result.Node.Vulnerabilities = result.Vulns
				totalVulns.Add(int32(len(result.Vulns)))
			}
			current := scanned.Add(1)

			// Send progress update
			if reporter != nil {
				reporter.Progress(int(current), nodesToScan, result.NodeKey, int(totalVulns.Load()))
			}
			resultMu.Unlock()
		}
	}()

	pool.Start()

	// Submit all jobs
	for _, node := range nodesToScanList {
		nodeKey := node.Name + "@" + node.Version
		if !pool.Submit(ScanJob{
			Node:    node,
			NodeKey: nodeKey,
		}) {
			break
		}
	}

	pool.Close()
	<-doneCollecting

	// Build result
	result := buildScanResultFromGraph(absPath, lockFile, lockHash, graph, lockType)

	// Send completion with results
	if reporter != nil {
		reporter.Done(result)
	}

	// Save cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	if err := lockfile.SaveCache(cachePath, result); err != nil {
		return nil, fmt.Errorf("save cache: %w", err)
	}

	return result, nil
}

func buildScanResultFromGraph(projectPath, lockFile, lockHash string, graph *types.DependencyGraph, lockType lockfile.LockFileType) *types.ScanResult {
	// Convert graph nodes to flat dependency list
	deps := make([]types.Dependency, 0, len(graph.Nodes))

	for _, node := range graph.Nodes {
		// Skip orphaned nodes ONLY for pnpm (where we have reliable graph structure)
		if lockType == lockfile.PnpmLock && node.Depth == -1 {
			continue
		}
		dep := types.Dependency{
			Name:            node.Name,
			Version:         node.Version,
			Ecosystem:       lockType.Ecosystem(),
			Type:            node.Type,
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
	}

	// Count vulnerabilities by severity (use CVESeverity from NVD if available)
	// Count vulnerabilities by severity (use CVESeverity from NVD if available)
	for _, node := range graph.Nodes {
		for _, vuln := range node.Vulnerabilities {
			result.TotalVulns++
			// Use CVESeverity from NVD if available, otherwise use Severity
			severity := vuln.Severity
			if vuln.CVESeverity != "" {
				severity = vuln.CVESeverity
			}

			// Normalize severity to lowercase
			normalizedSev := types.Severity(strings.ToLower(string(severity)))

			switch normalizedSev {
			case types.Critical:
				result.CriticalVulns++
			case types.High:
				result.HighVulns++
			case types.Medium:
				result.MediumVulns++
			case types.Low:
				result.LowVulns++
			default:
				// If severity is unknown or unmapped, count as Low for now to avoid "missing" vulns in summary
				// Ideally we should have an Unknown type, but for now this ensures the math works
				result.LowVulns++
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

// getWorkerCount returns number of parallel workers from env var VIGIL_WORKERS (default 10, max 100).
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
