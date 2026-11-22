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

	"github.com/guttenbergovitz/angry-turnip/internal/lockfile"
	"github.com/guttenbergovitz/angry-turnip/internal/osv"
	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

// ProgressReporter defines how the orchestrator reports progress to the UI.
type ProgressReporter interface {
	Error(msg string)
	Progress(current, total int, currentPkg string, currentVulns int)
	Vulnerability(vuln types.Vulnerability, pkg string, path []string)
	Done(result *types.ScanResult)
}

// Scan performs the vulnerability scan for a project lock file using DefaultScanner.
func Scan(ctx context.Context, absPath, lockFile string, lockType lockfile.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, reporter ProgressReporter) (*types.ScanResult, error) {
	return DefaultScanner().Scan(ctx, absPath, lockFile, lockType, lockHash, lockFilePath, skipDevDeps, reporter)
}

// Scan parses the lock file, scans all resolved dependencies using the Scanner's injected clients,
// persists the scan snapshot to .atnp.cache, and returns the resulting ScanResult.
func (s *Scanner) Scan(ctx context.Context, absPath, lockFile string, lockType lockfile.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, reporter ProgressReporter) (*types.ScanResult, error) {
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
		graph, err = lockfile.ParsePoetryLockGraph(lockf)
		if err = parseLockFile("poetry.lock", err); err != nil {
			return nil, err
		}
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
		deps, err = lockfile.ParsePomXmlFile(lockFilePath)
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

	totalNodes := len(graph.Nodes)
	emitStage(reporter, ScanEvent{
		Stage:   StageDiscovery,
		Status:  StageCompleted,
		Current: totalNodes,
		Total:   intPtr(totalNodes),
		Message: fmt.Sprintf("Discovered %d components in %s (%s)", totalNodes, lockFile, graph.Ecosystem),
	})

	resStatus := StageCompleted
	if len(graph.Unresolved) > 0 || len(graph.Ambiguous) > 0 || lockType == lockfile.PomXml || lockType == lockfile.GoModLock || lockType == lockfile.RequirementsTxt {
		resStatus = StagePartial
	}
	emitStage(reporter, ScanEvent{
		Stage:   StageResolution,
		Status:  resStatus,
		Current: totalNodes - len(graph.Unresolved),
		Total:   intPtr(totalNodes),
		Message: fmt.Sprintf("%d resolved, %d unresolved, %d ambiguous edges", totalNodes-len(graph.Unresolved), len(graph.Unresolved), len(graph.Ambiguous)),
	})

	var enrichedCount atomic.Int32
	scanFn := func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		vulns, err := s.VulnSource.QueryWithEcosystemContext(queryCtx, node.Name, node.Version, graph.Ecosystem)
		if err != nil {
			return nil, err
		}

		// Optionally fetch release date as informational metadata for npm packages.
		// Release dates are never used to filter or discard vulnerabilities.
		if len(vulns) > 0 && graph.Ecosystem == types.EcosystemNPM && s.ReleaseDates != nil {
			if releasedAt, relErr := s.ReleaseDates.GetReleaseDate(node.Name, node.Version); relErr == nil {
				node.ReleasedAt = releasedAt
			}
		}

		for j := range vulns {
			s.enrichVulnerability(ctx, &vulns[j], node)
			enrichedCount.Add(1)
		}

		return vulns, nil
	}

	result := scanGraph(ctx, absPath, lockFile, lockHash, graph, lockType, skipDevDeps, reporter, scanFn)
	if enrichedCount.Load() > 0 {
		emitStage(reporter, ScanEvent{
			Stage:   StageEnrichment,
			Status:  StageCompleted,
			Current: int(enrichedCount.Load()),
			Total:   intPtr(int(enrichedCount.Load())),
			Message: fmt.Sprintf("Enriched %d advisory records (NVD=%v, GHSA=enabled)", enrichedCount.Load(), s.NVDEnabled),
		})
	} else {
		emitStage(reporter, ScanEvent{
			Stage:   StageEnrichment,
			Status:  StageSkipped,
			Message: "No advisories required NVD/GHSA enrichment",
		})
	}

	s.enrichThreatIntelWithReporter(ctx, result, reporter)

	if reporter != nil {
		reporter.Done(result)
	}

	cachePath := filepath.Join(absPath, lockfile.DefaultCacheFileName)
	if err := lockfile.SaveCache(cachePath, result); err != nil {
		return nil, fmt.Errorf("save cache: %w", err)
	}

	return result, nil
}

// enrichVulnerability enriches a single vulnerability with NVD/GHSA CVSS data and risk score.
func (s *Scanner) enrichVulnerability(ctx context.Context, vuln *types.Vulnerability, node *types.DependencyNode) {
	originalCVSS := vuln.CVSSScore

	// 1. Try NVD API for CVE-* IDs when configured, coordinated through the global rate limiter.
	if vuln.CVEID != "" && strings.HasPrefix(vuln.CVEID, "CVE-") && s.NVDEnabled && s.CVEEnricher != nil {
		if err := s.NVDLimiter.Wait(ctx); err == nil {
			nvdVuln, err := s.CVEEnricher.QueryCVE(vuln.CVEID)
			if err == nil && nvdVuln != nil {
				vuln.CVETitle = nvdVuln.CVETitle
				vuln.CVEDescription = nvdVuln.CVEDescription
				if nvdVuln.CVESeverity != "" && nvdVuln.CVESeverity != types.Unknown {
					vuln.CVESeverity = types.NormaliseSeverity(nvdVuln.CVESeverity)
					vuln.Severity = vuln.CVESeverity
				}
				if nvdVuln.CVSSScore > 0 {
					vuln.CVSSScore = nvdVuln.CVSSScore
					vuln.CVSSVector = nvdVuln.CVSSVector
				}
			}
		}
	}

	// 2. If still no CVSS and it is a GHSA-*, try GitHub Security Advisories API.
	if vuln.CVSSScore == 0 && strings.HasPrefix(vuln.ID, "GHSA-") && s.GHSAEnricher != nil {
		ghsaVuln, err := s.GHSAEnricher.QueryGHSA(vuln.ID)
		if err == nil && ghsaVuln != nil && ghsaVuln.CVSSScore > 0 {
			vuln.CVSSScore = ghsaVuln.CVSSScore
			vuln.CVSSVector = ghsaVuln.CVSSVector
			if vuln.CVETitle == "" {
				vuln.CVETitle = ghsaVuln.Summary
			}
			if vuln.CVEDescription == "" {
				vuln.CVEDescription = ghsaVuln.Description
			}
			if ghsaVuln.Severity != "" && ghsaVuln.Severity != types.Unknown {
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

// enrichThreatIntel performs a single best-effort parallel batch pass over discovered CVE
// identifiers to attach keyless threat-intelligence signals (CISA KEV and FIRST EPSS) with
// independent per-source timeouts and explicit provenance statuses. Failures never degrade
// scan coverage or drop vulnerabilities, and are never conflated with negative lookups.
func (s *Scanner) enrichThreatIntel(ctx context.Context, result *types.ScanResult) {
	s.enrichThreatIntelWithReporter(ctx, result, nil)
}

func (s *Scanner) enrichThreatIntelWithReporter(ctx context.Context, result *types.ScanResult, reporter ProgressReporter) {
	if result == nil {
		return
	}

	result.ThreatIntel = types.ThreatIntelMetadata{
		KEV:  types.SourceEnrichmentStatus{Status: types.EnrichmentNotRequested},
		EPSS: types.SourceEnrichmentStatus{Status: types.EnrichmentNotRequested},
	}

	if s.KEVEnricher == nil && s.EPSSEnricher == nil {
		emitStage(reporter, ScanEvent{
			Stage:   StageThreatIntel,
			Status:  StageSkipped,
			Message: "Threat intelligence enrichers not configured",
		})
		return
	}

	cveSet := make(map[string]struct{})
	for i := range result.Dependencies {
		for j := range result.Dependencies[i].Vulnerabilities {
			v := &result.Dependencies[i].Vulnerabilities[j]
			if cveID := canonicalCVEID(v); cveID != "" {
				cveSet[cveID] = struct{}{}
			} else {
				v.KEVStatus = types.EnrichmentNotRequested
				v.EPSSStatus = types.EnrichmentNotRequested
			}
		}
	}
	if len(cveSet) == 0 {
		emitStage(reporter, ScanEvent{
			Stage:   StageThreatIntel,
			Status:  StageSkipped,
			Message: "No CVE identifiers discovered (0 threat-intel queries needed)",
		})
		return
	}

	cveIDs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		cveIDs = append(cveIDs, id)
	}
	sort.Strings(cveIDs)

	emitStage(reporter, ScanEvent{
		Stage:   StageThreatIntel,
		Status:  StageRunning,
		Current: 0,
		Total:   intPtr(len(cveIDs)),
		Message: fmt.Sprintf("Querying CISA KEV and FIRST EPSS for %d CVE(s)", len(cveIDs)),
	})

	// Shared overall budget with independent per-source timeouts so a slow source
	// cannot starve the other source.
	budgetCtx, budgetCancel := context.WithTimeout(ctx, 10*time.Second)
	defer budgetCancel()

	var (
		wg         sync.WaitGroup
		kevMatches map[string]bool
		kevErr     error
		kevFetched time.Time
		epssScores map[string]struct {
			epss float64
			pct  float64
			date string
		}
		epssErr       error
		epssFetched   time.Time
		epssModelDate string
	)

	if s.KEVEnricher != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kevCtx, cancel := context.WithTimeout(budgetCtx, 8*time.Second)
			defer cancel()
			m, err := s.KEVEnricher.LookupKEV(kevCtx, cveIDs)
			kevFetched = time.Now().UTC()
			kevMatches = m
			kevErr = err
		}()
	}

	if s.EPSSEnricher != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			epssCtx, cancel := context.WithTimeout(budgetCtx, 8*time.Second)
			defer cancel()
			scores, err := s.EPSSEnricher.LookupEPSS(epssCtx, cveIDs)
			epssFetched = time.Now().UTC()
			epssErr = err
			if err == nil && len(scores) > 0 {
				epssScores = make(map[string]struct {
					epss float64
					pct  float64
					date string
				}, len(scores))
				for id, sc := range scores {
					epssScores[id] = struct {
						epss float64
						pct  float64
						date string
					}{epss: sc.EPSS, pct: sc.Percentile, date: sc.Date}
					if sc.Date > epssModelDate {
						epssModelDate = sc.Date
					}
				}
			}
		}()
	}

	wg.Wait()

	if s.KEVEnricher != nil {
		t := kevFetched
		if kevErr != nil {
			result.ThreatIntel.KEV = types.SourceEnrichmentStatus{
				Status:    types.EnrichmentFailed,
				FetchedAt: &t,
				Error:     kevErr.Error(),
			}
		} else {
			result.ThreatIntel.KEV = types.SourceEnrichmentStatus{
				Status:    types.EnrichmentAvailable,
				FetchedAt: &t,
			}
		}
	}

	if s.EPSSEnricher != nil {
		t := epssFetched
		if epssErr != nil {
			result.ThreatIntel.EPSS = types.SourceEnrichmentStatus{
				Status:    types.EnrichmentFailed,
				FetchedAt: &t,
				Error:     epssErr.Error(),
			}
		} else {
			result.ThreatIntel.EPSS = types.SourceEnrichmentStatus{
				Status:    types.EnrichmentAvailable,
				FetchedAt: &t,
				ModelDate: epssModelDate,
			}
		}
	}

	for i := range result.Dependencies {
		for j := range result.Dependencies[i].Vulnerabilities {
			vuln := &result.Dependencies[i].Vulnerabilities[j]
			cveID := canonicalCVEID(vuln)
			if cveID == "" {
				continue
			}

			if s.KEVEnricher != nil {
				if kevErr != nil {
					vuln.KEVStatus = types.EnrichmentFailed
				} else if kevMatches[cveID] {
					vuln.KnownExploited = true
					vuln.KEVStatus = types.EnrichmentAvailable
					vuln.Sources = appendUniqueSource(vuln.Sources, "cisa-kev")
				} else {
					vuln.KEVStatus = types.EnrichmentNotFound
				}
			} else {
				vuln.KEVStatus = types.EnrichmentNotRequested
			}

			if s.EPSSEnricher != nil {
				if epssErr != nil {
					vuln.EPSSStatus = types.EnrichmentFailed
				} else if sc, ok := epssScores[cveID]; ok {
					vuln.EPSSScore = sc.epss
					vuln.EPSSPercentile = sc.pct
					vuln.EPSSDate = sc.date
					vuln.EPSSStatus = types.EnrichmentAvailable
					vuln.Sources = appendUniqueSource(vuln.Sources, "epss")
				} else {
					vuln.EPSSStatus = types.EnrichmentNotFound
				}
			} else {
				vuln.EPSSStatus = types.EnrichmentNotRequested
			}
		}
	}

	tiStatus := StageCompleted
	var tiErr string
	if kevErr != nil && epssErr != nil {
		tiStatus = StageFailed
		tiErr = fmt.Sprintf("KEV: %v; EPSS: %v", kevErr, epssErr)
	} else if kevErr != nil {
		tiStatus = StagePartial
		tiErr = fmt.Sprintf("KEV lookup failed: %v", kevErr)
	} else if epssErr != nil {
		tiStatus = StagePartial
		tiErr = fmt.Sprintf("EPSS lookup failed: %v", epssErr)
	}
	emitStage(reporter, ScanEvent{
		Stage:   StageThreatIntel,
		Status:  tiStatus,
		Current: len(cveIDs),
		Total:   intPtr(len(cveIDs)),
		Message: fmt.Sprintf("Checked %d CVE(s) against CISA KEV (%s) and FIRST EPSS (%s)", len(cveIDs), result.ThreatIntel.KEV.Status, result.ThreatIntel.EPSS.Status),
		Error:   tiErr,
	})
}

func canonicalCVEID(v *types.Vulnerability) string {
	if cve := strings.ToUpper(strings.TrimSpace(v.CVEID)); strings.HasPrefix(cve, "CVE-") {
		return cve
	}
	if id := strings.ToUpper(strings.TrimSpace(v.ID)); strings.HasPrefix(id, "CVE-") {
		return id
	}
	return ""
}

func appendUniqueSource(sources []string, source string) []string {
	for _, existing := range sources {
		if strings.EqualFold(existing, source) {
			return sources
		}
	}
	return append(sources, source)
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
	nodeKeys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		nodeKeys = append(nodeKeys, key)
	}
	sort.Strings(nodeKeys)

	nodesToScanList := make([]*types.DependencyNode, 0, len(graph.Nodes))
	for _, key := range nodeKeys {
		node := graph.Nodes[key]
		if node.ScanStatus == types.StatusUnsupported {
			continue
		}
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
			if node.ScanError == "" {
				node.ScanError = "missing package name or version"
			}
			continue
		}
		nodesToScanList = append(nodesToScanList, node)
	}

	nodesToScan := len(nodesToScanList)
	skippedCount := 0
	for _, key := range nodeKeys {
		if graph.Nodes[key].ScanStatus == types.StatusSkipped {
			skippedCount++
		}
	}

	numWorkers := getWorkerCount()
	if reporter != nil {
		reporter.Progress(0, nodesToScan, "Starting scan...", 0)
	}
	emitStage(reporter, ScanEvent{
		Stage:   StageSCA,
		Status:  StageRunning,
		Current: 0,
		Total:   intPtr(nodesToScan),
		Queued:  nodesToScan,
		Skipped: skippedCount,
		Workers: numWorkers,
		Message: fmt.Sprintf("Scanning %d package(s) across %d worker(s)", nodesToScan, numWorkers),
	})

	var totalVulns atomic.Int32
	var processed atomic.Int32
	var activeWorkers atomic.Int32
	var failedCount atomic.Int32
	var resultMu sync.Mutex

	pool := NewWorkerPool(ctx, numWorkers, func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		act := int(activeWorkers.Add(1))
		defer activeWorkers.Add(-1)
		done := int(processed.Load())
		queued := nodesToScan - done - act
		if queued < 0 {
			queued = 0
		}
		if reporter != nil {
			reporter.Progress(done, nodesToScan, nodeKey, int(totalVulns.Load()))
		}
		emitStage(reporter, ScanEvent{
			Stage:   StageSCA,
			Status:  StageRunning,
			Current: done,
			Total:   intPtr(nodesToScan),
			Queued:  queued,
			Active:  act,
			Failed:  int(failedCount.Load()),
			Skipped: skippedCount,
			Workers: numWorkers,
			Message: "Querying " + nodeKey,
		})
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
				failedCount.Add(1)
			} else {
				res.Node.ScanStatus = types.StatusScanned
				res.Node.ScanError = ""
				res.Node.Vulnerabilities = res.Vulns
				totalVulns.Add(int32(len(res.Vulns)))

				if reporter != nil {
					dependencyPath := graph.GetVulnerablePath(res.NodeKey)
					for _, vuln := range res.Vulns {
						reporter.Vulnerability(vuln, res.NodeKey, dependencyPath)
					}
				}
			}

			current := int(processed.Add(1))
			act := int(activeWorkers.Load())
			queued := nodesToScan - current - act
			if queued < 0 {
				queued = 0
			}
			if reporter != nil {
				reporter.Progress(current, nodesToScan, res.NodeKey, int(totalVulns.Load()))
			}
			emitStage(reporter, ScanEvent{
				Stage:   StageSCA,
				Status:  StageRunning,
				Current: current,
				Total:   intPtr(nodesToScan),
				Queued:  queued,
				Active:  act,
				Failed:  int(failedCount.Load()),
				Skipped: skippedCount,
				Workers: numWorkers,
				Message: "Completed " + res.NodeKey,
			})
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

	scaStatus := StageCompleted
	if failedCount.Load() > 0 {
		scaStatus = StagePartial
	}
	emitStage(reporter, ScanEvent{
		Stage:   StageSCA,
		Status:  scaStatus,
		Current: int(processed.Load()),
		Total:   intPtr(nodesToScan),
		Queued:  0,
		Active:  0,
		Failed:  int(failedCount.Load()),
		Skipped: skippedCount,
		Workers: numWorkers,
		Message: fmt.Sprintf("Evaluated %d package(s), %d failed, %d skipped", processed.Load(), failedCount.Load(), skippedCount),
	})

	return buildScanResultFromGraph(projectPath, lockFile, lockHash, graph, lockType, skipDevDeps)
}

func buildScanResultFromGraph(projectPath, lockFile, lockHash string, graph *types.DependencyGraph, lockType lockfile.LockFileType, skipDevDeps bool) *types.ScanResult {
	nodeKeys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		nodeKeys = append(nodeKeys, key)
	}
	sort.Strings(nodeKeys)

	deps := make([]types.Dependency, 0, len(graph.Nodes))
	var coverage types.ScanCoverage
	coverage.ResolutionScope = resolutionScopeForLockType(lockType)

	for _, key := range nodeKeys {
		node := graph.Nodes[key]

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

		children := append([]string(nil), node.Children...)
		sort.Strings(children)

		dep := types.Dependency{
			Name:            node.Name,
			Version:         node.Version,
			Ecosystem:       lockType.Ecosystem(),
			Type:            node.Type,
			Direct:          node.Direct,
			Ambiguous:       node.Ambiguous,
			DependsOn:       children,
			ReleasedAt:      node.ReleasedAt,
			ScanStatus:      node.ScanStatus,
			ScanError:       node.ScanError,
			Vulnerabilities: node.Vulnerabilities,
		}
		deps = append(deps, dep)
	}

	resolution := buildResolutionEvidence(graph, lockType)

	result := &types.ScanResult{
		Version:      1,
		ProjectPath:  projectPath,
		ScannedAt:    time.Now().UTC(),
		LockFile:     lockFile,
		LockFileHash: lockHash,
		SkipDevDeps:  skipDevDeps,
		Dependencies: deps,
		Graph:        graph,
		Coverage:     coverage,
		Resolution:   resolution,
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

func resolutionScopeForLockType(lockType lockfile.LockFileType) string {
	switch lockType {
	case lockfile.PomXml:
		return "partial-pom"
	case lockfile.GoModLock:
		return "go-mod-manifest"
	case lockfile.RequirementsTxt:
		return "flat-manifest"
	case lockfile.PipfileLock, lockfile.GradleLock:
		return "flat-lockfile"
	default:
		return "graph-lockfile"
	}
}

func buildResolutionEvidence(graph *types.DependencyGraph, lockType lockfile.LockFileType) types.ResolutionEvidence {
	ev := types.ResolutionEvidence{
		InputKind:       types.InputKindLockfile,
		ResolverVersion: "1",
		Completeness:    types.ResolutionComplete,
	}

	switch lockType {
	case lockfile.PomXml:
		ev.InputKind = types.InputKindManifest
		ev.Completeness = types.ResolutionPartial
		ev.Limitations = append(ev.Limitations, "Maven pom.xml is a manifest (direct declarations and local parent POM hierarchy only; transitive dependencies require a lockfile or effective POM).")
	case lockfile.GoModLock:
		ev.InputKind = types.InputKindManifest
		ev.Completeness = types.ResolutionPartial
		ev.Limitations = append(ev.Limitations, "Go go.mod records module requirements without full Go toolchain MVS build list or parent-child edges.")
	case lockfile.RequirementsTxt:
		ev.InputKind = types.InputKindManifest
		ev.Completeness = types.ResolutionPartial
		ev.Limitations = append(ev.Limitations, "Python requirements.txt is a flat manifest without transitive dependency graph metadata.")
	case lockfile.PipfileLock, lockfile.GradleLock:
		ev.Completeness = types.ResolutionPartial
		ev.Limitations = append(ev.Limitations, "Lockfile format does not encode parent-child dependency graph edges (all packages treated as root depth).")
	}

	if graph != nil {
		keys := make([]string, 0, len(graph.Nodes))
		for k := range graph.Nodes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			node := graph.Nodes[k]
			if node.ScanStatus == types.StatusUnsupported {
				reason := node.ScanError
				if reason == "" {
					reason = "unresolved dependency version or unsupported metadata"
				}
				ev.Unresolved = append(ev.Unresolved, types.UnresolvedDependency{
					Package: node.Name,
					Reason:  reason,
				})
			}
		}
		if len(graph.Unresolved) > 0 {
			ev.Unresolved = append(ev.Unresolved, graph.Unresolved...)
			ev.Limitations = append(ev.Limitations, fmt.Sprintf("%d dependency reference(s) in the lockfile could not be matched to any resolved package version.", len(graph.Unresolved)))
		}
		if len(graph.Ambiguous) > 0 {
			ev.Ambiguous = append([]types.AmbiguousDependency(nil), graph.Ambiguous...)
			ev.Limitations = append(ev.Limitations, fmt.Sprintf("%d dependency edge(s) matched multiple candidate versions in the lockfile and were left unlinked.", len(graph.Ambiguous)))
		}
	}

	if len(ev.Unresolved) > 0 {
		ev.Completeness = types.ResolutionPartial
	} else if len(ev.Ambiguous) > 0 && ev.Completeness == types.ResolutionComplete {
		ev.Completeness = types.ResolutionAmbiguous
	}

	return ev
}

// buildGraphFromDeps constructs a DependencyGraph from flat Dependencies for lock files without native graph support.
func buildGraphFromDeps(deps *lockfile.Dependencies, ecosystem types.Ecosystem) *types.DependencyGraph {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = ecosystem

	prodNames := make([]string, 0, len(deps.Production))
	for name := range deps.Production {
		prodNames = append(prodNames, name)
	}
	sort.Strings(prodNames)
	for _, name := range prodNames {
		node := graph.AddNode(name, deps.Production[name], types.Production, true)
		graph.Root = append(graph.Root, node.Name+"@"+node.Version)
	}

	devNames := make([]string, 0, len(deps.Development))
	for name := range deps.Development {
		devNames = append(devNames, name)
	}
	sort.Strings(devNames)
	for _, name := range devNames {
		node := graph.AddNode(name, deps.Development[name], types.Development, true)
		graph.Root = append(graph.Root, node.Name+"@"+node.Version)
	}

	// Surface unresolved manifest entries (e.g. Maven BOM/parent-inherited versions) explicitly
	// as StatusUnsupported rather than silently dropping them.
	for _, name := range deps.Unresolved {
		node := graph.AddNode(name, "", types.Production, true)
		node.ScanStatus = types.StatusUnsupported
		node.ScanError = "unresolved dependency version (inherited from external parent or BOM)"
		graph.Root = append(graph.Root, node.Name+"@"+node.Version)
	}

	graph.CalculateDepths()
	return graph
}

// getWorkerCount returns the number of parallel workers from ATNP_WORKERS (falling back to
// legacy VIGIL_WORKERS when ATNP_WORKERS is unset; default 10, max 100).
func getWorkerCount() int {
	workers := os.Getenv("ATNP_WORKERS")
	if workers == "" {
		workers = os.Getenv("VIGIL_WORKERS")
	}
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
