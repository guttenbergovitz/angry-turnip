# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.6.1] - 2026-11-22

### Fixed

- **Full TOML Parsing & Deterministic Multi-Version Edge Resolution (`internal/lockfile`)**
  - Replaced line-by-line TOML scanning for `uv.lock`, `poetry.lock`, and `Cargo.lock` with `github.com/BurntSushi/toml`.
  - Replaced unordered map iteration in `buildPythonGraph` and `ParseCargoLockGraph` with deterministic `(name, version)` edge resolution (matching exact dependency version pins first and falling back to sorted candidate versions), eliminating arbitrary version selection when multiple versions of a package exist.
- **Explicit `ResolutionScope` & Maven Parent Version Verification (`internal/lockfile`, `internal/policy`, `internal/scan`)**
  - Added `ResolutionScope` (`full-lockfile`, `go-mod-manifest`, `partial-pom`, `flat-manifest`) to `ScanCoverage` and `EvaluationResult` with explicit `EvidenceNotes` so `EvidenceState = COMPLETE` on a manifest-only file (`pom.xml`, `go.mod`, `requirements.txt`) is never conflated with full transitive lockfile resolution.
  - Added parent `<version>` verification in `parsePomXmlWithAncestors` so local parent POMs with mismatched versions are never inherited.
- **SARIF Diagnostic Results for Incomplete / Invalid Evidence (`internal/policy/sarif.go`)**
  - Emitted explicit SARIF `results` and `rules` (`VIGIL-EVIDENCE-INVALID`, `VIGIL-EVIDENCE-UNVERIFIED`, `VIGIL-SCAN-INCOMPLETE`, `VIGIL-BASELINE-INCOMPATIBLE`) whenever evidence completeness or baseline comparability fails, ensuring `BLOCK` or `REVIEW` decisions with zero vulnerability findings are never invisible in GitHub Code Scanning.
- **Set-Intersection Benchmark Metric & Scope Documentation (`benchmarks/reference/`)**
  - Added canonical finding set-intersection (`[shared:N]`) reporting to `benchmarks/reference/cmd/compare` and refined `benchmarks/reference/RESULTS.md` to distinguish controlled fixture parity and input format support from universal scanner equivalence.

## [2.6.0] - 2026-11-22

### Added

- **Hardened Dependency Resolution across Python, Maven, and Go (`internal/lockfile`)**
  - Added `ParsePoetryLockGraph` preserving transitive `[package.dependencies]` edges, BFS depth, and Poetry 1.5+ `groups = ["dev"]` / `["test"]` classification.
  - Updated `ParseRequirementsTxt` to accept only exact pinned versions (`==` / `===`) in `Production` while recording unpinned or floating-range specifications (`>=`, `~=`, bare names) in `Unresolved` (`StatusUnsupported`).
  - Added `ParsePomXmlFile` resolving inherited `<properties>` and `<dependencyManagement>` across local multi-module Maven `<parent>` hierarchies (`<relativePath>` or `../pom.xml` up to 5 ancestor levels).
  - Updated `ParseGoModGraph` to flag local filesystem `replace` directives (without an upstream module version) as `StatusUnsupported` rather than querying OSV with a placeholder version.
- **SARIF 2.1.0 Output (`--format sarif` / `--output sarif`)**
  - Added `policy.WriteSARIF` (`internal/policy/sarif.go`) mapping canonical `FindingDecision` outcomes (`BLOCK` -> `error`, `REVIEW` -> `warning`, `ALLOW` -> `note`), `EvidenceState`, PURL, CISA KEV, FIRST EPSS (with `epss_date`), and `EffectiveScoreReason` for GitHub Code Scanning.
- **Empirical Live Benchmark Report (`benchmarks/reference/RESULTS.md`)**
  - Executed and documented live multi-ecosystem comparison against Trivy across `npm`, `go`, `maven`, `python`, `cargo`, and `composer` (100% ground-truth recall across all 6 ecosystems; exact finding count parity on `npm`, `go`, and `composer`; full `uv.lock` and `PARTIAL` Maven BOM accounting).

### Fixed

- **Clean Machine-Readable Stdout in `vigil scan --no-tui --output <fmt>`**
  - Suppressed the human `"Scanning..."` banner on `stdout` when `--output` is set so machine-readable JSON, SARIF, CycloneDX, SPDX, CSV, and Markdown streams are never corrupted.

## [2.5.0] - 2026-11-22

### Added

- **Normalized Benchmark Runner & Frozen OSV Snapshot Testing (`benchmarks/reference/`)**
  - Added `benchmarks/reference/cmd/compare` normalizing Vigil, OSV-Scanner, Trivy, and Grype outputs to canonical `(advisoryID, PURL)` pairs, tracking execution status (`OK`, `FAILED`, `N/A`) independently of finding counts, and computing recall against `expected.json`.
  - Added `TestReferenceAdvisoryMatchingFromFrozenOSVSnapshot` testing `osv.Client` parsing, Maven PURL formatting, `aliases[]`, `severity[]` CVSS vectors, and `database_specific.severity` against a frozen OSV API response independently of `expected.json`.
- **EPSS Model Date Provenance**
  - Recorded FIRST EPSS upstream `date` (`epss_date` on `Finding` / `Vulnerability` and `model_date` on `SourceEnrichmentStatus`) separately from `fetched_at`, and surfaced it in `vigil explain`.

### Fixed

- **Prevented Silent `ALLOW` on Unverified Threat Intelligence & Incompatible Baselines**
  - When a policy rule relies on CISA KEV or FIRST EPSS and the lookup status for a `CVE-*` finding is `failed` or `not_requested`, `policy.Evaluate` now defaults to `DecisionReview` (unless `on_threat_intel_unavailable` is explicitly set to `ALLOW` or `BLOCK`), never treating missing or unrequested queries as negative proof.
  - When `CompareBaselineScope` detects an incompatible scan configuration (`ConfigFingerprint` mismatch), `policy.Evaluate` rejects the baseline for delta classification (evaluating all findings as new so `new_only` rules cannot be bypassed) and escalates `OverallDecision` to at least `DecisionReview`.
- **OSV Client Maven PURL & Schema Parsing (`internal/osv`)**
  - Fixed Maven PURL construction in `osv.Client.QueryWithEcosystemContext` (`pkg:maven/groupId/artifactId@version`), added `aliases[]` CVE extraction, `severity[]` CVSS vector extraction, and `database_specific.severity` fallback.
- **TUI Lifecycle, Canonical Findings, Secret Masking & Scoped Local Hide (`internal/ui`, `internal/cli`)**
  - Executed Secrets, IaC, Licenses (`license.AnalyzeResultLicenses`), and canonical `policy.Evaluate` inside the scan workflow before sending `ui.DoneMsg`, ensuring all TUI tabs and policy decisions are populated before entering explorer mode.
  - Built the TUI Vulnerabilities view from canonical `policy.EvaluationResult` decisions (displaying `Decision`, `EvidenceState`, `Coverage`, and `KEV`/`EPSS` status in the header).
  - Masked secret values by default (`secrets.MaskSecret`) in both CLI `--secrets` output and the TUI Secrets tab, with explicit `[s]` toggle to reveal/mask in TUI.
  - Replaced global `Mark Fixed` with scoped `Hide locally` keyed by canonical `Finding.Key` (`ID|PURL`), added `[v]` to view/unhide hidden items and `[X]` to restore all, protected group headers (`IsGroupHeader`) from hide/copy actions, included `unknown` in severity grouping, sorted package groups deterministically, ran file exports asynchronously via `tea.Cmd`, removed redundant `ticker()` spawns, added `cancelFunc` invocation on `Ctrl+C`, and switched table cell truncation to UTF-8 rune boundaries.

## [2.4.0] - 2026-11-22

### Added

- **Threat Intelligence Provenance & Parallel Execution**
  - Added explicit per-source `EnrichmentStatus` (`available`, `not_found`, `failed`, `not_requested`), fetch timestamps, and error reporting on `ScanResult.ThreatIntel` and per-finding `kev_status` / `epss_status` so lookup failures are never conflated with negative results.
  - Executed CISA KEV and FIRST EPSS lookups in parallel with independent per-source timeouts (8s each within a shared 10s budget).
  - Surfaced failed threat-intelligence lookups in `EvaluationResult.EvidenceNotes`, `Finding.MissingEvidence`, and `vigil explain`.
- **Policy Engine Integration for CISA KEV & FIRST EPSS**
  - Added `known_exploited` and `min_epss` (strictly validated `0.0–1.0`) rule conditions to `policy.Rule` and `on_threat_intel_unavailable` (`ALLOW` / `REVIEW` / `BLOCK`) to `policy.Policy`.
  - Updated `DefaultPolicy()` to block actively exploited production vulnerabilities (`threat-intel/kev-block`) regardless of severity, while keeping basic SCA resilient to transient threat-intelligence API failures.
- **Baseline Scope Comparability**
  - Separated `ScanScope.ConfigFingerprint` (lock file, resolution model version, `skip_dev_deps`) from `ScanScope.ComponentsFingerprint` (sorted `ScannedPURLs`).
  - Added `CompareBaselineScope` and `EvaluationResult.BaselineScopeCompatible` so configuration mismatches emit explicit warnings while routine dependency updates remain comparable.
- **Source-Specific Evidence Preservation**
  - Preserved per-source advisory records (`SourceEvidence`) through union-find deduplication and added `EffectiveScoreReason` explaining which upstream source(s) supplied the effective severity and CVSS score.
- **Reference Fixtures & Scanner Comparison Benchmark (`benchmarks/reference/`)**
  - Added six ground-truth reference fixtures (`npm`, `go`, `maven`, `python`, `cargo`, `composer`) with `expected.json` manifests verifying 100% component PURL precision/recall, `ScanStatus`, `EvidenceState`, and historical CVE findings offline via `go test ./benchmarks/reference/...`.
  - Added `benchmarks/reference/compare.sh` for side-by-side live comparison against keyless public scanners (OSV-Scanner, Trivy, Grype).

## [2.3.0] - 2026-11-22

### Added

- **Keyless Threat Intelligence Enrichment (CISA KEV & FIRST EPSS)**
  - Added `internal/kev` client querying the public CISA Known Exploited Vulnerabilities (KEV) catalogue (fetched at most once per scan and cached in memory) to flag actively exploited CVEs (`known_exploited: true`, source `cisa-kev`).
  - Added `internal/epss` client querying the public FIRST EPSS API in batches (up to 50 CVEs per request) to attach 30-day exploitation probability and percentile rank (`epss_score`, `epss_percentile`, source `epss`).
  - Executed as a single best-effort post-scan pass that makes zero network requests on clean scans and never degrades `ScanCoverage` on network failure.
  - Propagated KEV and EPSS fields through `policy.Finding` deduplication and surfaced them in `vigil explain`.
- **Free API Key & Public Source Documentation**
  - Updated `README.md` and `documentation/user-guide/commands.md` to clearly document keyless operation (OSV.dev, public GHSA REST, CISA KEV, FIRST EPSS), free key acquisition links (`NVD_API_KEY`, `GITHUB_TOKEN`), required scopes, and rate limits.

### Fixed

- **Cross-checked `ScanCoverage` against actual `ScanResult.Dependencies`**
  - `policy.ValidateEvidence` now verifies that every dependency has a valid `ScanStatus`, rejects duplicate component PURLs, and rejects mismatches between reported coverage counters and actual dependency statuses.
  - Scans where all dependencies are excluded (`ScannedPackages == 0 && SkippedPackages == TotalPackages`) now yield `EvidenceUnverified` rather than `EvidenceComplete`.
- **Transitive, permutation-invariant advisory deduplication**
  - Replaced greedy single-match deduplication with union-find connected-component merging per PURL in `policy.BuildFindings`, guaranteeing identical canonical findings regardless of advisory record order.
  - Recomputed all derived fields (`ExploitType`, `Exploitability`, `MissingEvidence`) from canonical merged vulnerability evidence.
- **Reproducible baseline scope identity**
  - Extended `policy.ScanScope` with `ResolutionModelVersion`, sorted `ScannedPURLs` manifest, and SHA-256 `ScopeFingerprint`.
- **Unified CI JSON output**
  - `vigil ci --format json` now consistently emits `policy.EvaluationResult` in both threshold mode and `--policy` mode.
- **Property tests & documentation accuracy**
  - Added property tests for coverage consistency, permutation invariance (all 6 permutations of transitively linked advisories), merge consistency, and scope reproducibility.
  - Updated `README.md` CVSS enrichment description and circular dependency safety note.

## [2.2.2] - 2026-11-22

### Fixed

- **Enforced `ScanCoverage` invariants and blocked `EvidenceUnverified`**
  - `policy.ValidateEvidence` now validates coverage counter consistency (`scanned + failed + skipped + unsupported == total`, non-negative counts, and consistency with `Dependencies`), returning `EvidenceInvalid` on mismatches.
  - `policy.Evaluate` and `vigil ci` now block (`DecisionBlock`, exit code `2`) when `EvidenceState` is `UNVERIFIED` or `INVALID`, ensuring empty or corrupted scans never pass as `ALLOW`.
  - Separated intentional scope exclusions (`ScopeExclusions` / `SkippedPackages`, e.g. `--skip-devdeps`) from coverage failures (`FailedPackages`, `UnsupportedPackages`).
- **Required explicit scope on policy exceptions**
  - `policy.ParsePolicy` now requires every exception to declare either `package` + (`version` or `all_versions: true`) or explicit `global: true`, preventing accidental wildcard suppressions.
  - Added `strict_exceptions: true` policy option requiring `approval_id` on every exception.
- **Recorded scan scope in baseline snapshots**
  - Added `ScanScope` (`total_packages`, `scanned_packages`, `skipped_packages`) to `policy.Baseline` and routed `ValidateForBaseline` through `ValidateEvidence`.
- **Deduplicated overlapping advisory findings**
  - Updated `policy.BuildFindings` to merge duplicate vulnerability records for the same component PURL that share any advisory identifier or alias (`GHSA-*` / `CVE-*`), preserving the `CVE-*` primary ID, highest severity/CVSS, and union of sources.
- **Eliminated duplicate CI evaluation pass**
  - Updated `cli.CI` to execute `policy.Evaluate` exactly once and share the resulting `EvaluationResult` across output rendering and exit code determination.

## [2.2.1] - 2026-11-22

### Fixed

- **Blocked incomplete scans when `UnsupportedPackages > 0`**
  - Both `policy.Evaluate` and `vigil ci` now enforce `--fail-on-unsupported` (default: `true`) alongside `--fail-on-scan-error`, preventing unresolved Maven or unsupported dependencies from silently producing a passing CI gate.
- **Separated `EvidenceState` from `Decision`**
  - Added `EvidenceState` (`COMPLETE`, `PARTIAL`, `UNVERIFIED`, `INVALID`) and `EvidenceNotes` to `policy.EvaluationResult` so evidence completeness is always surfaced independently from `ALLOW` / `REVIEW` / `BLOCK`.
- **Hardened policy exceptions and default policy semantics**
  - Extended `policy.Exception` with scope constraints (`package`, `version`, `ecosystem`, `max_severity`, `approval_id`) and explicit `AcceptedRisk` marking (formally accepted risk is never presented as proof of safety and never overrides incomplete scans).
  - Updated `DefaultPolicy()` so previously observed `HIGH` vulnerabilities in production remain subject to `REVIEW` unless formally accepted via an active exception.
- **Strict YAML policy validation**
  - Enabled `yaml.Decoder.KnownFields(true)` in `policy.ParsePolicy` and added validation for `version: 1`, non-empty `rules`, `min_cvss` range (`0.0–10.0`), contradictory severity bounds, and required exception metadata.
- **Unified CI evaluation engine**
  - Routed both CLI threshold mode (`--fail-on` / `--fail-on-cvss`) and `--policy` mode through `internal/policy` via `PolicyFromThresholds`.
- **PURL-qualified finding keys, safe `vigil baseline`, and `not_observed` delta state**
  - Updated `policy.Finding.Key` to `<advisory-id>|<purl>` with alias matching across `GHSA-*` and `CVE-*`.
  - Updated `vigil baseline` to require a fresh, hash-verified, and complete scan (`FailedPackages == 0 && UnsupportedPackages == 0`).
  - Updated `policy.ComputeDelta` to classify missing findings from unscanned/failed/unsupported packages as `NotObserved` rather than `Resolved`.
- **Fixed CLI flag ordering and cache freshness warnings**
  - Added flag reordering for `vigil explain`, `vigil baseline`, and `vigil ci` so flags work both before and after positional arguments.
  - Added cache staleness, hash-mismatch, and incomplete-coverage warnings to `vigil explain`.
- **Atomic cache persistence**
  - Updated `lockfile.SaveCache` to write via a temporary file + `fsync` + `os.Rename`.
- **Added negative invariant regression tests**
  - Added dedicated tests covering all six correctness invariants (unsupported packages, incomplete delta `NotObserved`, scoped exception boundaries, strict YAML rejection, GHSA/CVE alias stability, and byte-for-byte deterministic evaluation).

## [2.2.0] - 2026-11-22

### Added

- **Canonical Finding Model (`internal/policy`)**
  - Added `policy.Finding` normalising vulnerability identity (CVE + aliases), advisory provenance, dependency scope, evidence-based exploitability, and an explicit `MissingEvidence` list (such as call-graph reachability and runtime deployment exposure).
- **Baseline & Delta Analysis (`vigil baseline`)**
  - Added `vigil baseline [path] [--output <file>]` to generate deterministic `.vigil.baseline.json` snapshots and `policy.ComputeDelta` to classify findings as new, existing, or resolved.
- **Declarative Policy as Code (`--policy`)**
  - Added typed YAML policy evaluation (`ALLOW`, `REVIEW`, `BLOCK`) with `min_severity`, `match_severity`, `min_cvss`, `production_only`, and `new_only` rules.
  - Added time-bounded, owned exceptions (`id`, `package`, `owner`, `reason`, `expires_at`) with automatic expiry enforcement and audit reasoning.
  - Integrated `--policy` and `--baseline` flags into `vigil ci`.
- **Explainable Release Gate (`vigil explain <vuln-id>`)**
  - Added `vigil explain` command (`text` and `json` output) detailing the decision, matched rule, step-by-step reasoning, and missing evidence for any vulnerability.
- **Architecture Decision Record**
  - Added [ADR 013](documentation/adr/013-explainable-policy-decisions.md) documenting the canonical finding model, baseline delta, and policy-as-code boundary.

## [2.1.0] - 2026-11-22

### Added

- **Dependency-graph SBOM relationships and deterministic output**
  - CycloneDX v1.5 exports now include `bom-ref` identifiers and a full `dependencies` relationship graph (reconstructed from `ScanResult.Dependencies[].DependsOn` even when exporting from `.vigil.cache`).
  - SPDX v2.3 exports now include root application package entries and `DESCRIBES` / `DEPENDS_ON` relationships.
  - Added deterministic alphabetical ordering for components, packages, and dependency edges across SBOM and scan results.
- **Orchestrator dependency injection and global NVD rate limiter**
  - Introduced `scan.Scanner` with narrow consumer-side interfaces (`VulnerabilitySource`, `CVEEnricher`, `GHSAEnricher`, `ReleaseDateFetcher`) and `scan.RateLimiter` to coordinate NVD requests globally across concurrent workers.
- **GitHub Actions CI workflow**
  - Added `.github/workflows/ci.yml` running `go vet ./...`, `go test -short -race ./...`, and `go build ./cmd/vigil` on Go 1.27.

### Changed

- **Improved Maven `pom.xml` resolution and transparency**
  - Added support for local `<dependencyManagement>` and `<parent>` / `${project.version}` / `${project.groupId}` property resolution.
  - Recorded dependencies with externally inherited versions (external parent POM or BOM) in `Dependencies.Unresolved` and surfaced them as `StatusUnsupported` in `ScanCoverage` instead of silently skipping them.
- **Hardened remote git repository cloning**
  - Replaced URL token injection with `GIT_CONFIG_*` `extraheader` environment variables, `GIT_TERMINAL_PROMPT=0`, `exec.CommandContext` timeout enforcement, and secret redaction in error output.

### Fixed

- **Fixed SBOM specification compliance bugs**
  - Generated valid RFC 4122 UUID v4 `serialNumber` values for CycloneDX instead of `urn:uuid:vigil-<timestamp>`.
  - Used dynamic `version.Get()` instead of hardcoded `1.1.0` in SBOM tool metadata.
  - Added Maven PURL support (`pkg:maven/<groupId>/<artifactId>@<version>`) in `buildPurl`.
  - Appended deterministic SHA-256 hash suffixes to SPDX package identifiers to prevent `SPDXID` collisions.
- **Preserved `Unknown` severity across OSV, NVD, and GitHub clients**
  - Stopped defaulting missing upstream severity fields to `Medium` in `internal/osv`, `internal/nvd`, and `internal/github`.

## [2.0.0] - 2026-11-22

### Breaking Changes

- **Fresh scans and fail-on-scan-error by default in `vigil ci`**
  - `vigil ci` now executes a fresh vulnerability scan by default instead of trusting `.vigil.cache` without verifying lock file changes or freshness.
  - Added `--fail-on-scan-error` (default: `true`) so incomplete scans with API lookup failures fail the CI gate (exit code `2`) rather than passing silently.
  - Added opt-in `--use-cache` with strict SHA-256 lock file hash verification and `--max-cache-age` expiry enforcement (default: `24h`).
- **Evidence-based runtime exploitability assessment**
  - Replaced categorical `yes` / `no` / `conditional` exploitability values with `potentially_exploitable`, `unknown`, and `confirmed_not_affected`, accompanied by confidence level and explicit rationale.
- **Removed temporal vulnerability filtering from security decisions**
  - Stopped discarding vulnerabilities published before a package release date, eliminating silent false negatives when subsequent releases do not patch an earlier disclosure. Dates are retained solely as informational metadata via `ComputeTemporalMetadata`.
- **Corrected Go `// indirect` dependency classification**
  - Replaced line-by-line `go.mod` parsing with `golang.org/x/mod/modfile` (honouring `replace` and `exclude` directives).
  - Separated `Direct`/`Indirect` from `Production`/`Development`: Go `// indirect` modules are now classified as `Production` transitive dependencies so `--skip-devdeps` never excludes runtime modules.

### Added

- **Explicit per-package scan status and coverage reporting**
  - Added `PackageScanStatus` (`scanned`, `failed`, `skipped`, `unsupported`) and `ScanCoverage` to `types.ScanResult`.
  - Reports (`table`, `text`, `security`) and CLI summaries now surface incomplete scan warnings when vulnerability lookups fail.
- **`types.Unknown` severity level**
  - Added `Unknown` severity (`"unknown"`) so vulnerabilities without severity or CVSS data are tracked explicitly in `UnknownVulns` instead of being miscounted as `Low` or assigned fabricated CVSS scores.
- **Testable CLI exit codes**
  - Replaced direct `os.Exit()` calls inside `internal/cli` with typed `cli.ExitError` handled centrally in `cmd/vigil/main.go`.

### Fixed

- **Fixed lexicographical severity comparison bug in recommendations**
  - Replaced `severity >= types.Medium` string comparison (where `"high" >= "medium"` evaluated to `false`) with `severity.HigherOrEqualThan(types.Medium)` in `internal/report/recommendations.go`.
- **Fixed TUI/report vulnerability mismatch**
  - Emitted `reporter.Vulnerability()` events only after final vulnerability processing so TUI live output matches the final `ScanResult`.
- **Updated documentation and Go version requirement**
  - Updated `README.md` (`Go 1.27+`), `documentation/user-guide/commands.md`, and `documentation/user-guide/reports.md` to reflect actual guarantees and en-GB terminology.

## [1.6.0] - 2026-11-21

### Fixed

- **Fix hjkl vim navigation conflict**
  - Added `h` (vim left) for previous pane navigation
  - Added `l` (vim right) for next pane navigation
  - No conflict with filter shortcuts: C/H/M/L use capitals, h/l use lowercase
- **Fix quit hang during scan**
  - Check context cancellation after TUI exits
  - Wait for scan goroutine to finish before exit
  - Clean shutdown when user presses `q` during scan
- **Add help command**
  - Press `?` to show keyboard shortcuts modal
  - Organized by category: Navigation, Tabs, Filtering, Actions, Other
  - Close with `?`, `q`, or `Esc`

## [1.5.4] - 2026-07-27

### Fixed

- **Initialize Column Widths in `NewModel()` & Auto-Sync Table Layout**
  - Executed `recalculateViewports()` directly inside `NewModel()` so column widths (`tableReasonColWidth`, `tableTargetColWidth`, `tableIDColWidth`) are initialized immediately upon TUI startup.
  - Automatically triggered `updateTableLayout()` inside `recalculateViewports()` so table rows are re-generated for current terminal dimensions instantly without needing window zoom resize workarounds.

## [1.5.2] - 2026-07-27

### Fixed

- **Subtract 5-Column Cell Padding Margins in Table Column Width Calculations**
  - Subtracted 18 characters from `availWidth` for 5-column table widths (`tableInnerWidth := availWidth - 18`) to account for bubbles/table internal cell padding spaces.
  - Completely eliminated any row line-wrapping and header underline overflow in Box 1 full-width table.

## [1.5.1] - 2026-07-27

### Fixed

- **Reset Item Selection and Table Cursor on Tab Navigation**
  - Reset `selectedIdx = 0` and table cursor to position `0` whenever switching tabs (`[1-5]`).
  - Automatically populate detailed inspection, reason why flagged, and dependency tree path for item #0 immediately upon switching tabs.

## [1.5.0] - 2026-07-27

### Added

- **Full-Width Top Table & 3-Column Bottom Pane Layout Architecture**
  - **Top Section (Full-Width Box 1)**: Rich 5-column table (`DOMAIN`, `SEVERITY`, `TARGET / PACKAGE`, `ID / RULE`, `REASON SUMMARY`) spanning 100% of body width.
  - **Bottom Section (3 Side-by-Side Columns)**:
    - `💡 [2] Reason Why Flagged` (Width: 25%) - Word-wrapped reason for active item.
    - `󰈔 [3] Detailed Inspection` (Width: 50%) - Complete CVSS score & vector, context, and remediation.
    - `󰒍 [4] Dependency Tree Path` (Width: 25%) - Dependency tree graph path.

## [1.4.7] - 2026-07-27

### Fixed

- **Optimize Column Width Ratios & Add Row String Truncation in Box 1 Table**
  - Reallocated Box 1 table column ratios (`SEVERITY`: 10, `TARGET / PACKAGE`: 40%, `ID / RULE`: 60%) so long identifiers (e.g. `GHSA-m99w-x7hq-7vfj` or `CVE-2026-44577`) get generous width and never get pushed to a second line.
  - Added strict string truncation (`...`) for package and ID strings to ensure every row in Box 1 strictly occupies 1 single line with zero row-wrapping.

## [1.4.6] - 2026-07-27

### Fixed

- **Subtract Cell Padding Margins in Table Column Width Calculations**
  - Accounted for internal cell padding added by `charmbracelet/bubbles/table` (`-10` in grid views, `-12` in scanning view).
  - Ensured table horizontal rule lines `─────` fit strictly within box inner width, completely eliminating `│────│` and `│──` line-wrapping visual artifacts.

## [1.4.5] - 2026-07-27

### Fixed

- **Simplify Box 1 Table to 3 Wide Columns (`SEVERITY`, `TARGET / PACKAGE`, `ID / RULE`)**
  - Removed redundant `REASON` column from Box 1 table, since full word-wrapped reasons are rendered in adjacent Box 2 (`💡 Reason Why Flagged`).
  - Allocated 100% of Box 1 width to `SEVERITY`, `TARGET / PACKAGE`, and `ID / RULE` columns, completely eliminating any row or line wrapping visual bugs.

## [1.4.4] - 2026-07-27

### Fixed

- **Boxed Fullscreen DevSecOps Scanning State**
  - Render scanning progress view (`StateScanning`) in a clean, pixel-perfect boxed panel spanning full screen.
  - Dynamically calculate scanning stream table column widths to eliminate any terminal line-wrapping during live scan execution.

## [1.4.3] - 2026-07-27

### Fixed

- **Fix Table Column Width & Underline Line Wrapping Visual Bug**
  - Dynamically calculate table column widths (`SEVERITY`, `TARGET`, `ID / RULE`, `REASON`) fitting `leftWidth` exactly.
  - Automatically truncate reason summary to fit allocated column width, completely eliminating table header underline line wrapping.

## [1.4.2] - 2026-07-27

### Fixed

- **Fix Fullscreen Layout Clipping & Sticky Top Header Toolbar**
  - Adjusted grid dimension calculations (`availWidth = m.width - 2`, `bodyHeight = m.height - 4`) so horizontal wrapping never occurs, ensuring top header toolbar is always visible.
  - Ensured scanning progress view (`StateScanning`) renders in fullscreen AltScreen mode from launch.

## [1.4.1] - 2026-07-27

### Added

- **Lazygit & Bottom (`btm`) Style Multi-Pane Grid Dashboard**
  - 4-Pane Grid Layout: `[1] Security Findings Table`, `[2] Reason Why Flagged`, `[3] Dependency Tree Path`, `[4] Detailed Inspection`
  - Active Pane Focus cycling (`[Tab]` / `[Shift+Tab]`) with highlighted borders
  - Expandable/Collapsible Window Maximization (`[w]` or `[f]`) to maximize focused pane to 100% full screen
  - Dynamic Terminal Window Resize & Automatic Word Wrapping matching exact terminal dimensions (`m.width`, `m.height`)

## [1.4.0] - 2026-07-27

### Added

- **Fullscreen DevSecOps Dashboard TUI** (ADR 011)
  - Fullscreen Tabbed Dashboard Navigation (`[1] Vulns`, `[2] Secrets`, `[3] IaC Security`, `[4] Licenses`, `[5] Dep Graph`)
  - Interactive Grouping Engine (`[g]` for Flat View, Group by Package, Group by Severity)
  - Explicit **"Reason Why Flagged"** justification display in Deep Inspector view
  - Interactive **Export Modal (`[e]`)** supporting JSON, CSV, Markdown, CycloneDX v1.5, and SPDX v2.3 export formats directly from TUI
  - Modern Neovim / Nerd Fonts icon aesthetic (no standard emojis)

## [1.3.0] - 2026-07-27

### Added

- **Java Ecosystem Support (Maven & Gradle)** (ADR 010)
  - Added support for Maven `pom.xml` dependency parsing with property `${property.name}` resolution
  - Added support for Gradle `gradle.lockfile` dependency resolution
  - Added `EcosystemMaven` (`"Maven"`) with `pkg:maven/{groupId}/{artifactId}@{version}` PURL mapping

## [1.2.0] - 2026-07-27

### Added

- **Full-Spectrum Security & SBOM Engine** (ADR 009)
  - **Secret Scanning (`--secrets`)**: Pattern matching engine with Shannon entropy calculation (>4.5) to detect AWS keys, GitHub tokens, Slack webhooks, SSH keys, JWT tokens, and DB connection credentials with masked output
  - **Software Bill of Materials (SBOM)**: Export standard **CycloneDX v1.5 JSON** (`--format cyclonedx`) and **SPDX v2.3 JSON** (`--format spdx`) formats
  - **License Compliance**: Categorization of package licenses into Permissive (MIT, Apache, BSD) vs Copyleft/restrictive (GPL, AGPL, LGPL, MPL) risk profiles
  - **Container & IaC Security**: Security linter for `Dockerfile` (root user, unpinned base images, secrets in ENV) and `.github/workflows/*.yml` (unpinned actions, dangerous `pull_request_target` triggers)

## [1.1.0] - 2026-07-27

### Added

- **Multi-Ecosystem Scanning Support** (ADR 008)
  - Added support for **Python**: `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`
  - Added support for **Rust**: `Cargo.lock`
  - Added support for **PHP**: `composer.lock`
  - Added support for **Go**: `go.mod`
  - Added `types.Ecosystem` abstraction (`npm`, `PyPI`, `Cargo`, `Packagist`, `Go`)
  - Integrated ecosystem-specific PURL queries for OSV API (`pkg:pypi/...`, `pkg:cargo/...`, `pkg:composer/...`, `pkg:golang/...`)
  - Added `--lockfile` CLI flag to explicitly override lockfile selection
- **Multi-Ecosystem Architecture**
  - Priority lockfile auto-detection strategy
- **Containerization & Nix Flake support** (ADR 003)
  - Multi-stage `Dockerfile` for minimal Alpine-based runtime (~20MB)
  - `flake.nix` with hermetic Go builds, development shell, and `nix run` support
  - Comprehensive Taskfile automation for Docker (`docker-build`, `docker-run`, `docker-scan`, `docker-push`, `docker-clean`)
  - Comprehensive Taskfile automation for Nix (`nix-build`, `nix-run`, `nix-scan`, `nix-shell`, `nix-check`)

### Changed

- Replaced Makefile with Taskfile for build automation
  - Uses go-task/task for cross-platform build system
  - Native host architecture detection
  - Cleaner YAML syntax
  - Same functionality (build, install, test, clean, version)

## [1.0.0] - 2026-07-27

### Added

- **Remote repository scanning** - Scan GitHub, Bitbucket, and other git repositories directly without manual cloning
  - Support for HTTPS, HTTP, SSH, and git@ URL formats
  - Automatic shallow clone (`--depth 1`) to temp directory
  - GITHUB_TOKEN environment variable support for private repositories
  - SSH key support via system git configuration
  - Automatic cleanup of temp directories on success or failure
- **Temporal false positive filtering** - Eliminates 30-40% of false positives by filtering vulnerabilities published before package release dates
  - npm registry integration to fetch package release dates
  - Conservative filtering approach (includes vulnerabilities when dates unavailable)
  - Reduces noise in security reports significantly
- **Full dependency chain tracking** - Complete transitive dependency paths for all lock file types
  - npm package-lock.json now shows full dependency graphs with parent→child relationships
  - Yarn lock files now parse dependencies and build complete graphs
  - All lock file formats (npm, Yarn, pnpm) provide identical path visibility
  - GetVulnerablePath works consistently across all package managers
- **Comprehensive documentation** - Well-structured documentation in ./documentation
  - Getting Started guides (installation, quick start, examples)
  - User Guide (commands reference, reports interpretation, troubleshooting)
  - Architecture documentation (overview, components, data flow)
  - Development guides (setup, contributing, testing)

### Changed

- Refactored codebase to remove dead code and improve maintainability
  - Removed unused config module (265 lines)
  - Centralized severity mapping and ranking logic
  - Extracted CVSS utility functions to types package
  - Removed 4 unused graph methods
- Updated lock file parsing to use graph parsers for all formats
  - npm and Yarn parsers now build full dependency graphs
  - Consistent graph structure across all lock file types
- Improved report formats to show dependency chains for all lock file types

### Fixed

- Dependency paths now work for npm and Yarn (previously only pnpm)
- Temporal filtering prevents reporting of vulnerabilities that predate package releases

### Removed

- Deleted entire internal/config module (unused)
- Removed unused graph traversal methods
- Cleaned up duplicate severity mapping code

## [0.1.0] - Initial development

### Added

- Initial vulnerability scanning for JavaScript/TypeScript projects
- Support for npm, Yarn, and pnpm lock files
- Multi-source CVSS enrichment (OSV, NVD, GitHub Security Advisories)
- Interactive TUI with real-time progress
- Multiple report formats (table, security, text, CSV, markdown, JSON)
- Intelligent risk assessment with exploit classification
- Release gate recommendations
- CI/CD integration with configurable failure thresholds

[Unreleased]: https://github.com/guttenbergovitz/vigil-cli/compare/v2.2.3...HEAD
[2.2.3]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.2.3
[2.2.2]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.2.2
[2.2.1]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.2.1
[2.2.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.2.0
[2.1.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.1.0
[2.0.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v2.0.0
[1.6.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v1.6.0
[1.1.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v1.0.0
