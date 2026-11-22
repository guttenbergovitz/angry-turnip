# Reference Fixtures & Scanner Correctness Benchmark

This directory contains independently verified reference fixtures across all six ecosystems supported by Vigil (`npm`, `go`, `maven`, `python`, `cargo`, `composer`).

## Structure

Each subdirectory contains:
- A realistic lock file or manifest exercising non-trivial resolution cases (scoped packages, transitive edges, dev dependencies, Go `replace` directives, Maven `<properties>` + `<dependencyManagement>` + unresolved parent BOM versions).
- `expected.json`: ground-truth manifest specifying:
  - exact expected component PURLs (`precision` and `recall` = 100%),
  - expected `type` (`production` / `development`), `direct` flag, and `scan_status` (`scanned` / `unsupported`),
  - expected `EvidenceState` (`COMPLETE` or `PARTIAL`),
  - known historical CVEs expected for vulnerable pinned versions.

## Running Offline Ground-Truth Verification

Runs without network access as part of standard Go testing. Includes two independent suites:
1. `TestReferenceFixturesResolutionAndCoverage`: verifies 100% PURL precision/recall, `direct`/`type` classification, `ScanStatus`, and `EvidenceState` across all six ecosystems.
2. `TestReferenceAdvisoryMatchingFromFrozenOSVSnapshot`: verifies `osv.Client` response parsing, Maven PURL construction, `aliases[]`, `severity[]` CVSS vectors, and `database_specific.severity` against a frozen OSV API payload independently of `expected.json`.

```bash
go test -v ./benchmarks/reference/...
```

## Running Live Scanner Comparison (Vigil vs OSV-Scanner, Trivy, Grype)

Uses `benchmarks/reference/cmd/compare` to normalize each scanner's output to canonical `(advisoryID, PURL)` pairs, separate execution status (`OK` / `FAILED` / `N/A`) from finding counts, and compute recall against `expected.json`:

```bash
bash benchmarks/reference/compare.sh
```
