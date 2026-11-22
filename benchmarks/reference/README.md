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

Runs without network access as part of standard Go testing:

```bash
go test -v ./benchmarks/reference/...
```

## Running Live Scanner Comparison (Vigil vs OSV-Scanner, Trivy, Grype)

Requires network access and any combination of `osv-scanner`, `trivy`, or `grype` installed on `PATH` (all keyless):

```bash
bash benchmarks/reference/compare.sh
```
