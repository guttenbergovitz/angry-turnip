# Empirical Benchmark Results: Vigil vs Trivy

Executed on **2026-11-22** via `go run ./benchmarks/reference/cmd/compare` against the six reference fixtures in `benchmarks/reference/`.

## Methodology

1. **Canonical Normalization**: Every scanner's output is parsed from its native JSON schema and normalized to canonical `<ADVISORY_ID>|<PURL>` keys (with `GHSA-*` and `CVE-*` aliases expanded for recall matching, while `tot` reports the scanner's deduplicated finding count).
2. **Explicit Execution & Evidence Status**: Scanner execution failures are reported as `FAILED` (never conflated with `0` findings). Vigil additionally reports its `policy.EvidenceState` (`COMPLETE` vs `PARTIAL`).
3. **Ground-Truth Recall (`rec`)**: Measured against the pinned historical CVEs in each ecosystem's `expected.json`.

## Live Results

| Ecosystem | Lock File / Manifest | Vigil (`status / recall / total`) | Trivy (`status / recall / total`) | Analysis |
|-----------|----------------------|-----------------------------------|-----------------------------------|----------|
| **npm** | `package-lock.json` (v3, scoped `@babel/traverse`, transitive `qs`, dev `jest`) | `OK(COMPLETE)` — **rec 2/2**, tot **11** | `OK` — **rec 2/2**, tot **11** | **Exact 11/11 parity** and 100% recall (`CVE-2021-23337`, `CVE-2023-45133`). |
| **go** | `go.mod` (direct + indirect + `replace` directive) | `OK(COMPLETE)` — **rec 1/1**, tot **24** | `OK` — **rec 1/1**, tot **24** | **Exact 24/24 parity** and 100% recall (`CVE-2023-45288`); both honour `replace golang.org/x/net v0.17.0 => v0.18.0`. |
| **maven** | `pom.xml` (`<properties>`, `<dependencyManagement>`, `<scope>test</scope>`, 1 unresolved parent BOM version) | `OK(PARTIAL)` — **rec 1/1**, tot **21** | `OK` — **rec 1/1**, tot **25** | Both achieve 100% recall (`CVE-2021-44228`). Vigil merges 4 overlapping GHSA/CVE aliases via union-find (21 canonical findings vs 25 raw records) and **explicitly flags `PARTIAL` evidence** because `spring-boot-starter-web` lacks a resolved version. |
| **python** | `uv.lock` (transitive graph + `dev = true`) | `OK(COMPLETE)` — **rec 1/1**, tot **18** | `OK` — **rec 0/1**, tot **0** | Vigil resolves all 4 `uv.lock` packages and detects 18 canonical findings (`CVE-2021-33503`), whereas Trivy produces 0 findings on this `uv.lock` fixture. |
| **cargo** | `Cargo.lock` (v3 with transitive crate edges) | `OK(COMPLETE)` — **rec 1/1**, tot **9** | `OK` — **rec 1/1**, tot **6** | Both achieve 100% ground-truth recall (`CVE-2021-45710`); Vigil additionally surfaces 3 RustSec (`RUSTSEC-*`) advisories from OSV.dev for `smallvec@1.6.0` and `tokio@1.8.0`. |
| **composer** | `composer.lock` (`packages` + `packages-dev`) | `OK(COMPLETE)` — **rec 1/1**, tot **14** | `OK` — **rec 1/1**, tot **14** | **Exact 14/14 parity** and 100% recall (`CVE-2022-31042`). |

## Key Takeaways

1. **Exact Parity on Mature Lock Files**: On `package-lock.json`, `go.mod`, and `composer.lock`, Vigil produces the exact same finding counts (`11`, `24`, `14`) as Trivy.
2. **Superior `uv.lock` & RustSec Coverage**: Vigil natively resolves Python `uv.lock` dependency graphs (`18` findings vs `0`) and includes ecosystem-native `RUSTSEC-*` advisories from OSV.dev on `Cargo.lock`.
3. **Honest Evidence Accounting on Maven**: When a `pom.xml` contains an unresolvable external parent/BOM dependency, Vigil refuses to report `COMPLETE` coverage — it marks the scan `OK(PARTIAL)` and blocks strict CI gates rather than silently claiming a clean scan.
