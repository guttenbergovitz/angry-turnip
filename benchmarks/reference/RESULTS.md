# Reference Fixture Benchmark Results: Angry Turnip vs Trivy

Executed on **2026-11-22** via `go run ./benchmarks/reference/cmd/compare` against the six controlled reference fixtures in `benchmarks/reference/`.

## Scope & Methodology

1. **Controlled Reference Fixtures (Not Universal Equivalence)**: These six fixtures are small, deterministic reference manifests designed to verify PURL construction, alias normalization, evidence accounting, and known historical CVE recall across all supported ecosystems. Matching counts on a controlled fixture do not imply universal equivalence across arbitrary real-world repositories.
2. **Canonical Set Normalization**: Every scanner's output is parsed from its native JSON schema and normalized to canonical `<ADVISORY_ID>|<PURL>` keys (with `GHSA-*` and `CVE-*` aliases expanded for recall and set-intersection matching, while `tot` reports the scanner's deduplicated finding count).
3. **Labelled-Case Precision (`lbl-prec`) & Unlabelled Findings (`unlbl`)**:
   - `rec` (Recall) measures `TP / (TP + FN)` against `known_historical_cves`.
   - `lbl-prec` (Labelled-Case Precision) measures `TP / (TP + FP)` specifically over the labelled positive (`known_historical_cves`) and negative (`verified_negative_cves`) ground-truth controls.
   - `unlbl` reports the count of additional findings returned by a scanner that are outside the small labelled ground-truth set (`tot - TP - FP`), ensuring unverified extra findings are never conflated with full-corpus precision.
4. **`EvidenceState` vs `ResolutionEvidence`**:
   - `EvidenceState = COMPLETE` means 100% of dependencies resolved within the input artifact were queried without error.
   - `Resolution.Completeness` (`complete`, `partial`, `ambiguous`) independently tracks graph resolution quality and is enforced by `on_resolution_incomplete` (`REVIEW` by default when ambiguous or unresolved edges exist).

## Live Results on Reference Fixtures

| Ecosystem | Lock File & `ResolutionScope` | Angry Turnip (`status / recall / total`) | Trivy (`status / recall / total`) | Analysis |
|-----------|-------------------------------|-----------------------------------|-----------------------------------|----------|
| **npm** | `package-lock.json` (`full-lockfile`) | `OK(COMPLETE)` — **rec 2/2**, tot **11** | `OK` — **rec 2/2**, tot **11** | Identical 11-finding set on this fixture and 2/2 ground-truth recall (`CVE-2021-23337`, `CVE-2023-45133`). |
| **go** | `go.mod` (`go-mod-manifest`) | `OK(COMPLETE)` — **rec 1/1**, tot **24** | `OK` — **rec 1/1**, tot **24** | Both honour `replace golang.org/x/net v0.17.0 => v0.18.0` and report the same 24 findings (`CVE-2023-45288`) on this `go.mod` fixture. |
| **maven** | `pom.xml` (`partial-pom`) | `OK(PARTIAL)` — **rec 1/1**, tot **21** | `OK` — **rec 1/1**, tot **25** | Both detect `CVE-2021-44228`. Angry Turnip merges 4 overlapping GHSA/CVE aliases via union-find (21 canonical findings vs 25 raw records) and **explicitly flags `PARTIAL` evidence** (with `resolution_scope: partial-pom`) because `spring-boot-starter-web` lacks a locally resolvable version. |
| **python** | `uv.lock` (`full-lockfile`) | `OK(COMPLETE)` — **rec 1/1**, tot **18** | `OK` — **rec 0/1**, tot **0** | Difference reflects input format support: Angry Turnip natively parses `uv.lock` (`18` findings including `CVE-2021-33503`), whereas Trivy did not ingest `uv.lock` in this run. |
| **cargo** | `Cargo.lock` (`full-lockfile`) | `OK(COMPLETE)` — **rec 1/1**, tot **9** | `OK` — **rec 1/1**, tot **6** | Both detect `CVE-2021-45710`; the +3 difference on Angry Turnip comes from unaliased `RUSTSEC-*` advisories in OSV.dev for `smallvec@1.6.0` and `tokio@1.8.0`. |
| **composer** | `composer.lock` (`full-lockfile`) | `OK(COMPLETE)` — **rec 1/1**, tot **14** | `OK` — **rec 1/1**, tot **14** | Identical 14-finding set on this fixture and 1/1 ground-truth recall (`CVE-2022-31042`). |
