# Angry Turnip (`atnp`)

> **Note:** **Angry Turnip** (`atnp`) is the new product name and CLI executable for **Vigil CLI** (`vigil`). See [Migrating from Vigil CLI to Angry Turnip](#migrating-from-vigil-cli-to-angry-turnip) and [ADR-014](documentation/adr/014-rebrand-vigil-to-angry-turnip.md) for complete migration and compatibility details.

Lightweight vulnerability scanner and explainable policy decision engine for JavaScript/TypeScript, Python, Rust, PHP, Go, and Java projects.

Analyses dependency trees and reports CVE exposure with context, enriched CVSS scores, CISA KEV / FIRST EPSS threat intelligence, and auditable policy decisions.

## Quick Start

```bash
# Install
go install github.com/guttenbergovitz/angry-turnip/cmd/atnp@latest

# Scan local project
cd /path/to/your/project
atnp scan .

# Scan remote repository
atnp scan https://github.com/user/repo

# View report
atnp report
```

## Features

- **Multi-ecosystem SCA scanning** - JavaScript/TypeScript, Python, Rust, PHP, Go, and Java projects
- **Secret Scanning** - Detect hardcoded AWS keys, GitHub tokens, Slack webhooks, SSH keys, and DB credentials using regex and Shannon entropy analysis
- **Software Bill of Materials (SBOM)** - Export deterministic **CycloneDX v1.5** and **SPDX v2.3** JSON documents with full dependency graph relationships, RFC 4122 UUIDs, and collision-resistant SPDX identifiers
- **Licence Compliance** - Categorise licences into Permissive (MIT, Apache) vs Copyleft (GPL, AGPL) risk levels
- **Container & IaC Security** - Audit Dockerfiles and GitHub Actions workflows for security misconfigurations
- **Remote repository scanning** - Scan GitHub, Bitbucket, and other git repositories directly without cloning manually
- **Full dependency chain tracking** - Shows complete vulnerability paths for all supported lock file types
- **Explicit scan coverage & error reporting** - Tracks `scanned`, `failed`, `skipped`, and `unsupported` packages so API failures are never disguised as zero vulnerabilities
- **Multi-source CVSS enrichment** - Aggregates scores from NVD, GitHub Security Advisories, and OSV
- **Interactive DevSecOps TUI Assessment View** - Observable 9-stage scanning progress and interactive decision-first explorer with 5 security domains (`[1-5]`), Overview (`[o]`), Evidence (`[i]`), detail expansion (`[Enter]`), quick actions (`[y]` copy, `[x]` hide), search (`[/]`), and export formats (`[e]`). See [TUI User Guide](documentation/user-guide/tui.md).
- **Comprehensive CVE data** - Titles, descriptions, publication dates, and dependency paths
- **Multiple report formats**
  - **Table** (default): Compact Trivy-style tabular format with exploit classification
  - **Security**: Production-ready report for AppSec teams with executive summary
  - **SARIF 2.1.0**: GitHub Code Scanning integration with diagnostic rules for incomplete or unverified evidence
  - **CycloneDX / SPDX**: Industry-standard SBOM export formats (JSON)
  - **Text**: Tree-structured detailed view
  - **CSV / Markdown / JSON**: Export formats for integration
- **Evidence-based exploitability assessment** - Distinguishes `potentially_exploitable`, `unknown`, and `confirmed_not_affected` with explicit rationale instead of categorical assumptions
- **Explainable security decisions (`atnp explain`)** - Explains why a vulnerability is `ALLOW`, `REVIEW`, or `BLOCK`, which policy rule matched, and what evidence is missing
- **Baseline & delta analysis (`atnp baseline`)** - Tracks newly introduced, existing, and resolved vulnerabilities against an accepted baseline snapshot
- **Policy as Code (`--policy`)** - Declarative YAML rules with owned, time-bounded exceptions (`expires_at`) enforced deterministically in `atnp ci`
- **Fresh CI/CD security gate** - `atnp ci` runs a fresh scan by default and fails on incomplete scan coverage (`--fail-on-scan-error`)

## Requirements

- Go 1.27+ (if building from source)
- Project with a supported lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `Cargo.lock`, `composer.lock`, `go.mod`, `pom.xml`, or `gradle.lockfile`)

## Installation

### Option 1: go install (Recommended)

```bash
go install github.com/guttenbergovitz/angry-turnip/cmd/atnp@latest
```

### Option 2: Docker

```bash
docker pull guttenbergovitz/angry-turnip:latest
docker run --rm -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan .
```

### Option 3: Nix

```bash
nix run github:guttenbergovitz/angry-turnip -- scan .
```

### Option 4: Build from Source

```bash
# Install task runner (if not installed)
go install github.com/go-task/task/v3/cmd/task@latest

# Build atnp
git clone https://github.com/guttenbergovitz/angry-turnip
cd angry-turnip
task build
sudo mv atnp /usr/local/bin/
```

Taskfile injects version information at build time. See [Installation Guide](documentation/getting-started/installation.md) for details.

## Usage

### Scan Dependencies

```bash
# Interactive TUI assessment (default when stdout is a terminal)
atnp scan .

# Non-interactive human summary (no TUI)
atnp scan . --no-tui

# Machine-readable output on stdout (TUI automatically disabled)
atnp scan . --output json
atnp scan . --output sarif
atnp scan . --output cyclonedx
atnp scan . --output spdx

# Control scan scope: 'all' (SCA + Secrets + IaC + Licences) or 'sca' (SCA only)
atnp scan . --scope sca
atnp scan . --scope all

# Stream plain stage progress lines to stderr (clean stdout for piping/CI)
atnp scan . --progress plain --no-tui

# Exclude development dependencies or specify an explicit lockfile
atnp scan . --skip-devdeps --lockfile uv.lock

# Scan remote repository (GitHub, Bitbucket, GitLab)
atnp scan https://github.com/user/repo
atnp scan git@github.com:user/repo.git
```

#### `atnp scan` CLI Flags

| Flag | Values / Default | Description |
|------|------------------|-------------|
| `--no-tui` | `false` | Disable interactive Bubble Tea TUI and print human summary |
| `--output <fmt>` | `json`, `sarif`, `csv`, `markdown`, `cyclonedx`, `spdx` | Emit machine-readable report to `stdout` (auto-disables TUI) |
| `--scope <mode>` | `all` (default), `sca` | `all` runs SCA, Secrets, IaC, and Licences; `sca` runs dependency vulnerability scanning only |
| `--progress <mode>` | `auto` (default), `plain`, `none` | `plain` streams stage completion events to `stderr`; `none` suppresses progress output |
| `--skip-devdeps` | `false` | Exclude development/test dependencies from scan scope |
| `--lockfile <name>` | auto-detected | Explicitly select lockfile or manifest (e.g. `uv.lock`, `poetry.lock`, `pom.xml`) |
| `--secrets` | `false` | Print masked secret scan findings in CLI summary mode |

**Remote scanning:**
- Clones repository to temp directory
- Scans lockfile
- Automatic cleanup after scan
- Uses `GITHUB_TOKEN` env var for private repos

### Generate Report

```bash
# Default table format
atnp report

# Security format for AppSec teams
atnp report --format security

# Export to file
atnp report --format csv --export vulns.csv

# Filter by severity
atnp report --filter high
```

### CI/CD Integration

```bash
# Fail build on high/critical vulnerabilities (fresh scan by default)
atnp ci --fail-on high

# Enforce declarative YAML policy with baseline delta (text, JSON, or SARIF 2.1.0)
atnp baseline .
atnp ci --policy atnp.yaml --baseline .atnp.baseline.json --format sarif

# Explain why a specific vulnerability triggered ALLOW, REVIEW, or BLOCK
atnp explain CVE-2026-0001 --policy atnp.yaml --baseline .atnp.baseline.json
```

See [Commands Reference](documentation/user-guide/commands.md) for all options and [Empirical Benchmark Results](benchmarks/reference/RESULTS.md) for side-by-side accuracy validation against Trivy across all six ecosystems.

## Environment Variables & API Keys

Angry Turnip works **out of the box without any API keys** using free public endpoints ([OSV.dev](https://osv.dev/), the public GitHub Security Advisories REST API, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/)).

Both optional keys below are **100% free** and only improve enrichment coverage and rate limits:

| Variable | Cost | Where to Obtain | Purpose & Rate Limits |
|----------|------|-----------------|-----------------------|
| `NVD_API_KEY` | **Free** (email registration) | [NIST NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key) | Enables authoritative NVD CVE enrichment (50 req / 30s, globally rate-limited). Skipped when unset. |
| `GITHUB_TOKEN` | **Free** (GitHub account) | [GitHub Personal Access Tokens](https://github.com/settings/tokens) (no scopes needed for public advisories; read-only `repo` scope only for private git cloning) | Switches GHSA lookups from public REST (60 req/hr) to GraphQL (5,000 req/hr) and authenticates private GitHub clones via `extraheader`. |
| `ATNP_WORKERS` | N/A | Local setting (`1`–`100`, default `10`; falls back to legacy `VIGIL_WORKERS`) | Controls concurrent package scan worker count. |

## Migrating from Vigil CLI to Angry Turnip

Angry Turnip (`atnp`) is a direct in-place rebrand of **Vigil CLI** (`vigil`). All core features, policy semantics, exit codes, and Git history are preserved.

### Identity & Distribution Mapping

| Item | Legacy (Vigil CLI) | Canonical (Angry Turnip) |
|------|--------------------|--------------------------|
| **Product Name** | Vigil / Vigil CLI | **Angry Turnip** |
| **GitHub Repository** | `https://github.com/guttenbergovitz/vigil-cli` | `https://github.com/guttenbergovitz/angry-turnip` |
| **CLI Executable** | `vigil` (`./cmd/vigil`) | **`atnp`** (`./cmd/atnp`) |
| **Go Module Path** | `github.com/guttenbergovitz/vigil-cli` | `github.com/guttenbergovitz/angry-turnip` |
| **Go Install Command** | `go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest` | `go install github.com/guttenbergovitz/angry-turnip/cmd/atnp@latest` |
| **Nix Flake Command** | `nix run github:guttenbergovitz/vigil-cli -- scan .` | `nix run github:guttenbergovitz/angry-turnip -- scan .` |
| **Scan Cache File** | `.vigil.cache` | `.atnp.cache` (automatically falls back to `.vigil.cache` on read) |
| **Default Baseline File** | `.vigil.baseline.json` | `.atnp.baseline.json` (`--baseline` accepts any file path) |
| **Worker Concurrency Env** | `VIGIL_WORKERS` | `ATNP_WORKERS` (automatically falls back to `VIGIL_WORKERS` if unset) |
| **SARIF Driver & Rule Prefix** | `driver.name: "Vigil"`, `VIGIL-*` | `driver.name: "Angry Turnip"`, `ATNP-*` |

### Updating Local Installations & CI Scripts

1. **Install the `atnp` binary**:
   ```bash
   go install github.com/guttenbergovitz/angry-turnip/cmd/atnp@latest
   atnp version
   ```
2. **Replace `vigil` invocations with `atnp` in shell scripts and CI workflows**:
   - `vigil scan .` → `atnp scan .`
   - `vigil report` → `atnp report`
   - `vigil ci` → `atnp ci`
   - `vigil explain` → `atnp explain`
   - `vigil baseline` → `atnp baseline`
3. **Configuration, Cache, and Build Compatibility**:
   - **Cache files**: `atnp scan` writes `.atnp.cache`. Commands that read cached results (`atnp report`, `atnp explain`, `atnp baseline`, `atnp ci --use-cache`) check `.atnp.cache` first and transparently fall back to `.vigil.cache` if `.atnp.cache` does not exist yet.
   - **Policy & baseline files**: YAML policy schemas (`version: 1`) and baseline JSON schemas (`version: 1`) are 100% compatible; existing `vigil.yaml` and `.vigil.baseline.json` files work unmodified with `--policy` and `--baseline`.
   - **Legacy `./cmd/vigil` build target**: `cmd/vigil/main.go` is retained as a thin compatibility entry point in the repository so legacy scripts building `./cmd/vigil` continue to compile, and the Docker image provides `/usr/local/bin/vigil` symlinked to `/usr/local/bin/atnp`.
   - **Breaking changes to watch for**: Downstream tools that parse SARIF `tool.driver.name` (`"Angry Turnip"`), SARIF diagnostic rule IDs (`ATNP-SCAN-INCOMPLETE`, `ATNP-EVIDENCE-INVALID`, `ATNP-EVIDENCE-UNVERIFIED`, `ATNP-BASELINE-INCOMPATIBLE`, `ATNP-RESOLUTION-AMBIGUOUS`), or SBOM tool metadata (`vendor: "Angry Turnip"`, `name: "atnp"`) should update any hardcoded `"Vigil"` filters.

## Documentation

- **Getting Started**
  - [Installation](documentation/getting-started/installation.md)
  - [Quick Start](documentation/getting-started/quick-start.md)
  - [Examples](documentation/getting-started/examples.md)
- **User Guide**
  - [Commands Reference](documentation/user-guide/commands.md)
  - [Interactive TUI Assessment View](documentation/user-guide/tui.md)
  - [Understanding Reports](documentation/user-guide/reports.md)
  - [Troubleshooting](documentation/user-guide/troubleshooting.md)
- **Architecture**
  - [System Overview](documentation/architecture/overview.md)
  - [Components](documentation/architecture/components.md)
  - [Data Flow](documentation/architecture/data-flow.md)
  - [ADR-014: Rebrand Vigil CLI as Angry Turnip](documentation/adr/014-rebrand-vigil-to-angry-turnip.md)
- **Development**
  - [Setup](documentation/development/setup.md)
  - [Contributing](documentation/development/contributing.md)
  - [Testing](documentation/development/testing.md)

Full documentation index: [documentation/README.md](documentation/README.md)

## Project Structure

```
.
├── cmd/
│   ├── atnp/                   # Canonical CLI entry point (atnp)
│   └── vigil/                  # Legacy compatibility entry point
├── internal/
│   ├── cli/                    # Command implementations
│   ├── container/              # Dockerfile & CI workflow auditor
│   ├── epss/                   # FIRST EPSS threat-intelligence client
│   ├── export/                 # Output format encoders
│   ├── git/                    # Remote Git repository cloner
│   ├── github/                 # GitHub Security Advisories client
│   ├── kev/                    # CISA KEV catalogue client
│   ├── license/                # Package licence compliance scanner
│   ├── lockfile/               # Lock file parsers and caching
│   ├── nvd/                    # NVD API client
│   ├── osv/                    # OSV API client
│   ├── policy/                 # Unified policy engine, baselines, and SARIF 2.1.0
│   ├── report/                 # Report generation
│   ├── sbom/                   # CycloneDX v1.5 and SPDX v2.3 SBOM generators
│   ├── scan/                   # Scan orchestration and observable stage events
│   ├── secrets/                # Regex + Shannon entropy secret scanner
│   ├── types/                  # Core data structures
│   └── ui/                     # Terminal UI (TUI)
├── benchmarks/reference/       # Ground-truth reference fixtures & live scanner benchmark
├── documentation/
│   ├── getting-started/        # Installation, quick start, examples
│   ├── user-guide/             # Commands, TUI, reports, troubleshooting
│   ├── architecture/           # System design and components
│   ├── development/            # Contributing and testing
│   └── adr/                    # Architecture decision records (ADR-001 to ADR-014)
└── test-project/               # Test fixtures
```

## CVSS & Threat Intelligence Sources

Angry Turnip enriches CVSS scores from multiple sources in priority order:

1. **NVD API** (for `CVE-*` IDs, when `NVD_API_KEY` is configured) — authoritative CVE scores, globally rate-limited across concurrent workers
2. **GitHub Security Advisories** (for `GHSA-*` IDs) — uses GraphQL when `GITHUB_TOKEN` is set, falling back to public REST API
3. **OSV API** — baseline community-aggregated advisory data
4. **Derived from known severity** — fallback approximation only when severity is explicitly known (`Unknown` severity retains CVSS `0.0` rather than fabricating a score)

When CVEs are discovered, Angry Turnip also runs a single best-effort, keyless threat-intelligence pass (zero requests on clean scans):

- **CISA KEV** — flags vulnerabilities confirmed as actively exploited in the wild (`known_exploited: true`)
- **FIRST EPSS** — attaches 30-day exploitation probability and percentile rank (`epss_score`, `epss_percentile`)

Circular dependency graphs are traversed safely without infinite loops via BFS depth tracking and visited-node guards.

## Lock File Support

- **JavaScript / TypeScript**: `package-lock.json` (npm), `yarn.lock` (Yarn), `pnpm-lock.yaml` (pnpm)
- **Python**: `uv.lock` (uv — full transitive graph), `poetry.lock` (Poetry — full transitive graph, `category` & `groups`), `Pipfile.lock` (Pipenv), `requirements.txt` (pip — pinned `==`/`===` versions; unpinned/range entries flagged as `unsupported`)
- **Rust**: `Cargo.lock` (Cargo)
- **PHP**: `composer.lock` (Composer)
- **Go**: `go.mod` (Go modules via `golang.org/x/mod/modfile`, supporting `replace` and `exclude`; local filesystem replacements flagged as `unsupported`)
- **Java / Kotlin**: `pom.xml` (Maven — direct declarations, local `<properties>`, `<dependencyManagement>`, and local multi-module `<parent>` inheritance up to 5 ancestor levels; external parent/BOM versions reported as `unsupported`), `gradle.lockfile` (Gradle)

## Contributing

See [Contributing Guide](documentation/development/contributing.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and notable changes.

## Licence

MIT
