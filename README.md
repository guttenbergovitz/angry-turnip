# Vigil CLI

Lightweight vulnerability scanner for JavaScript/TypeScript, Python, Rust, PHP, Go, and Java projects.

Analyses dependency trees and reports CVE exposure with context, enriched CVSS scores, and detailed vulnerability information.

## Quick Start

```bash
# Install
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest

# Scan local project
cd /path/to/your/node/project
vigil scan .

# Scan remote repository
vigil scan https://github.com/user/repo

# View report
vigil report
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
- **Interactive DevSecOps TUI Dashboard** - Productivity-focused single-pane dashboard with 5 security domains (`[1-5]`), detail expansion (`[Enter]`), quick actions (`[y]` copy, `[x]` mark fixed), visual severity badges, search (`[/]`), and export formats (`[e]`). Smart default: Critical+High filter. See [TUI User Guide](documentation/user-guide/tui.md).
- **Comprehensive CVE data** - Titles, descriptions, publication dates, and dependency paths
- **Multiple report formats**
  - **Table** (default): Compact Trivy-style tabular format with exploit classification
  - **Security**: Production-ready report for AppSec teams with executive summary
  - **CycloneDX / SPDX**: Industry-standard SBOM export formats (JSON)
  - **Text**: Tree-structured detailed view
  - **CSV / Markdown / JSON**: Export formats for integration
- **Evidence-based exploitability assessment** - Distinguishes `potentially_exploitable`, `unknown`, and `confirmed_not_affected` with explicit rationale instead of categorical assumptions
- **Explainable security decisions (`vigil explain`)** - Explains why a vulnerability is `ALLOW`, `REVIEW`, or `BLOCK`, which policy rule matched, and what evidence is missing
- **Baseline & delta analysis (`vigil baseline`)** - Tracks newly introduced, existing, and resolved vulnerabilities against an accepted baseline snapshot
- **Policy as Code (`--policy`)** - Declarative YAML rules with owned, time-bounded exceptions (`expires_at`) enforced deterministically in `vigil ci`
- **Fresh CI/CD security gate** - `vigil ci` runs a fresh scan by default and fails on incomplete scan coverage (`--fail-on-scan-error`)

## Requirements

- Go 1.27+ (if building from source)
- Project with a supported lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `Cargo.lock`, `composer.lock`, `go.mod`, `pom.xml`, or `gradle.lockfile`)

## Installation

### Option 1: go install (Recommended)

```bash
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

### Option 2: Docker

```bash
docker pull guttenbergovitz/vigil:latest
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan .
```

### Option 3: Nix

```bash
nix run github:guttenbergovitz/vigil-cli -- scan .
```

### Option 4: Build from Source

```bash
# Install task runner (if not installed)
go install github.com/go-task/task/v3/cmd/task@latest

# Build vigil
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli
task build
sudo mv vigil /usr/local/bin/
```

Taskfile injects version information at build time. See [Installation Guide](documentation/getting-started/installation.md) for details.

## Usage

### Scan Dependencies

```bash
# Interactive TUI assessment (default when stdout is a terminal)
vigil scan .

# Non-interactive human summary (no TUI)
vigil scan . --no-tui

# Machine-readable output on stdout (TUI automatically disabled)
vigil scan . --output json
vigil scan . --output sarif
vigil scan . --output cyclonedx
vigil scan . --output spdx

# Control scan scope: 'all' (SCA + Secrets + IaC + Licences) or 'sca' (SCA only)
vigil scan . --scope sca
vigil scan . --scope all

# Stream plain stage progress lines to stderr (clean stdout for piping/CI)
vigil scan . --progress plain --no-tui

# Exclude development dependencies or specify an explicit lockfile
vigil scan . --skip-devdeps --lockfile uv.lock

# Scan remote repository (GitHub, Bitbucket, GitLab)
vigil scan https://github.com/user/repo
vigil scan git@github.com:user/repo.git
```

#### `vigil scan` CLI Flags

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
vigil report

# Security format for AppSec teams
vigil report --format security

# Export to file
vigil report --format csv --export vulns.csv

# Filter by severity
vigil report --filter high
```

### CI/CD Integration

```bash
# Fail build on high/critical vulnerabilities (fresh scan by default)
vigil ci --fail-on high

# Enforce declarative YAML policy with baseline delta (text, JSON, or SARIF 2.1.0)
vigil baseline .
vigil ci --policy vigil.yaml --baseline .vigil.baseline.json --format sarif

# Explain why a specific vulnerability triggered ALLOW, REVIEW, or BLOCK
vigil explain CVE-2026-0001 --policy vigil.yaml --baseline .vigil.baseline.json
```

See [Commands Reference](documentation/user-guide/commands.md) for all options and [Empirical Benchmark Results](benchmarks/reference/RESULTS.md) for side-by-side accuracy validation against Trivy across all six ecosystems.

## Environment Variables & API Keys

Vigil works **out of the box without any API keys** using free public endpoints ([OSV.dev](https://osv.dev/), the public GitHub Security Advisories REST API, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/)).

Both optional keys below are **100% free** and only improve enrichment coverage and rate limits:

| Variable | Cost | Where to Obtain | Purpose & Rate Limits |
|----------|------|-----------------|-----------------------|
| `NVD_API_KEY` | **Free** (email registration) | [NIST NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key) | Enables authoritative NVD CVE enrichment (50 req / 30s, globally rate-limited). Skipped when unset. |
| `GITHUB_TOKEN` | **Free** (GitHub account) | [GitHub Personal Access Tokens](https://github.com/settings/tokens) (no scopes needed for public advisories; read-only `repo` scope only for private git cloning) | Switches GHSA lookups from public REST (60 req/hr) to GraphQL (5,000 req/hr) and authenticates private GitHub clones via `extraheader`. |
| `VIGIL_WORKERS` | N/A | Local setting (`1`–`100`, default `10`) | Controls concurrent package scan worker count. |

## Documentation

- **Getting Started**
  - [Installation](documentation/getting-started/installation.md)
  - [Quick Start](documentation/getting-started/quick-start.md)
  - [Examples](documentation/getting-started/examples.md)
- **User Guide**
  - [Commands Reference](documentation/user-guide/commands.md)
  - [Understanding Reports](documentation/user-guide/reports.md)
  - [Troubleshooting](documentation/user-guide/troubleshooting.md)
- **Architecture**
  - [System Overview](documentation/architecture/overview.md)
  - [Components](documentation/architecture/components.md)
  - [Data Flow](documentation/architecture/data-flow.md)
- **Development**
  - [Setup](documentation/development/setup.md)
  - [Contributing](documentation/development/contributing.md)
  - [Testing](documentation/development/testing.md)

Full documentation index: [documentation/README.md](documentation/README.md)

## Project Structure

```
.
├── cmd/vigil/                  # CLI entry point
├── internal/
│   ├── cli/                    # Command implementations
│   ├── export/                 # Output format encoders
│   ├── github/                 # GitHub Security Advisories client
│   ├── lockfile/               # Lock file parsers and caching
│   ├── nvd/                    # NVD API client
│   ├── osv/                    # OSV API client
│   ├── report/                 # Report generation
│   ├── scan/                   # Scan orchestration
│   ├── types/                  # Core data structures
│   └── ui/                     # Terminal UI (TUI)
├── documentation/
│   ├── getting-started/        # Installation, quick start, examples
│   ├── user-guide/             # Commands, reports, troubleshooting
│   ├── architecture/           # System design and components
│   ├── development/            # Contributing and testing
│   └── adr/                    # Architecture decision records
└── test-project/               # Test fixtures
```

## CVSS & Threat Intelligence Sources

Vigil enriches CVSS scores from multiple sources in priority order:

1. **NVD API** (for `CVE-*` IDs, when `NVD_API_KEY` is configured) — authoritative CVE scores, globally rate-limited across concurrent workers
2. **GitHub Security Advisories** (for `GHSA-*` IDs) — uses GraphQL when `GITHUB_TOKEN` is set, falling back to public REST API
3. **OSV API** — baseline community-aggregated advisory data
4. **Derived from known severity** — fallback approximation only when severity is explicitly known (`Unknown` severity retains CVSS `0.0` rather than fabricating a score)

When CVEs are discovered, Vigil also runs a single best-effort, keyless threat-intelligence pass (zero requests on clean scans):

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
