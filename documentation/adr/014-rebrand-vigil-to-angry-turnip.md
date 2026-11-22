# ADR-014: Rebrand Vigil CLI as Angry Turnip with atnp executable

**Status:** Accepted

**Date:** 2026-11-22

## Context

The project originally launched under the name **Vigil CLI** (`github.com/guttenbergovitz/vigil-cli`) with the `vigil` command-line executable. As the tool matured into a full-spectrum security assessment and explainable policy decision engine across six package ecosystems (`npm`, `PyPI`, `Go`, `Cargo`, `Packagist`, `Maven`), Secrets, IaC, Licences, SBOMs, and SARIF 2.1.0, several product identity and trademark constraints became clear:

1. **Naming collisions in the security and developer tooling space**: "Vigil" is heavily overloaded across open-source monitoring tools, commercial security products, and status page services, creating search ambiguity and package registry collisions.
2. **Desire for a memorable, distinctive brand paired with an ergonomic CLI executable**: A security CLI invoked dozens of times per day in developer terminals and CI pipelines benefits from a distinct brand identity for documentation and discovery alongside a concise, low-friction 4-character executable name.
3. **Continuity of Git history, release tags, and existing user workflows**: The repository already has an established commit history, fourteen Architecture Decision Records, benchmark suites, and release tags through `v2.8.0`. Any migration must preserve full Git history, tags, and backwards compatibility for local caches, baselines, and environment variables.

## Decision

We will rebrand the product and migrate its canonical identity as follows:

- **Product / Project Name**: **Angry Turnip**
- **GitHub Repository**: `guttenbergovitz/angry-turnip` (renamed in place from `guttenbergovitz/vigil-cli` to preserve Git history, tags, releases, and GitHub HTTP/Git redirects)
- **Go Module Path**: `github.com/guttenbergovitz/angry-turnip`
- **Canonical CLI Executable**: **`atnp`** (built from `./cmd/atnp`)
- **Backwards-Compatible Entry Point**: Retain `./cmd/vigil` as a thin compatibility wrapper so existing build scripts targeting `./cmd/vigil` continue to compile during the transition period
- **Persisted Data & Environment Compatibility**:
  - Default scan cache filename becomes `.atnp.cache`, with automatic read fallback to `.vigil.cache` if `.atnp.cache` is absent.
  - Default baseline filename becomes `.atnp.baseline.json`, while `--baseline` continues to accept any path (including `.vigil.baseline.json`).
  - Worker concurrency reads `ATNP_WORKERS` first and falls back to `VIGIL_WORKERS` when `ATNP_WORKERS` is unset.

## Alternatives Considered

### 1. Keep "Vigil"

- **Pros**: Zero migration effort; no changes to module paths, documentation, or scripts.
- **Cons**: Perpetual naming collision with existing monitoring and security tools named Vigil; weak brand distinctiveness.
- **Decision**: Rejected.

### 2. "Vigil" + Descriptive Suffix (e.g. `vigil-sec`, `vigil-scanner`)

- **Pros**: Familiar root word for existing users.
- **Cons**: Still collides with the crowded "Vigil" namespace; longer, less memorable brand and binary names.
- **Decision**: Rejected.

### 3. "Purple Turtle"

- **Pros**: Memorable two-word animal/colour pairing.
- **Cons**: Conveys slowness ("turtle"), which conflicts with a high-concurrency Go security scanner; weaker visual and tonal fit for an assertive security gate.
- **Decision**: Rejected.

### 4. "Cautrix"

- **Pros**: Synthetic security-adjacent name derived from "caution" / "matrix".
- **Cons**: Sounds like a generic enterprise SaaS vendor; less memorable and harder to spell or pronounce consistently.
- **Decision**: Rejected.

### 5. "Tsirah"

- **Pros**: Short and unique in search results.
- **Cons**: Non-obvious pronunciation and spelling (`ts-` initial cluster), leading to typing friction in CLI and documentation contexts.
- **Decision**: Rejected.

### 6. "Angry Turnip" with `turnip` Executable

- **Pros**: Strong, unmistakable brand identity; natural English word for the binary.
- **Cons**: 6-character binary name (`turnip`) is slightly longer to type repeatedly in interactive terminal workflows and may collide with unrelated hobby scripts.
- **Decision**: Rejected in favour of a 4-character acronym executable.

### 7. "Angry Turnip" with `angry-turnip` Executable

- **Pros**: Exact 1:1 match between repository slug and binary name.
- **Cons**: 12 characters with a hyphen is cumbersome for daily interactive CLI invocation (`angry-turnip scan .`, `angry-turnip explain ...`).
- **Decision**: Rejected for the executable name, but selected for the GitHub repository slug (`guttenbergovitz/angry-turnip`).

### 8. "Angry Turnip" with `atnp` Executable (Selected)

- **Pros**: Distinctive, memorable brand name (**Angry Turnip**) combined with a fast, collision-free 4-letter consonant executable (**`atnp`**) following Unix CLI conventions (`rg`, `gh`, `jq`, `trivy`).
- **Cons**: Requires documentation to link the **Angry Turnip** product name with the `atnp` executable and `ATNP_*` environment variables.
- **Decision**: **Accepted**.

## Consequences

### Positive

- **Distinctive brand identity**: **Angry Turnip** is memorable, unambiguous in search engines, and free of collisions in the AppSec tooling ecosystem.
- **Ergonomic CLI invocation**: `atnp scan .`, `atnp ci`, `atnp explain`, `atnp report`, and `atnp baseline` are concise and fast to type.
- **Preserved engineering heritage**: In-place repository rename preserves all commits, branches, release tags (`v1.0.0` through `v2.8.0`), and historical ADRs (`001`–`013`), while GitHub automatically redirects legacy git clone and web URLs.
- **Smooth user transition**: Automatic fallbacks for `.vigil.cache`, `VIGIL_WORKERS`, and `./cmd/vigil` prevent sudden breakage in local workspaces and CI pipelines.

### Negative

- **Module path migration**: Downstream Go consumers or scripts using `go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest` must update to `go install github.com/guttenbergovitz/angry-turnip/cmd/atnp@latest` for future releases.
- **Dual terminology during transition**: Documentation must briefly explain the relationship between **Angry Turnip**, `atnp`, and legacy `vigil` artifacts.

## Risk Mitigation

1. **GitHub repository rename in place**: Use `gh repo rename angry-turnip` rather than creating a new repository so GitHub maintains permanent HTTP and Git push/pull redirects from `guttenbergovitz/vigil-cli`.
2. **Cache and environment variable fallback**: `lockfile.ResolveCachePath` transparently falls back to `.vigil.cache` on read when `.atnp.cache` does not exist yet, and `getWorkerCount()` honours `VIGIL_WORKERS` when `ATNP_WORKERS` is not set.
3. **Legacy `./cmd/vigil` wrapper**: Keep `cmd/vigil/main.go` compiling in the tree so existing local build scripts do not fail immediately.
4. **Comprehensive migration guide**: Document old-to-new mappings for URLs, binaries, `go install`, Docker, Nix, caches, baselines, and SARIF rule IDs in `README.md`.

## Validation and Rollback

- **Validation**:
  - `go fmt ./...`, `go vet ./...`, and `go test -race ./...` pass across all packages and reference benchmarks.
  - `go build -o atnp ./cmd/atnp` produces a working `atnp` executable whose `version`, `scan`, `report`, `ci`, `explain`, and `baseline` subcommands output canonical `Angry Turnip` / `atnp` branding.
  - `git remote -v` and `gh repo view guttenbergovitz/angry-turnip` confirm the renamed remote and preserved release tags.
- **Rollback**:
  - If an unexpected issue arises during migration, the repository can be renamed back via `gh repo rename vigil-cli --repo guttenbergovitz/angry-turnip --yes` and the migration commit reverted cleanly on `develop` and `main` without loss of history.
