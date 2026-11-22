# Angry Turnip Documentation

Complete documentation for **Angry Turnip (`atnp`)** vulnerability scanner and security policy engine (formerly **Vigil CLI**).

## Getting Started

New to Angry Turnip? Start here:

- [Installation](getting-started/installation.md) - Install `atnp` on your system
- [Quick Start](getting-started/quick-start.md) - First scan in 5 minutes
- [Examples](getting-started/examples.md) - Common use cases and workflows

## User Guide

Using Angry Turnip in production:

- [Commands](user-guide/commands.md) - Complete CLI reference (`atnp scan`, `atnp report`, `atnp ci`, `atnp explain`, `atnp baseline`, `atnp version`)
- [Interactive TUI Assessment View](user-guide/tui.md) - Observable stage scanning & decision-first terminal explorer
- [Reports](user-guide/reports.md) - Understanding output formats
- [Troubleshooting](user-guide/troubleshooting.md) - Common issues and solutions

## Architecture

Technical deep-dive:

- [Overview](architecture/overview.md) - System design and components
- [Components](architecture/components.md) - Internal package architecture
- [Data Flow](architecture/data-flow.md) - Scanning and enrichment pipeline

## Development

Contributing to Angry Turnip:

- [Setup](development/setup.md) - Development environment setup
- [Contributing](development/contributing.md) - Contribution guidelines
- [Testing](development/testing.md) - Running and writing tests

## Architecture Decision Records

Historical and current design decisions:

- [ADR-001: Language Choice](adr/001-language-choice.md)
- [ADR-002: OSV API Integration](adr/002-osv-api-integration.md)
- [ADR-003: Project Structure](adr/003-project-structure.md)
- [ADR-004: Caching Strategy](adr/004-caching-strategy.md)
- [ADR-005: Multi-source CVSS Enrichment](adr/005-multi-source-cvss-enrichment.md)
- [ADR-006: Internal by Default](adr/006-internal-by-default.md)
- [ADR-007: Security Report Format](adr/007-security-report-format.md)
- [ADR-008: Multi-Ecosystem Support](adr/008-multi-ecosystem-support.md)
- [ADR-009: Full-Spectrum Security & SBOM Engine](adr/009-full-spectrum-security-and-sbom.md)
- [ADR-010: Java Ecosystem Support (Maven & Gradle)](adr/010-java-ecosystem-support.md)
- [ADR-011: Fullscreen DevSecOps Dashboard TUI](adr/011-fullscreen-devsecops-tui.md)
- [ADR-012: Hardened Multi-Ecosystem Dependency Resolution](adr/012-hardened-multi-ecosystem-dependency-resolution.md)
- [ADR-013: Explainable Policy Decisions, Baselines, and Evidence Completeness](adr/013-explainable-policy-decisions.md)
- [ADR-014: Rebrand Vigil CLI as Angry Turnip with atnp executable](adr/014-rebrand-vigil-to-angry-turnip.md)

## Quick Links

- [Main README](../README.md)
- [GitHub Repository](https://github.com/guttenbergovitz/angry-turnip)
