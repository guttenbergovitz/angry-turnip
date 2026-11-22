# Angry Turnip (`atnp`) DevSecOps Full-Spectrum Scanner

`guttenbergovitz/angry-turnip` (formerly `guttenbergovitz/vigil`) is a lightweight, zero-dependency DevSecOps scanner for multi-ecosystem Software Composition Analysis (SCA), Secret Scanning, Licence Compliance, SBOM Generation, Container Audit, IaC Security, and Explainable Policy Decisions.

[![Docker Pulls](https://img.shields.io/docker/pulls/guttenbergovitz/angry-turnip)](https://hub.docker.com/r/guttenbergovitz/angry-turnip)
[![Docker Image Size](https://img.shields.io/docker/image-size/guttenbergovitz/angry-turnip/latest)](https://hub.docker.com/r/guttenbergovitz/angry-turnip)
[![GitHub License](https://img.shields.io/github/license/guttenbergovitz/angry-turnip)](https://github.com/guttenbergovitz/angry-turnip)

---

## 🚀 Quick Start

### 1. Scan Local Directory

Run a full security scan on your current working directory:

```bash
docker run --rm -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan .
```

### 2. Scan Remote Git Repository

Scan any public or private GitHub/Bitbucket repository directly:

```bash
docker run --rm guttenbergovitz/angry-turnip:latest scan https://github.com/expressjs/express
```

### 3. Interactive DevSecOps Assessment TUI

Run with terminal interactive TUI enabled (`-it` flag):

```bash
docker run --rm -it -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan .
```

---

## ✨ Features

- **Multi-Ecosystem SCA**: JavaScript/TypeScript (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`), Rust (`Cargo.lock`), PHP (`composer.lock`), Go (`go.mod`), and Java (`pom.xml`, `gradle.lockfile`).
- **Secret Scanning**: Scans codebase for leaked AWS keys, GitHub PATs, Slack Webhooks, DB passwords, and private SSH keys using regex patterns and Shannon entropy analysis.
- **Licence Compliance**: Identifies Permissive vs Copyleft (GPL, AGPL) obligations.
- **Container & IaC Security**: Audits Dockerfiles and GitHub Actions workflows for security misconfigurations and root execution risks.
- **Software Bill of Materials (SBOM)**: Generates industry-standard **CycloneDX v1.5** and **SPDX v2.3** JSON formats.
- **Explainable Policy Engine & SARIF 2.1.0**: Evaluates findings into `BLOCK`, `REVIEW`, and `ALLOW` with CISA KEV and FIRST EPSS threat intelligence.
- **Interactive Assessment TUI**: Observable 9-stage progress view and single-table explorer with tabs (`[1-5]`), Overview (`[o]`), Evidence (`[i]`), detail pane (`[Enter]`), grouping (`[g]`), search (`[/]`), and export modal (`[e]`).
- **Multiple Export Formats**: JSON, SARIF 2.1.0, CSV, Markdown, CycloneDX, SPDX.

---

## 🛠️ Environment Variables

Optionally pass API tokens for higher rate limits and enriched vulnerability scoring:

```bash
docker run --rm -v "$(pwd):/scan" \
  -e NVD_API_KEY="your-nvd-api-key" \
  -e GITHUB_TOKEN="your-github-token" \
  guttenbergovitz/angry-turnip:latest scan .
```

---

## 📊 Exporting Reports

To emit machine-readable reports directly to your host machine:

```bash
# Save JSON report
docker run --rm -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan . --output json > report.json

# Save SARIF 2.1.0 report
docker run --rm -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan . --output sarif > report.sarif.json

# Save CycloneDX v1.5 SBOM
docker run --rm -v "$(pwd):/scan" guttenbergovitz/angry-turnip:latest scan . --output cyclonedx > sbom.cdx.json
```

---

## 📄 Repository & Documentation

- **GitHub Repository**: [https://github.com/guttenbergovitz/angry-turnip](https://github.com/guttenbergovitz/angry-turnip)
- **Documentation**: [https://github.com/guttenbergovitz/angry-turnip/tree/main/documentation](https://github.com/guttenbergovitz/angry-turnip/tree/main/documentation)
- **Changelog**: [https://github.com/guttenbergovitz/angry-turnip/blob/main/CHANGELOG.md](https://github.com/guttenbergovitz/angry-turnip/blob/main/CHANGELOG.md)
