#!/usr/bin/env bash
set -euo pipefail

# Normalizes scanner outputs to canonical (CVE/AdvisoryID, PURL) pairs, tracks execution
# status independently from finding counts, and computes recall against expected.json.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"
exec go run ./benchmarks/reference/cmd/compare
