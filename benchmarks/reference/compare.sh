#!/usr/bin/env bash
set -euo pipefail

# Side-by-side live comparison of Vigil against keyless public SCA scanners
# (OSV-Scanner, Trivy, Grype) on the reference fixtures in benchmarks/reference/.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ECOSYSTEMS=(npm go maven python cargo composer)

VIGIL_BIN="${REPO_ROOT}/vigil-bench"
go build -o "${VIGIL_BIN}" "${REPO_ROOT}/cmd/vigil"
trap 'rm -f "${VIGIL_BIN}"' EXIT

printf "%-10s | %-12s | %-12s | %-12s | %-12s\n" "Ecosystem" "Vigil" "OSV-Scanner" "Trivy" "Grype"
printf "%-10s-+-%-12s-+-%-12s-+-%-12s-+-%-12s\n" "----------" "------------" "------------" "------------" "------------"

for eco in "${ECOSYSTEMS[@]}"; do
  dir="${SCRIPT_DIR}/${eco}"
  tmp="$(mktemp -d)"
  cp -R "${dir}/." "${tmp}/"

  vigil_out=$("${VIGIL_BIN}" ci --format json "${tmp}" 2>/dev/null || true)
  vigil_cnt=$(printf '%s' "${vigil_out}" | grep -o '"key":' | wc -l | tr -d ' ')

  if command -v osv-scanner >/dev/null 2>&1; then
    osv_cnt=$(osv-scanner --format json "${tmp}" 2>/dev/null | grep -o '"id":' | wc -l | tr -d ' ' || echo "err")
  else
    osv_cnt="n/a"
  fi

  if command -v trivy >/dev/null 2>&1; then
    trivy_cnt=$(trivy fs --format json --quiet "${tmp}" 2>/dev/null | grep -o '"VulnerabilityID":' | wc -l | tr -d ' ' || echo "err")
  else
    trivy_cnt="n/a"
  fi

  if command -v grype >/dev/null 2>&1; then
    grype_cnt=$(grype "dir:${tmp}" -o json -q 2>/dev/null | grep -o '"vulnerability":' | wc -l | tr -d ' ' || echo "err")
  else
    grype_cnt="n/a"
  fi

  printf "%-10s | %-12s | %-12s | %-12s | %-12s\n" "${eco}" "${vigil_cnt}" "${osv_cnt}" "${trivy_cnt}" "${grype_cnt}"
  rm -rf "${tmp}"
done
