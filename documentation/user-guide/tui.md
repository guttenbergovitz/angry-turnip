# Interactive Security Assessment TUI

Vigil includes an interactive terminal assessment view built on Bubble Tea, designed for observable multi-stage scanning and explainable policy triage.

```
VIGIL / ASSESSMENT | DECISION: BLOCK | EVIDENCE: COMPLETE | RESOLUTION: COMPLETE | Coverage: 247/247
[1] Findings (SCA)  [2] Secrets (0)  [3] IaC (0)  [4] Licences (247)  [5] Dep Graph  [o] Overview  [i] Evidence
BLOCK: 2 · REVIEW: 8 · ALLOW: 26 (Accepted: 1) | Showing: 36
╭──────────────────────────────────────────────────────────────────────────────────────────────────────╮
│  Findings (Enter to inspect decision & provenance)                                                   │
│ DECISION    DOMAIN    SEVERITY    COMPONENT                 ID / RULE           SIGNAL & REASON      │
│──────────────────────────────────────────────────────────────────────────────────────────────────────│
│ BLOCK       SCA       CRITICAL    log4j-core@2.14.1         CVE-2021-44228      [KEV] Matched rule...│
│ REVIEW      SCA       HIGH        example-lib@1.4.0         CVE-2026-0001       [NEW] Require rev... │
│ ACCEPTED    SCA       MEDIUM      legacy-lib@0.9.0          CVE-2025-1111       [Accepted risk] ...  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
 [↑/↓/j/k] Move | [Enter] Details | [/] Search | [f] Filter | [s] Sort | [g] Group | [x/X/v] Hide/Restore | [r] Reveal Secret | [e] Export | [?] Help | [q] Quit
```

---

## Observable Scan Pipeline

During scanning (`StateScanning`), Vigil displays live status across all nine assessment stages rather than a single global percentage:

1. **Discover & parse** — lockfile/manifest discovery and component count
2. **Dependency resolution** — resolved nodes, unresolved entries, and ambiguous multi-version edges
3. **Vulnerability lookup** — live `processed`, `queued`, `active`, `failed`, and `skipped` counters with actual `VIGIL_WORKERS`
4. **NVD / GHSA enrichment** — authoritative CVSS and severity enrichment
5. **CISA KEV / FIRST EPSS** — parallel threat-intelligence enrichment
6. **Secrets scan** — credential and high-entropy pattern detection
7. **IaC / Container audit** — Dockerfile and CI workflow checks
8. **Licence analysis** — SPDX licence extraction and obligation classification
9. **Policy evaluation** — canonical finding deduplication and `ALLOW` / `REVIEW` / `BLOCK` evaluation

Live findings shown during scanning are explicitly marked as **preliminary** until deduplication, enrichment, and policy evaluation finish.

---

## Views & Navigation

| Key | Action |
| --- | --- |
| `↑` / `↓` / `k` / `j` | Move cursor in the active findings table |
| `Enter` | Expand or collapse the full decision, provenance, dependency path, and missing-evidence pane |
| `1` – `5` | Switch domain view (`Findings (SCA)`, `Secrets`, `IaC`, `Licences`, `Dep Graph`) |
| `o` | Open **Assessment Overview** (overall decision, evidence & resolution completeness, coverage, threat-intel status) |
| `i` | Open **Evidence & Pipeline Stages** (stage outcomes, unresolved/ambiguous dependencies, activity log) |

## Filtering, Sorting & Grouping

By default, **all findings are shown** (including `Medium`, `Low`, and `Unknown` severity) and sorted by **Decision Priority** (`BLOCK` > `REVIEW` > `ACCEPTED` > `ALLOW`).

| Key | Action |
| --- | --- |
| `/` | Live search by package, CVE/GHSA, PURL, policy decision, or summary |
| `f` | Cycle quick filters (`All` → `BLOCK only` → `REVIEW only` → `CISA KEV only` → `Critical+High`) |
| `s` | Cycle sort order (`Decision Priority` → `Severity` → `CVSS Score` → `Component Name`) |
| `g` | Cycle grouping (`None` → `Package` → `Severity` → `Decision`) |
| `C` / `H` / `M` / `L` | Filter by `Critical`, `High`, `Medium`, or `Low` severity |
| `a` | Clear all active filters and search |

## Triage Actions, Secret Safety & Export

| Key | Action |
| --- | --- |
| `y` | Copy selected CVE / advisory / rule ID to clipboard |
| `x` | Hide or unhide the selected finding locally by canonical key (`ID\|PURL`) — never claims remediation |
| `v` | Toggle viewing locally hidden findings so individual items can be inspected or unhidden |
| `X` | Restore all locally hidden findings |
| `r` | Reveal or mask **only the currently selected secret** (secrets are masked by default) |
| `e` | Open Export Dialog (`JSON`, `CSV`, `Markdown`, `CycloneDX v1.5`, `SPDX v2.3`, **`SARIF v2.1.0`**) |
| `?` | Context-aware keyboard shortcut help |
| `q` / `Ctrl+C` | Quit (cancels active scan context) |

## CLI Execution Modes

```bash
vigil scan .                        # Interactive TUI (when stdout is a TTY)
vigil scan . --no-tui               # Human-readable CLI summary
vigil scan . --output json          # Machine-readable JSON on stdout (TUI auto-disabled)
vigil scan . --output sarif         # Machine-readable SARIF 2.1.0 on stdout (TUI auto-disabled)
vigil scan . --scope sca            # Run SCA only (skips Secrets, IaC, and Licences)
vigil scan . --scope all            # Run all assessment stages (default)
vigil scan . --progress plain       # Stream stage completion lines to stderr
```
