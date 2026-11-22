# ADR 013: Explainable Security Decisions, Baseline Delta, and Policy as Code

## Status

Accepted (2026-11-22)

## Context

Counting CVEs alone does not give engineering teams enough information to decide whether a release should pass, require manual review, or be blocked. Previous versions of Vigil coupled raw vulnerability counts directly to UI/CI decisions and lacked a structured way to distinguish newly introduced risks from accepted baselines or to audit why a finding triggered a gate.

## Decision

Introduce a dedicated `internal/policy` domain layer sitting strictly between canonical scan evidence and CLI/CI presentation:

1. **Canonical Finding Model (`policy.Finding`)**: normalises vulnerability identity (CVE + aliases), provenance (`Sources`), severity, dependency scope (`production`/`development`, `direct`/`transitive`), evidence-based runtime exploitability, and an explicit `MissingEvidence` list (for example, call-graph reachability and runtime deployment exposure).
2. **Baseline & Delta Analysis (`policy.Baseline`, `policy.ComputeDelta`)**: enables teams to snapshot accepted findings via `vigil baseline` and evaluate only newly introduced findings alongside resolved regressions.
3. **Declarative Policy as Code (`policy.Policy`)**: typed YAML rules (`ALLOW` / `REVIEW` / `BLOCK`) with mandatory-metadata, time-bounded exceptions (`id`, `owner`, `reason`, `expires_at`). Expired exceptions never suppress findings and are explicitly surfaced in decision reasoning.
4. **Explainable Release Gate (`vigil explain <vuln-id>`)**: prints the exact policy decision, matched rule, step-by-step reasoning, and missing evidence for any finding in text or JSON format.

## Consequences

- Security decisions are deterministic and reproducible for the same scan snapshot, policy file, and baseline.
- UI layers never decide what is safe; external APIs supply evidence while policy rules own decisions.
- No external rule-engine DSL (such as OPA/Rego) is required at this stage; simple typed YAML keeps maintenance low and auditability high.
