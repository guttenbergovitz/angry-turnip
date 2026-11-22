# Understanding Reports

Guide to interpreting Angry Turnip (`atnp`) output.

## Severity Levels

| Level    | CVSS Score | Description | Typical Action |
|----------|------------|-------------|----------------|
| CRITICAL | 9.0-10.0   | Immediate exploitation risk | Hotfix required |
| HIGH     | 7.0-8.9    | Significant security impact | Review / fix next release |
| MEDIUM   | 4.0-6.9    | Moderate security risk | Plan remediation |
| LOW      | 0.1-3.9    | Minor security concern | Monitor, fix when convenient |
| UNKNOWN  | N/A        | Severity not reported by advisory | Manual review required |

## Exploit Types

**RCE (Remote Code Execution)**
- Attacker can execute arbitrary code
- Most severe exploit type
- Often leads to full system compromise

**Injection (SQL, XSS, Command)**
- Malicious input executes unintended operations
- SQL injection: database manipulation
- XSS: client-side script injection
- Command injection: OS command execution

**Auth Bypass**
- Authentication or authorisation circumvented
- Privilege escalation risks
- Unauthorised access to resources

**DoS (Denial of Service)**
- Service availability disrupted
- Resource exhaustion attacks
- Regular expression DoS (ReDoS)

**Data Leak**
- Sensitive information exposed
- Path traversal, directory listing
- Information disclosure

**Logic Error**
- Business logic flaws
- Race conditions, timing attacks
- Prototype pollution

## Exploitability Assessment

Static lock file analysis cannot prove runtime reachability or deployment exposure on its own. Angry Turnip therefore reports evidence-based exploitability states with explicit rationale rather than categorical `yes`/`no` claims:

**potentially_exploitable**
- Advisory signals (such as CVSS `AV:N` network attack vector or `AC:L` low attack complexity) indicate potential exposure
- Confidence is low until call-graph reachability and deployment configuration are verified

**unknown**
- Available advisory metadata does not establish runtime reachability or deployment exposure
- Manual triage is required to confirm impact

**confirmed_not_affected**
- Verified evidence demonstrates that the vulnerable code path is not affected in this deployment

## Recommended Actions

**Immediate hotfix**
- Critical/High severity in production
- Exploit available and easily triggered
- Deploy fix within 24-48 hours

**Upgrade next release**
- High/Medium severity
- Conditional exploitability
- Include in next planned release

**Infra mitigation required**
- Cannot patch immediately
- Deploy WAF rules, rate limiting
- Monitor for exploitation attempts

**Monitoring only**
- Low severity or dev dependencies
- No immediate action required
- Track for future updates

**Risk acceptance candidate**
- Very low severity
- Fix unavailable or high effort
- Document in risk register

## Release Gate Recommendations

**✅ Release can proceed**
- No Critical findings
- High findings in dev dependencies only or mitigated
- Acceptable risk profile for production

**⚠️ Release allowed with mitigations**
- High findings with compensating controls
- Deploy with monitoring/WAF rules
- Documented risk acceptance
- Remediation planned for next sprint

**❌ Release must be blocked**
- Critical findings in production dependencies
- Highly exploitable vulnerabilities
- No acceptable mitigation available
- Fixes required before deployment

## Dependency Paths

Vulnerability paths show transitive dependency chains for all lock file types (npm, Yarn, pnpm):

```
express@4.18.2 → semver@7.3.5
```

- `express@4.18.2` - Direct dependency
- `semver@7.3.5` - Vulnerable transitive dependency

Longer paths indicate deep transitive dependencies:

```
next@14.0.0 → webpack@5.88.0 → terser@5.19.2
```

Fix by updating root dependency (`next`) which pulls in fixed version.

All lock file formats now provide full dependency chain visibility.

## CVSS Vectors

CVSS vector strings encode vulnerability characteristics:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Meaning |
|--------|-------|---------|
| AV | N | Attack Vector: Network |
| AC | L | Attack Complexity: Low |
| PR | N | Privileges Required: None |
| UI | N | User Interaction: None |
| S | U | Scope: Unchanged |
| C | H | Confidentiality Impact: High |
| I | H | Integrity Impact: High |
| A | H | Availability Impact: High |

Higher severity when:
- AV:N (network accessible)
- AC:L (low complexity)
- PR:N (no privileges required)
- C/I/A:H (high impact)

## CVSS Score Sources

Angry Turnip enriches CVSS from multiple authoritative sources:

1. **NVD API** (CVE-* IDs) - Most authoritative for CVEs
2. **GitHub Security Advisories** (GHSA-* IDs) - Comprehensive GHSA data
3. **OSV API** - Community-sourced scores
4. **Derived from severity** - Fallback calculation

Source priority ensures accurate risk assessment.

## Temporal Metadata

Package release dates and advisory publication dates are retained strictly as informational metadata. Angry Turnip does **not** filter or discard vulnerabilities published before a package release date, because an unpatched vulnerability disclosed prior to a release can still affect subsequent releases until fixed.

## Production vs Development Dependencies

**Production dependencies:**
- Included in final application bundle or runtime module graph
- In Go (`go.mod`), both direct and `// indirect` requirements are classified as production dependencies (`// indirect` indicates a transitive dependency, not a development-only dependency)
- Higher risk priority

**Development dependencies:**
- Build tools and test frameworks explicitly scoped to development/test
- Lower risk priority (still scanned by default)

Use `--skip-devdeps` to exclude development-scoped dependencies.

## Risk Scoring

Angry Turnip calculates 0-100 risk score based on:

- **Base**: CVSS severity score
- **+20**: Production dependency
- **+15**: Public exploit available
- **+10**: Popular package (>1M downloads/week)
- **-10**: Fix available in current version range
- **-20**: Optional/dev dependency

Higher risk score = higher priority remediation.

## Interpreting Security Report

Security format includes:

**1. Executive Risk Summary**
- Total findings by severity
- Production-exploitable count
- Release blocker identification

**2. Vulnerability Details**
- Grouped by severity
- Technical analysis per vuln
- Dependency paths
- Recommended actions

**3. Systemic Risk Signals**
- Repeated vulnerabilities across dependencies
- Hot clusters (many vulns in one package)
- Critical layer impacts (auth, crypto, network)

**4. Release Gate Recommendation**
- Go/no-go decision
- Technical justification
- Mitigation requirements

Use for stakeholder communication and release decisions.

## Next Steps

- [Commands](commands.md) - CLI reference
- [Troubleshooting](troubleshooting.md) - Common issues
- [Examples](../getting-started/examples.md) - Practical workflows
