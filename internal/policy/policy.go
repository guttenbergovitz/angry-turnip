package policy

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
	"gopkg.in/yaml.v3"
)

// Decision represents an auditable security gate outcome.
type Decision string

const (
	DecisionAllow  Decision = "ALLOW"
	DecisionReview Decision = "REVIEW"
	DecisionBlock  Decision = "BLOCK"
)

// EvidenceState describes the completeness and reliability of scan evidence independently
// from the policy decision.
type EvidenceState string

const (
	EvidenceComplete   EvidenceState = "COMPLETE"
	EvidencePartial    EvidenceState = "PARTIAL"
	EvidenceUnverified EvidenceState = "UNVERIFIED"
	EvidenceInvalid    EvidenceState = "INVALID"
)

// Rule defines a declarative policy rule evaluated against canonical findings.
type Rule struct {
	Name           string         `yaml:"name" json:"name"`
	Decision       Decision       `yaml:"decision" json:"decision"`
	MinSeverity    types.Severity `yaml:"min_severity,omitempty" json:"min_severity,omitempty"`
	MatchSeverity  types.Severity `yaml:"match_severity,omitempty" json:"match_severity,omitempty"`
	MinCVSS        float64        `yaml:"min_cvss,omitempty" json:"min_cvss,omitempty"`
	KnownExploited *bool          `yaml:"known_exploited,omitempty" json:"known_exploited,omitempty"`
	MinEPSS        float64        `yaml:"min_epss,omitempty" json:"min_epss,omitempty"`
	ProductionOnly bool           `yaml:"production_only,omitempty" json:"production_only,omitempty"`
	NewOnly        bool           `yaml:"new_only,omitempty" json:"new_only,omitempty"`
	Description    string         `yaml:"description,omitempty" json:"description,omitempty"`
}

// Exception defines a scoped, owned, time-bounded risk acceptance for a specific vulnerability.
// Every exception must explicitly declare its scope: either Package + (Version or AllVersions: true),
// or Global: true. Omitting scope fields is rejected so wildcard exceptions can never occur by accident.
type Exception struct {
	ID          string         `yaml:"id" json:"id"`
	Package     string         `yaml:"package,omitempty" json:"package,omitempty"`
	Version     string         `yaml:"version,omitempty" json:"version,omitempty"`
	AllVersions bool           `yaml:"all_versions,omitempty" json:"all_versions,omitempty"`
	Global      bool           `yaml:"global,omitempty" json:"global,omitempty"`
	Ecosystem   string         `yaml:"ecosystem,omitempty" json:"ecosystem,omitempty"`
	MaxSeverity types.Severity `yaml:"max_severity,omitempty" json:"max_severity,omitempty"`
	ApprovalID  string         `yaml:"approval_id,omitempty" json:"approval_id,omitempty"`
	Owner       string         `yaml:"owner" json:"owner"`
	Reason      string         `yaml:"reason" json:"reason"`
	ExpiresAt   string         `yaml:"expires_at" json:"expires_at"`
}

// Policy defines declarative security gate rules and scoped exceptions.
type Policy struct {
	Version                  int         `yaml:"version" json:"version"`
	StrictExceptions         bool        `yaml:"strict_exceptions,omitempty" json:"strict_exceptions,omitempty"`
	FailOnScanError          *bool       `yaml:"fail_on_scan_error,omitempty" json:"fail_on_scan_error,omitempty"`
	FailOnUnsupported        *bool       `yaml:"fail_on_unsupported,omitempty" json:"fail_on_unsupported,omitempty"`
	OnThreatIntelUnavailable Decision    `yaml:"on_threat_intel_unavailable,omitempty" json:"on_threat_intel_unavailable,omitempty"`
	OnResolutionIncomplete   Decision    `yaml:"on_resolution_incomplete,omitempty" json:"on_resolution_incomplete,omitempty"`
	Rules                    []Rule      `yaml:"rules" json:"rules"`
	Exceptions               []Exception `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// FindingDecision records the deterministic policy decision and reasoning for a single Finding.
type FindingDecision struct {
	Finding          Finding    `json:"finding"`
	Decision         Decision   `json:"decision"`
	AcceptedRisk     bool       `json:"accepted_risk,omitempty"`
	MatchedRule      string     `json:"matched_rule,omitempty"`
	IsNew            bool       `json:"is_new"`
	Exception        *Exception `json:"exception,omitempty"`
	ExpiredException *Exception `json:"expired_exception,omitempty"`
	Reasoning        []string   `json:"reasoning"`
}

// EvaluationResult aggregates all finding decisions alongside independent evidence validation.
type EvaluationResult struct {
	OverallDecision         Decision                   `json:"overall_decision"`
	EvidenceState           EvidenceState              `json:"evidence_state"`
	ResolutionScope         string                     `json:"resolution_scope,omitempty"`
	Resolution              *types.ResolutionEvidence  `json:"resolution,omitempty"`
	EvidenceNotes           []string                   `json:"evidence_notes,omitempty"`
	ThreatIntel             *types.ThreatIntelMetadata `json:"threat_intel,omitempty"`
	BaselineScopeCompatible *bool                      `json:"baseline_scope_compatible,omitempty"`
	ScopeExclusions         int                        `json:"scope_exclusions,omitempty"`
	PolicyVersion           int                        `json:"policy_version"`
	Decisions               []FindingDecision          `json:"decisions"`
	BlockCount              int                        `json:"block_count"`
	ReviewCount             int                        `json:"review_count"`
	AllowCount              int                        `json:"allow_count"`
	SuppressedCount         int                        `json:"suppressed_count"`
	ExpiredExceptions       int                        `json:"expired_exceptions"`
	ScanIncomplete          bool                       `json:"scan_incomplete"`
	FailedPackages          int                        `json:"failed_packages"`
	UnsupportedPackages     int                        `json:"unsupported_packages"`
}

// DefaultPolicy returns Vigil's built-in deterministic security policy.
// Known HIGH vulnerabilities in production remain subject to REVIEW unless formally
// accepted via an active, scoped exception. Actively exploited (CISA KEV) production
// vulnerabilities are blocked regardless of severity.
func DefaultPolicy() Policy {
	failOnError := true
	failOnUnsupported := true
	kevTrue := true
	return Policy{
		Version:           1,
		FailOnScanError:   &failOnError,
		FailOnUnsupported: &failOnUnsupported,
		Rules: []Rule{
			{
				Name:           "threat-intel/kev-block",
				Decision:       DecisionBlock,
				KnownExploited: &kevTrue,
				ProductionOnly: true,
				Description:    "Block releases with production vulnerabilities listed in CISA KEV (actively exploited).",
			},
			{
				Name:           "production/critical-block",
				Decision:       DecisionBlock,
				MinSeverity:    types.Critical,
				ProductionOnly: true,
				Description:    "Block releases with CRITICAL vulnerabilities in production dependencies.",
			},
			{
				Name:           "production/high-review",
				Decision:       DecisionReview,
				MinSeverity:    types.High,
				ProductionOnly: true,
				Description:    "Require manual review for HIGH vulnerabilities in production dependencies unless formally accepted.",
			},
			{
				Name:          "severity/unknown-review",
				Decision:      DecisionReview,
				MatchSeverity: types.Unknown,
				Description:   "Require manual review when upstream advisory severity is unknown.",
			},
		},
	}
}

// PolicyFromThresholds constructs a Policy from CLI severity and CVSS threshold flags so
// all CI evaluations run through the single policy engine.
func PolicyFromThresholds(minSev types.Severity, failOnCVSS float64, failOnScanError, failOnUnsupported bool) Policy {
	rules := []Rule{
		{
			Name:        fmt.Sprintf("threshold/severity-%s", minSev),
			Decision:    DecisionBlock,
			MinSeverity: minSev,
			Description: fmt.Sprintf("Block when any vulnerability has severity %s or higher.", strings.ToUpper(string(minSev))),
		},
	}
	if failOnCVSS > 0.0 {
		rules = append(rules, Rule{
			Name:        fmt.Sprintf("threshold/cvss-%.1f", failOnCVSS),
			Decision:    DecisionBlock,
			MinCVSS:     failOnCVSS,
			Description: fmt.Sprintf("Block when any vulnerability has CVSS >= %.1f.", failOnCVSS),
		})
	}
	return Policy{
		Version:           1,
		FailOnScanError:   &failOnScanError,
		FailOnUnsupported: &failOnUnsupported,
		Rules:             rules,
	}
}

// LoadPolicy reads and strictly validates a YAML policy file from disk.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy strictly decodes and validates YAML policy bytes, rejecting unknown fields,
// unsupported schema versions, empty rule sets, out-of-range CVSS scores, and unscoped exceptions.
func ParsePolicy(data []byte) (Policy, error) {
	var pol Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pol); err != nil {
		if err == io.EOF {
			return Policy{}, fmt.Errorf("policy YAML is empty")
		}
		return Policy{}, fmt.Errorf("parse policy YAML: %w", err)
	}

	if pol.Version != 1 {
		return Policy{}, fmt.Errorf("unsupported or missing policy schema version %d (expected version: 1)", pol.Version)
	}

	if len(pol.Rules) == 0 {
		return Policy{}, fmt.Errorf("policy must declare at least one rule")
	}

	if pol.OnThreatIntelUnavailable != "" {
		pol.OnThreatIntelUnavailable = Decision(strings.ToUpper(strings.TrimSpace(string(pol.OnThreatIntelUnavailable))))
		switch pol.OnThreatIntelUnavailable {
		case DecisionAllow, DecisionReview, DecisionBlock:
		default:
			return Policy{}, fmt.Errorf("invalid on_threat_intel_unavailable %q (allowed: ALLOW, REVIEW, BLOCK)", pol.OnThreatIntelUnavailable)
		}
	}

	if pol.OnResolutionIncomplete != "" {
		pol.OnResolutionIncomplete = Decision(strings.ToUpper(strings.TrimSpace(string(pol.OnResolutionIncomplete))))
		switch pol.OnResolutionIncomplete {
		case DecisionAllow, DecisionReview, DecisionBlock:
		default:
			return Policy{}, fmt.Errorf("invalid on_resolution_incomplete %q (allowed: ALLOW, REVIEW, BLOCK)", pol.OnResolutionIncomplete)
		}
	}

	for i := range pol.Rules {
		r := &pol.Rules[i]
		if strings.TrimSpace(r.Name) == "" {
			return Policy{}, fmt.Errorf("rule #%d is missing required field 'name'", i+1)
		}
		r.Decision = Decision(strings.ToUpper(strings.TrimSpace(string(r.Decision))))
		switch r.Decision {
		case DecisionAllow, DecisionReview, DecisionBlock:
		default:
			return Policy{}, fmt.Errorf("rule %q has invalid decision %q (allowed: ALLOW, REVIEW, BLOCK)", r.Name, r.Decision)
		}
		if r.MinCVSS < 0.0 || r.MinCVSS > 10.0 {
			return Policy{}, fmt.Errorf("rule %q has out-of-range min_cvss %.2f (must be between 0.0 and 10.0)", r.Name, r.MinCVSS)
		}
		if r.MinEPSS < 0.0 || r.MinEPSS > 1.0 {
			return Policy{}, fmt.Errorf("rule %q has out-of-range min_epss %.4f (must be between 0.0 and 1.0)", r.Name, r.MinEPSS)
		}
		if r.MinSeverity != "" {
			sev, ok := types.ParseSeverity(string(r.MinSeverity))
			if !ok {
				return Policy{}, fmt.Errorf("rule %q has invalid min_severity %q", r.Name, r.MinSeverity)
			}
			r.MinSeverity = sev
		}
		if r.MatchSeverity != "" {
			sev, ok := types.ParseSeverity(string(r.MatchSeverity))
			if !ok {
				return Policy{}, fmt.Errorf("rule %q has invalid match_severity %q", r.Name, r.MatchSeverity)
			}
			r.MatchSeverity = sev
		}
		if r.MinSeverity != "" && r.MatchSeverity != "" && !r.MatchSeverity.HigherOrEqualThan(r.MinSeverity) {
			return Policy{}, fmt.Errorf("rule %q has contradictory min_severity (%s) and match_severity (%s)", r.Name, r.MinSeverity, r.MatchSeverity)
		}
	}

	for i := range pol.Exceptions {
		ex := &pol.Exceptions[i]
		if strings.TrimSpace(ex.ID) == "" {
			return Policy{}, fmt.Errorf("exception #%d is missing required field 'id'", i+1)
		}
		if strings.TrimSpace(ex.Owner) == "" {
			return Policy{}, fmt.Errorf("exception %q is missing required field 'owner'", ex.ID)
		}
		if strings.TrimSpace(ex.Reason) == "" {
			return Policy{}, fmt.Errorf("exception %q is missing required field 'reason'", ex.ID)
		}
		if pol.StrictExceptions && strings.TrimSpace(ex.ApprovalID) == "" {
			return Policy{}, fmt.Errorf("exception %q is missing required 'approval_id' (strict_exceptions is enabled)", ex.ID)
		}
		// Require explicit scope: either global: true OR package + (version or all_versions: true).
		if !ex.Global {
			if strings.TrimSpace(ex.Package) == "" {
				return Policy{}, fmt.Errorf("exception %q must specify 'package' (or explicitly set 'global: true')", ex.ID)
			}
			if strings.TrimSpace(ex.Version) == "" && !ex.AllVersions {
				return Policy{}, fmt.Errorf("exception %q for package %q must specify 'version' (or explicitly set 'all_versions: true')", ex.ID, ex.Package)
			}
		}
		if ex.MaxSeverity != "" {
			sev, ok := types.ParseSeverity(string(ex.MaxSeverity))
			if !ok || sev == types.Unknown {
				return Policy{}, fmt.Errorf("exception %q has invalid max_severity %q", ex.ID, ex.MaxSeverity)
			}
			ex.MaxSeverity = sev
		}
		if _, err := parseExpiry(ex.ExpiresAt); err != nil {
			return Policy{}, fmt.Errorf("exception %q has invalid expires_at %q: %w", ex.ID, ex.ExpiresAt, err)
		}
	}

	return pol, nil
}

// ValidateEvidence inspects scan coverage invariants against the actual dependency list and
// returns an independent EvidenceState. Intentional scope exclusions (SkippedPackages) are
// reported separately from coverage failures (FailedPackages and UnsupportedPackages), while
// zero-scanned (all-skipped) scans are treated as EvidenceUnverified rather than EvidenceComplete.
func ValidateEvidence(result *types.ScanResult) (EvidenceState, []string) {
	if result == nil {
		return EvidenceInvalid, []string{"Scan result is missing."}
	}

	c := result.Coverage
	if c.TotalPackages < 0 || c.ScannedPackages < 0 || c.FailedPackages < 0 || c.SkippedPackages < 0 || c.UnsupportedPackages < 0 {
		return EvidenceInvalid, []string{"Scan coverage contains negative counters."}
	}

	sum := c.ScannedPackages + c.FailedPackages + c.SkippedPackages + c.UnsupportedPackages
	if c.TotalPackages > 0 && sum != c.TotalPackages {
		return EvidenceInvalid, []string{fmt.Sprintf("Inconsistent scan coverage counters: scanned(%d)+failed(%d)+skipped(%d)+unsupported(%d) != total(%d).",
			c.ScannedPackages, c.FailedPackages, c.SkippedPackages, c.UnsupportedPackages, c.TotalPackages)}
	}
	if c.TotalPackages == 0 && sum > 0 {
		return EvidenceInvalid, []string{"Inconsistent scan coverage: total_packages is 0 while status counters are non-zero."}
	}
	if c.TotalPackages == 0 && len(result.Dependencies) == 0 {
		return EvidenceUnverified, []string{"No dependencies were evaluated in this scan."}
	}

	// Cross-check actual dependency statuses and component identity uniqueness against Coverage.
	var actualScanned, actualFailed, actualSkipped, actualUnsupported int
	seenPURLs := make(map[string]bool, len(result.Dependencies))

	for _, dep := range result.Dependencies {
		purl := BuildPURL(dep.Ecosystem, dep.Name, dep.Version)
		if seenPURLs[purl] {
			return EvidenceInvalid, []string{fmt.Sprintf("Duplicate dependency identity in scan result: %s.", purl)}
		}
		seenPURLs[purl] = true

		switch dep.ScanStatus {
		case types.StatusScanned:
			actualScanned++
		case types.StatusFailed:
			actualFailed++
		case types.StatusSkipped:
			actualSkipped++
		case types.StatusUnsupported:
			actualUnsupported++
		default:
			return EvidenceInvalid, []string{fmt.Sprintf("Dependency %s has unknown or missing scan status %q.", purl, dep.ScanStatus)}
		}
	}

	if len(result.Dependencies) > c.TotalPackages {
		return EvidenceInvalid, []string{fmt.Sprintf("Inconsistent scan coverage: %d dependencies present but total_packages is %d.",
			len(result.Dependencies), c.TotalPackages)}
	}
	if actualScanned != c.ScannedPackages || actualFailed != c.FailedPackages || actualUnsupported != c.UnsupportedPackages || c.SkippedPackages < actualSkipped {
		return EvidenceInvalid, []string{fmt.Sprintf("Scan coverage counters do not match actual dependency statuses (reported scanned=%d failed=%d unsupported=%d skipped=%d; actual scanned=%d failed=%d unsupported=%d skipped=%d).",
			c.ScannedPackages, c.FailedPackages, c.UnsupportedPackages, c.SkippedPackages,
			actualScanned, actualFailed, actualUnsupported, actualSkipped)}
	}

	var notes []string
	switch c.ResolutionScope {
	case "partial-pom":
		notes = append(notes, "Resolution scope: partial POM resolution (direct declarations and local parent POMs only; transitive Maven dependencies are not resolved without a lockfile).")
	case "go-mod-manifest":
		notes = append(notes, "Resolution scope: go.mod module requirement graph (static modfile analysis without full Go toolchain MVS build list).")
	case "flat-manifest":
		notes = append(notes, "Resolution scope: flat requirements.txt manifest (direct pinned requirements only; transitive dependencies are not declared).")
	case "flat-lockfile":
		notes = append(notes, "Resolution scope: flat lockfile without parent-child dependency graph edges.")
	}
	for _, lim := range result.Resolution.Limitations {
		notes = append(notes, lim)
	}
	if c.FailedPackages > 0 {
		notes = append(notes, fmt.Sprintf("%d package(s) failed vulnerability lookup.", c.FailedPackages))
	}
	if c.UnsupportedPackages > 0 {
		notes = append(notes, fmt.Sprintf("%d package(s) could not be resolved or are unsupported.", c.UnsupportedPackages))
	}
	if c.SkippedPackages > 0 {
		notes = append(notes, fmt.Sprintf("%d package(s) were intentionally excluded from scope (for example via --skip-devdeps).", c.SkippedPackages))
	}

	if c.FailedPackages > 0 || c.UnsupportedPackages > 0 {
		return EvidencePartial, notes
	}

	// A scan consisting solely of scope exclusions has zero verified packages.
	if c.ScannedPackages == 0 {
		notes = append(notes, "Zero packages were evaluated (all dependencies were excluded from scope).")
		return EvidenceUnverified, notes
	}

	return EvidenceComplete, notes
}

// Evaluate deterministically evaluates a ScanResult against a Policy and optional Baseline.
func Evaluate(result *types.ScanResult, pol Policy, baseline *Baseline, now time.Time) EvaluationResult {
	evidenceState, evidenceNotes := ValidateEvidence(result)
	findings := BuildFindings(result)

	eval := EvaluationResult{
		OverallDecision: DecisionAllow,
		EvidenceState:   evidenceState,
		EvidenceNotes:   evidenceNotes,
		PolicyVersion:   pol.Version,
		Decisions:       make([]FindingDecision, 0, len(findings)),
	}

	effectiveBaseline := baseline
	baselineIncompatible := false

	if result != nil {
		eval.ResolutionScope = result.Coverage.ResolutionScope
		if result.Resolution.InputKind != "" || result.Resolution.Completeness != "" || len(result.Resolution.Ambiguous) > 0 || len(result.Resolution.Unresolved) > 0 {
			resCopy := result.Resolution
			eval.Resolution = &resCopy
		}
		eval.FailedPackages = result.Coverage.FailedPackages
		eval.UnsupportedPackages = result.Coverage.UnsupportedPackages
		eval.ScopeExclusions = result.Coverage.SkippedPackages

		if result.ThreatIntel.KEV.Status != "" || result.ThreatIntel.EPSS.Status != "" {
			ti := result.ThreatIntel
			eval.ThreatIntel = &ti
			if ti.KEV.Status == types.EnrichmentFailed {
				eval.EvidenceNotes = append(eval.EvidenceNotes, fmt.Sprintf("Threat intelligence enrichment failed for CISA KEV: %s", ti.KEV.Error))
			}
			if ti.EPSS.Status == types.EnrichmentFailed {
				eval.EvidenceNotes = append(eval.EvidenceNotes, fmt.Sprintf("Threat intelligence enrichment failed for FIRST EPSS: %s", ti.EPSS.Error))
			}
		}

		if baseline != nil {
			compatible, scopeWarnings, _, _ := CompareBaselineScope(result, baseline)
			eval.BaselineScopeCompatible = &compatible
			eval.EvidenceNotes = append(eval.EvidenceNotes, scopeWarnings...)
			if !compatible {
				// Reject an incompatible baseline for delta classification so new_only rules
				// can never be bypassed by comparing against a different scan configuration.
				effectiveBaseline = nil
				baselineIncompatible = true
			}
		}
	}

	delta := ComputeDelta(findings, ScannedPURLSet(result), effectiveBaseline)
	newSet := make(map[string]bool, len(delta.New))
	for _, f := range delta.New {
		newSet[f.Key] = true
	}

	failOnScanError := true
	if pol.FailOnScanError != nil {
		failOnScanError = *pol.FailOnScanError
	}
	failOnUnsupported := true
	if pol.FailOnUnsupported != nil {
		failOnUnsupported = *pol.FailOnUnsupported
	}

	if (failOnScanError && eval.FailedPackages > 0) || (failOnUnsupported && eval.UnsupportedPackages > 0) {
		eval.ScanIncomplete = true
	}

	for _, f := range findings {
		isNew := newSet[f.Key]
		fd := evaluateFinding(f, pol, effectiveBaseline != nil, baselineIncompatible, isNew, now)
		eval.Decisions = append(eval.Decisions, fd)

		if fd.Exception != nil {
			eval.SuppressedCount++
		}
		if fd.ExpiredException != nil {
			eval.ExpiredExceptions++
		}

		switch fd.Decision {
		case DecisionBlock:
			eval.BlockCount++
		case DecisionReview:
			eval.ReviewCount++
		default:
			eval.AllowCount++
		}

		eval.OverallDecision = higherDecision(eval.OverallDecision, fd.Decision)
	}

	if baselineIncompatible {
		eval.OverallDecision = higherDecision(eval.OverallDecision, DecisionReview)
	}

	// Enforce resolution completeness policy: ambiguous or unresolved dependency edges
	// cannot silently pass as ALLOW unless on_resolution_incomplete: ALLOW is explicitly set.
	if result != nil {
		resComp := result.Resolution.Completeness
		hasGraphDefects := resComp == types.ResolutionAmbiguous || len(result.Resolution.Ambiguous) > 0 || len(result.Resolution.Unresolved) > 0
		if pol.OnResolutionIncomplete != "" && ((resComp != "" && resComp != types.ResolutionComplete) || hasGraphDefects) {
			eval.OverallDecision = higherDecision(eval.OverallDecision, pol.OnResolutionIncomplete)
		} else if pol.OnResolutionIncomplete == "" && hasGraphDefects {
			eval.OverallDecision = higherDecision(eval.OverallDecision, DecisionReview)
		}
	}

	// Incomplete, unverified, or invalid evidence always overrides finding-level ALLOW / exceptions.
	if eval.ScanIncomplete || eval.EvidenceState == EvidenceInvalid || eval.EvidenceState == EvidenceUnverified {
		eval.OverallDecision = DecisionBlock
	}

	return eval
}

func evaluateFinding(f Finding, pol Policy, hasBaseline, baselineIncompatible, isNew bool, now time.Time) FindingDecision {
	fd := FindingDecision{
		Finding:  f,
		Decision: DecisionAllow,
		IsNew:    isNew,
	}

	if baselineIncompatible {
		fd.Reasoning = append(fd.Reasoning, "Baseline rejected for delta comparison due to incompatible scan configuration; evaluated as new.")
	} else if hasBaseline {
		if isNew {
			fd.Reasoning = append(fd.Reasoning, "New vulnerability introduced since baseline.")
		} else {
			fd.Reasoning = append(fd.Reasoning, "Vulnerability was previously observed in baseline (not automatically accepted).")
		}
	} else {
		fd.Reasoning = append(fd.Reasoning, "Evaluated without a baseline snapshot (treated as new).")
	}

	fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Runtime exploitability is %s (confidence: %s): %s",
		f.Exploitability.Status, f.Exploitability.Confidence, f.Exploitability.Rationale))

	needsKEV := false
	needsEPSS := false
	for _, rule := range pol.Rules {
		if rule.KnownExploited != nil {
			needsKEV = true
		}
		if rule.MinEPSS > 0 {
			needsEPSS = true
		}
		if !ruleMatches(rule, f, isNew) {
			continue
		}
		if decisionRank(rule.Decision) > decisionRank(fd.Decision) || fd.MatchedRule == "" {
			fd.Decision = rule.Decision
			fd.MatchedRule = rule.Name
		}
		if rule.Description != "" {
			fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Matched rule %q (%s): %s", rule.Name, rule.Decision, rule.Description))
		} else {
			fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Matched rule %q (%s).", rule.Name, rule.Decision))
		}
	}

	kevUnverified := needsKEV && isThreatIntelUnverified(f.ID, f.KEVStatus)
	epssUnverified := needsEPSS && isThreatIntelUnverified(f.ID, f.EPSSStatus)
	if kevUnverified || epssUnverified {
		var unverifiedSources []string
		if kevUnverified {
			unverifiedSources = append(unverifiedSources, fmt.Sprintf("CISA KEV (%s)", f.KEVStatus))
		}
		if epssUnverified {
			unverifiedSources = append(unverifiedSources, fmt.Sprintf("FIRST EPSS (%s)", f.EPSSStatus))
		}
		fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Threat intelligence unverified [%s]; absence of query or lookup failure is not negative proof.", strings.Join(unverifiedSources, ", ")))

		fallbackDecision := pol.OnThreatIntelUnavailable
		if fallbackDecision == "" {
			// Default to REVIEW when threat intelligence was explicitly marked failed or not_requested
			// for a CVE finding while KEV/EPSS rules are active, preventing silent ALLOW.
			fallbackDecision = DecisionReview
		}
		if decisionRank(fallbackDecision) > decisionRank(fd.Decision) {
			fd.Decision = fallbackDecision
			fd.MatchedRule = "threat-intel/unavailable"
		}
	}

	for i := range pol.Exceptions {
		ex := pol.Exceptions[i]
		if !exceptionMatchesScope(ex, f) {
			continue
		}
		if ex.MaxSeverity != "" && !ex.MaxSeverity.HigherOrEqualThan(f.Severity) {
			fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Exception %q does not apply: finding severity %s exceeds exception max_severity %s.",
				ex.ID, strings.ToUpper(string(f.Severity)), strings.ToUpper(string(ex.MaxSeverity))))
			continue
		}
		expiry, err := parseExpiry(ex.ExpiresAt)
		if err == nil && !now.After(expiry) {
			exCopy := ex
			fd.Exception = &exCopy
			fd.AcceptedRisk = true
			fd.Decision = DecisionAllow
			fd.MatchedRule = "exception/" + ex.ID
			approval := ""
			if ex.ApprovalID != "" {
				approval = fmt.Sprintf(" [approval: %s]", ex.ApprovalID)
			}
			fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Formally accepted risk (not proof of safety) via exception owned by %s until %s%s: %s",
				ex.Owner, ex.ExpiresAt, approval, ex.Reason))
			return fd
		}
		exCopy := ex
		fd.ExpiredException = &exCopy
		fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Exception owned by %s expired on %s and no longer suppresses this finding.", ex.Owner, ex.ExpiresAt))
	}

	if fd.MatchedRule == "" {
		fd.Reasoning = append(fd.Reasoning, "No blocking or review policy rule matched; allowed by default.")
	}

	return fd
}

func ruleMatches(rule Rule, f Finding, isNew bool) bool {
	if rule.ProductionOnly && f.DependencyType != types.Production {
		return false
	}
	if rule.NewOnly && !isNew {
		return false
	}
	if rule.MatchSeverity != "" && f.Severity != rule.MatchSeverity {
		return false
	}
	if rule.MinSeverity != "" && !f.Severity.HigherOrEqualThan(rule.MinSeverity) {
		return false
	}
	if rule.MinCVSS > 0 && f.CVSSScore < rule.MinCVSS {
		return false
	}
	if rule.KnownExploited != nil {
		// Neither failed nor not_requested constitutes proof of absence or presence.
		if f.KEVStatus == types.EnrichmentFailed || f.KEVStatus == types.EnrichmentNotRequested {
			return false
		}
		if !*rule.KnownExploited && f.KEVStatus != types.EnrichmentNotFound {
			return false
		}
		if f.KnownExploited != *rule.KnownExploited {
			return false
		}
	}
	if rule.MinEPSS > 0 {
		if f.EPSSStatus == types.EnrichmentFailed || f.EPSSStatus == types.EnrichmentNotRequested || f.EPSSScore < rule.MinEPSS {
			return false
		}
	}
	return true
}

func isThreatIntelUnverified(advisoryID string, status types.EnrichmentStatus) bool {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(advisoryID)), "CVE-") {
		return false
	}
	return status == types.EnrichmentFailed || status == types.EnrichmentNotRequested
}

func exceptionMatchesScope(ex Exception, f Finding) bool {
	if !f.MatchesID(ex.ID) {
		return false
	}
	if !ex.Global {
		if !strings.EqualFold(ex.Package, f.Package) {
			return false
		}
		if !ex.AllVersions && ex.Version != f.Version {
			return false
		}
	}
	if ex.Ecosystem != "" && !strings.EqualFold(ex.Ecosystem, string(f.Ecosystem)) {
		return false
	}
	return true
}

func parseExpiry(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, fmt.Errorf("expires_at is required")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Nanosecond), nil
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD date")
}

func decisionRank(d Decision) int {
	switch d {
	case DecisionBlock:
		return 3
	case DecisionReview:
		return 2
	default:
		return 1
	}
}

func higherDecision(a, b Decision) Decision {
	if decisionRank(b) > decisionRank(a) {
		return b
	}
	return a
}
