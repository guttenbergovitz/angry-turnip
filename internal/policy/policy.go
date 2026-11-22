package policy

import (
	"fmt"
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

// Rule defines a declarative policy rule evaluated against canonical findings.
type Rule struct {
	Name           string         `yaml:"name" json:"name"`
	Decision       Decision       `yaml:"decision" json:"decision"`
	MinSeverity    types.Severity `yaml:"min_severity,omitempty" json:"min_severity,omitempty"`
	MatchSeverity  types.Severity `yaml:"match_severity,omitempty" json:"match_severity,omitempty"`
	MinCVSS        float64        `yaml:"min_cvss,omitempty" json:"min_cvss,omitempty"`
	ProductionOnly bool           `yaml:"production_only,omitempty" json:"production_only,omitempty"`
	NewOnly        bool           `yaml:"new_only,omitempty" json:"new_only,omitempty"`
	Description    string         `yaml:"description,omitempty" json:"description,omitempty"`
}

// Exception defines a time-bounded, owned policy suppression for a specific vulnerability.
type Exception struct {
	ID        string `yaml:"id" json:"id"`
	Package   string `yaml:"package,omitempty" json:"package,omitempty"`
	Owner     string `yaml:"owner" json:"owner"`
	Reason    string `yaml:"reason" json:"reason"`
	ExpiresAt string `yaml:"expires_at" json:"expires_at"`
}

// Policy defines declarative security gate rules and time-bounded exceptions.
type Policy struct {
	Version         int         `yaml:"version" json:"version"`
	FailOnScanError *bool       `yaml:"fail_on_scan_error,omitempty" json:"fail_on_scan_error,omitempty"`
	Rules           []Rule      `yaml:"rules" json:"rules"`
	Exceptions      []Exception `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// FindingDecision records the deterministic policy decision and reasoning for a single Finding.
type FindingDecision struct {
	Finding          Finding    `json:"finding"`
	Decision         Decision   `json:"decision"`
	MatchedRule      string     `json:"matched_rule,omitempty"`
	IsNew            bool       `json:"is_new"`
	Exception        *Exception `json:"exception,omitempty"`
	ExpiredException *Exception `json:"expired_exception,omitempty"`
	Reasoning        []string   `json:"reasoning"`
}

// EvaluationResult aggregates all finding decisions and scan-completeness checks.
type EvaluationResult struct {
	OverallDecision   Decision          `json:"overall_decision"`
	Decisions         []FindingDecision `json:"decisions"`
	BlockCount        int               `json:"block_count"`
	ReviewCount       int               `json:"review_count"`
	AllowCount        int               `json:"allow_count"`
	SuppressedCount   int               `json:"suppressed_count"`
	ExpiredExceptions int               `json:"expired_exceptions"`
	ScanIncomplete    bool              `json:"scan_incomplete"`
	FailedPackages    int               `json:"failed_packages"`
}

// DefaultPolicy returns Vigil's built-in deterministic security policy.
func DefaultPolicy() Policy {
	failOnError := true
	return Policy{
		Version:         1,
		FailOnScanError: &failOnError,
		Rules: []Rule{
			{
				Name:           "production/critical-block",
				Decision:       DecisionBlock,
				MinSeverity:    types.Critical,
				ProductionOnly: true,
				Description:    "Block releases with CRITICAL vulnerabilities in production dependencies.",
			},
			{
				Name:           "production/high-new",
				Decision:       DecisionReview,
				MinSeverity:    types.High,
				ProductionOnly: true,
				NewOnly:        true,
				Description:    "Require manual review for newly introduced HIGH vulnerabilities in production dependencies.",
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

// LoadPolicy reads and validates a YAML policy file from disk.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy parses and validates YAML policy bytes.
func ParsePolicy(data []byte) (Policy, error) {
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return Policy{}, fmt.Errorf("parse policy YAML: %w", err)
	}

	for i := range pol.Rules {
		pol.Rules[i].Decision = Decision(strings.ToUpper(strings.TrimSpace(string(pol.Rules[i].Decision))))
		switch pol.Rules[i].Decision {
		case DecisionAllow, DecisionReview, DecisionBlock:
		default:
			return Policy{}, fmt.Errorf("rule %q has invalid decision %q (allowed: ALLOW, REVIEW, BLOCK)", pol.Rules[i].Name, pol.Rules[i].Decision)
		}
		if pol.Rules[i].MinSeverity != "" {
			sev, ok := types.ParseSeverity(string(pol.Rules[i].MinSeverity))
			if !ok {
				return Policy{}, fmt.Errorf("rule %q has invalid min_severity %q", pol.Rules[i].Name, pol.Rules[i].MinSeverity)
			}
			pol.Rules[i].MinSeverity = sev
		}
		if pol.Rules[i].MatchSeverity != "" {
			sev, ok := types.ParseSeverity(string(pol.Rules[i].MatchSeverity))
			if !ok {
				return Policy{}, fmt.Errorf("rule %q has invalid match_severity %q", pol.Rules[i].Name, pol.Rules[i].MatchSeverity)
			}
			pol.Rules[i].MatchSeverity = sev
		}
	}

	for i, ex := range pol.Exceptions {
		if strings.TrimSpace(ex.ID) == "" {
			return Policy{}, fmt.Errorf("exception #%d is missing required field 'id'", i+1)
		}
		if strings.TrimSpace(ex.Owner) == "" {
			return Policy{}, fmt.Errorf("exception %q is missing required field 'owner'", ex.ID)
		}
		if strings.TrimSpace(ex.Reason) == "" {
			return Policy{}, fmt.Errorf("exception %q is missing required field 'reason'", ex.ID)
		}
		if _, err := parseExpiry(ex.ExpiresAt); err != nil {
			return Policy{}, fmt.Errorf("exception %q has invalid expires_at %q: %w", ex.ID, ex.ExpiresAt, err)
		}
	}

	return pol, nil
}

// Evaluate deterministically evaluates a ScanResult against a Policy and optional Baseline.
func Evaluate(result *types.ScanResult, pol Policy, baseline *Baseline, now time.Time) EvaluationResult {
	findings := BuildFindings(result)
	delta := ComputeDelta(findings, baseline)

	newSet := make(map[string]bool, len(delta.New))
	for _, f := range delta.New {
		newSet[f.Key] = true
	}

	eval := EvaluationResult{
		OverallDecision: DecisionAllow,
		Decisions:       make([]FindingDecision, 0, len(findings)),
	}

	if result != nil && result.Coverage.FailedPackages > 0 {
		eval.ScanIncomplete = true
		eval.FailedPackages = result.Coverage.FailedPackages
	}

	for _, f := range findings {
		isNew := newSet[f.Key]
		fd := evaluateFinding(f, pol, baseline != nil, isNew, now)
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

	failOnScanError := true
	if pol.FailOnScanError != nil {
		failOnScanError = *pol.FailOnScanError
	}
	if failOnScanError && eval.ScanIncomplete {
		eval.OverallDecision = DecisionBlock
	}

	return eval
}

func evaluateFinding(f Finding, pol Policy, hasBaseline, isNew bool, now time.Time) FindingDecision {
	fd := FindingDecision{
		Finding:  f,
		Decision: DecisionAllow,
		IsNew:    isNew,
	}

	if hasBaseline {
		if isNew {
			fd.Reasoning = append(fd.Reasoning, "New vulnerability introduced since baseline.")
		} else {
			fd.Reasoning = append(fd.Reasoning, "Vulnerability was already present in baseline.")
		}
	} else {
		fd.Reasoning = append(fd.Reasoning, "Evaluated without a baseline snapshot (treated as new).")
	}

	fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Runtime exploitability is %s (confidence: %s): %s",
		f.Exploitability.Status, f.Exploitability.Confidence, f.Exploitability.Rationale))

	// Check exceptions first.
	for i := range pol.Exceptions {
		ex := pol.Exceptions[i]
		if !exceptionMatches(ex, f) {
			continue
		}
		expiry, err := parseExpiry(ex.ExpiresAt)
		if err == nil && !now.After(expiry) {
			exCopy := ex
			fd.Exception = &exCopy
			fd.Decision = DecisionAllow
			fd.MatchedRule = "exception/" + ex.ID
			fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Suppressed by active exception owned by %s until %s: %s", ex.Owner, ex.ExpiresAt, ex.Reason))
			return fd
		}
		exCopy := ex
		fd.ExpiredException = &exCopy
		fd.Reasoning = append(fd.Reasoning, fmt.Sprintf("Exception owned by %s expired on %s and no longer suppresses this finding.", ex.Owner, ex.ExpiresAt))
	}

	// Evaluate policy rules in declaration order; highest severity decision wins.
	for _, rule := range pol.Rules {
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
	return true
}

func exceptionMatches(ex Exception, f Finding) bool {
	if !f.MatchesID(ex.ID) {
		return false
	}
	if ex.Package != "" && !strings.EqualFold(ex.Package, f.Package) {
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
		// Treat date-only expiry as inclusive until end of that UTC day.
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
