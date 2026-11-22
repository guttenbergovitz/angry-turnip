package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/version"
)

// WriteSARIF serialises an EvaluationResult as a SARIF 2.1.0 report suitable for GitHub
// Code Scanning, mapping policy decisions (BLOCK -> error, REVIEW -> warning, ALLOW -> note)
// alongside evidence state, PURL, CISA KEV, FIRST EPSS, and source-specific provenance.
func WriteSARIF(out io.Writer, lockFile string, eval EvaluationResult) error {
	if strings.TrimSpace(lockFile) == "" {
		lockFile = "lockfile"
	}

	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	type sarifArtifactLocation struct {
		URI string `json:"uri"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string                 `json:"ruleId"`
		Level      string                 `json:"level"`
		Message    sarifMessage           `json:"message"`
		Locations  []sarifLocation        `json:"locations"`
		Properties map[string]interface{} `json:"properties"`
	}

	rules := make([]sarifRule, 0, len(eval.Decisions))
	seenRules := make(map[string]bool, len(eval.Decisions))
	results := make([]sarifResult, 0, len(eval.Decisions))

	for _, fd := range eval.Decisions {
		f := fd.Finding
		if !seenRules[f.ID] {
			seenRules[f.ID] = true
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifMessage{Text: f.Summary},
			})
		}

		level := "note"
		switch fd.Decision {
		case DecisionBlock:
			level = "error"
		case DecisionReview:
			level = "warning"
		}

		msg := fmt.Sprintf("[%s] %s in %s (%s). %s",
			fd.Decision, f.ID, f.PURL, strings.ToUpper(string(f.Severity)), strings.Join(fd.Reasoning, " "))

		props := map[string]interface{}{
			"decision":         fd.Decision,
			"evidence_state":   eval.EvidenceState,
			"purl":             f.PURL,
			"package":          f.Package,
			"version":          f.Version,
			"ecosystem":        f.Ecosystem,
			"severity":         f.Severity,
			"cvss_score":       f.CVSSScore,
			"known_exploited":  f.KnownExploited,
			"kev_status":       f.KEVStatus,
			"epss_score":       f.EPSSScore,
			"epss_percentile":  f.EPSSPercentile,
			"epss_date":        f.EPSSDate,
			"epss_status":      f.EPSSStatus,
			"accepted_risk":    fd.AcceptedRisk,
			"missing_evidence": f.MissingEvidence,
		}
		if f.EffectiveScoreReason != "" {
			props["effective_score_reason"] = f.EffectiveScoreReason
		}
		if fd.MatchedRule != "" {
			props["matched_rule"] = fd.MatchedRule
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   level,
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: lockFile},
					},
				},
			},
			Properties: props,
		})
	}

	// Emit explicit SARIF results for evidence, coverage, and baseline comparability failures
	// so that a BLOCK or REVIEW caused by incomplete/invalid evidence is never invisible in
	// GitHub Code Scanning when zero vulnerability findings were observed.
	addDiagnosticResult := func(ruleID, shortDesc, level, text string, extraProps map[string]interface{}) {
		if !seenRules[ruleID] {
			seenRules[ruleID] = true
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: sarifMessage{Text: shortDesc},
			})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: text},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: lockFile},
					},
				},
			},
			Properties: extraProps,
		})
	}

	switch eval.EvidenceState {
	case EvidenceInvalid:
		addDiagnosticResult(
			"VIGIL-EVIDENCE-INVALID",
			"Invalid or inconsistent scan coverage evidence",
			"error",
			fmt.Sprintf("[BLOCK] Scan evidence is INVALID (%s).", strings.Join(eval.EvidenceNotes, " ")),
			map[string]interface{}{"decision": eval.OverallDecision, "evidence_state": eval.EvidenceState},
		)
	case EvidenceUnverified:
		addDiagnosticResult(
			"VIGIL-EVIDENCE-UNVERIFIED",
			"Unverified scan scope (zero packages evaluated)",
			"error",
			fmt.Sprintf("[BLOCK] Scan evidence is UNVERIFIED (%s).", strings.Join(eval.EvidenceNotes, " ")),
			map[string]interface{}{"decision": eval.OverallDecision, "evidence_state": eval.EvidenceState},
		)
	case EvidencePartial:
		level := "warning"
		if eval.ScanIncomplete {
			level = "error"
		}
		addDiagnosticResult(
			"VIGIL-SCAN-INCOMPLETE",
			"Incomplete dependency scan coverage (failed or unsupported packages)",
			level,
			fmt.Sprintf("[%s] Scan coverage is PARTIAL (%d failed, %d unsupported package(s)). %s",
				eval.OverallDecision, eval.FailedPackages, eval.UnsupportedPackages, strings.Join(eval.EvidenceNotes, " ")),
			map[string]interface{}{
				"decision":             eval.OverallDecision,
				"evidence_state":       eval.EvidenceState,
				"failed_packages":      eval.FailedPackages,
				"unsupported_packages": eval.UnsupportedPackages,
			},
		)
	}

	if eval.BaselineScopeCompatible != nil && !*eval.BaselineScopeCompatible {
		addDiagnosticResult(
			"VIGIL-BASELINE-INCOMPATIBLE",
			"Baseline scan configuration is incompatible with current scan",
			"warning",
			"[REVIEW] Baseline configuration fingerprint mismatch; baseline rejected for delta comparison.",
			map[string]interface{}{
				"decision":                  eval.OverallDecision,
				"baseline_scope_compatible": false,
			},
		)
	}

	if eval.Resolution != nil && len(eval.Resolution.Ambiguous) > 0 {
		addDiagnosticResult(
			"VIGIL-RESOLUTION-AMBIGUOUS",
			"Ambiguous dependency graph edges across multiple lockfile package versions",
			"warning",
			fmt.Sprintf("Dependency graph contains %d ambiguous multi-version edge(s) that were left unlinked rather than fabricated.", len(eval.Resolution.Ambiguous)),
			map[string]interface{}{
				"resolution_completeness": eval.Resolution.Completeness,
				"ambiguous_edges":         eval.Resolution.Ambiguous,
			},
		)
	}

	doc := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "Vigil",
						"version":        version.Get(),
						"informationUri": "https://github.com/guttenbergovitz/vigil-cli",
						"rules":          rules,
					},
				},
				"properties": map[string]interface{}{
					"overall_decision": eval.OverallDecision,
					"evidence_state":   eval.EvidenceState,
					"evidence_notes":   eval.EvidenceNotes,
					"scan_incomplete":  eval.ScanIncomplete,
				},
				"results": results,
			},
		},
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
