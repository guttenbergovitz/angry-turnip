package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Explain executes the `vigil explain <vuln-id>` command, printing an auditable breakdown
// of why a vulnerability is allowed, flagged for review, or blocked, together with evidence
// state, freshness warnings, and missing evidence.
func Explain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to YAML policy file (defaults to built-in policy)")
	baselinePath := fs.String("baseline", "", "Path to baseline JSON file for delta analysis")
	format := fs.String("format", "text", "Output format (text, json)")
	maxCacheAge := fs.Duration("max-cache-age", 24*time.Hour, "Age threshold after which a stale cache warning is displayed")

	reordered := reorderFlagsFirst(args, map[string]bool{
		"policy":        true,
		"baseline":      true,
		"format":        true,
		"max-cache-age": true,
	})
	if err := fs.Parse(reordered); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: vigil explain <vuln-id> [path] [--policy file] [--baseline file] [--format text|json]")
	}

	vulnID := strings.TrimSpace(fs.Arg(0))
	projectPath := "./"
	if fs.NArg() > 1 {
		projectPath = fs.Arg(1)
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	cachePath := filepath.Join(absPath, ".vigil.cache")
	result, err := lockfile.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache (run `vigil scan` first): %w", err)
	}

	warnings := checkExplainCacheWarnings(absPath, result, *maxCacheAge, time.Now().UTC())

	pol := policy.DefaultPolicy()
	if *policyPath != "" {
		pol, err = policy.LoadPolicy(*policyPath)
		if err != nil {
			return err
		}
	}

	var baseline *policy.Baseline
	if *baselinePath != "" {
		baseline, err = policy.LoadBaseline(*baselinePath)
		if err != nil {
			return err
		}
	}

	eval := policy.Evaluate(result, pol, baseline, time.Now().UTC())

	var matched []policy.FindingDecision
	for _, fd := range eval.Decisions {
		if fd.Finding.MatchesID(vulnID) {
			matched = append(matched, fd)
		}
	}

	if len(matched) == 0 {
		return fmt.Errorf("no finding matching %q found in %s", vulnID, cachePath)
	}

	switch *format {
	case "json":
		payload := struct {
			EvidenceState policy.EvidenceState     `json:"evidence_state"`
			Warnings      []string                 `json:"warnings,omitempty"`
			Findings      []policy.FindingDecision `json:"findings"`
		}{
			EvidenceState: eval.EvidenceState,
			Warnings:      warnings,
			Findings:      matched,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	case "text":
		renderExplanations(os.Stdout, matched, eval.EvidenceState, warnings)
		return nil
	default:
		return fmt.Errorf("unknown format: %s (allowed: text, json)", *format)
	}
}

func checkExplainCacheWarnings(absPath string, result *types.ScanResult, maxAge time.Duration, now time.Time) []string {
	var warnings []string
	if result == nil {
		return warnings
	}
	if maxAge > 0 && now.Sub(result.ScannedAt) > maxAge {
		warnings = append(warnings, fmt.Sprintf("Cached scan is %s old (scanned at %s); re-run `vigil scan` for fresh results.",
			now.Sub(result.ScannedAt).Round(time.Minute), result.ScannedAt.Format(time.RFC3339)))
	}
	if result.LockFile != "" {
		lockFilePath := filepath.Join(absPath, result.LockFile)
		if currentHash, err := lockfile.HashFile(lockFilePath); err == nil {
			if result.LockFileHash != "" && currentHash != result.LockFileHash {
				warnings = append(warnings, fmt.Sprintf("Lock file %q has changed since the cached scan; explanation may be stale.", result.LockFile))
			}
		}
	}
	if result.Coverage.FailedPackages > 0 || result.Coverage.UnsupportedPackages > 0 {
		warnings = append(warnings, fmt.Sprintf("Cached scan had incomplete coverage (%d failed, %d unsupported package(s)).",
			result.Coverage.FailedPackages, result.Coverage.UnsupportedPackages))
	}
	return warnings
}

func renderExplanations(out io.Writer, decisions []policy.FindingDecision, evidenceState policy.EvidenceState, warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(out, "WARNING: %s\n", w)
	}
	if len(warnings) > 0 {
		fmt.Fprintf(out, "\n")
	}

	for i, fd := range decisions {
		if i > 0 {
			fmt.Fprintf(out, "\n───────────────────────────────────────────────────────────────────────────────\n\n")
		}
		f := fd.Finding

		scope := "transitive"
		if f.Direct {
			scope = "direct"
		}

		sources := "none"
		if len(f.Sources) > 0 {
			sources = strings.Join(f.Sources, ", ")
		}

		fmt.Fprintf(out, "%s  [%s]\n", f.ID, fd.Decision)
		fmt.Fprintf(out, "Evidence State:      %s\n", evidenceState)
		if fd.AcceptedRisk {
			fmt.Fprintf(out, "Risk Status:         FORMALLY ACCEPTED RISK (not proof of safety)\n")
		}
		if len(f.Aliases) > 0 {
			fmt.Fprintf(out, "Aliases:             %s\n", strings.Join(f.Aliases, ", "))
		}
		fmt.Fprintf(out, "Component PURL:      %s\n", f.PURL)
		fmt.Fprintf(out, "Package:             %s@%s (%s, %s, %s)\n", f.Package, f.Version, f.Ecosystem, f.DependencyType, scope)
		fmt.Fprintf(out, "Severity:            %s", strings.ToUpper(string(f.Severity)))
		if f.CVSSScore > 0 {
			fmt.Fprintf(out, " (CVSS %.1f)", f.CVSSScore)
		}
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "Sources:             %s\n", sources)
		if f.EffectiveScoreReason != "" {
			fmt.Fprintf(out, "Effective Score:     %s\n", f.EffectiveScoreReason)
		}
		if len(f.SourceEvidence) > 1 {
			fmt.Fprintf(out, "Source Breakdown:\n")
			for _, ev := range f.SourceEvidence {
				fmt.Fprintf(out, "  • %s (%s): %s", ev.Source, ev.AdvisoryID, strings.ToUpper(string(ev.Severity)))
				if ev.CVSSScore > 0 {
					fmt.Fprintf(out, " (CVSS %.1f)", ev.CVSSScore)
				}
				fmt.Fprintf(out, "\n")
			}
		}
		switch f.KEVStatus {
		case types.EnrichmentAvailable:
			fmt.Fprintf(out, "Known Exploited:     YES (CISA KEV)\n")
		case types.EnrichmentNotFound:
			fmt.Fprintf(out, "Known Exploited:     NO (checked CISA KEV)\n")
		case types.EnrichmentFailed:
			fmt.Fprintf(out, "Known Exploited:     UNAVAILABLE (CISA KEV lookup failed)\n")
		case types.EnrichmentNotRequested:
			fmt.Fprintf(out, "Known Exploited:     NOT REQUESTED (CISA KEV was not queried)\n")
		default:
			if f.KnownExploited {
				fmt.Fprintf(out, "Known Exploited:     YES (CISA KEV)\n")
			}
		}
		switch f.EPSSStatus {
		case types.EnrichmentAvailable:
			if f.EPSSDate != "" {
				fmt.Fprintf(out, "EPSS Score:          %.1f%% (percentile: %.1f%%, model date: %s)\n", f.EPSSScore*100, f.EPSSPercentile*100, f.EPSSDate)
			} else {
				fmt.Fprintf(out, "EPSS Score:          %.1f%% (percentile: %.1f%%)\n", f.EPSSScore*100, f.EPSSPercentile*100)
			}
		case types.EnrichmentNotFound:
			fmt.Fprintf(out, "EPSS Score:          NOT SCORED (checked FIRST EPSS)\n")
		case types.EnrichmentFailed:
			fmt.Fprintf(out, "EPSS Score:          UNAVAILABLE (FIRST EPSS lookup failed)\n")
		case types.EnrichmentNotRequested:
			fmt.Fprintf(out, "EPSS Score:          NOT REQUESTED (FIRST EPSS was not queried)\n")
		default:
			if f.EPSSScore > 0 {
				fmt.Fprintf(out, "EPSS Score:          %.1f%% (percentile: %.1f%%)\n", f.EPSSScore*100, f.EPSSPercentile*100)
			}
		}
		fmt.Fprintf(out, "Runtime Exposure:    %s (confidence: %s)\n", f.Exploitability.Status, f.Exploitability.Confidence)
		if fd.MatchedRule != "" {
			fmt.Fprintf(out, "Policy Rule:         %s\n", fd.MatchedRule)
		}

		fmt.Fprintf(out, "\nDecision Reasoning:\n")
		for _, reason := range fd.Reasoning {
			fmt.Fprintf(out, "  • %s\n", reason)
		}

		if len(f.MissingEvidence) > 0 {
			fmt.Fprintf(out, "\nMissing Evidence:\n")
			for _, item := range f.MissingEvidence {
				fmt.Fprintf(out, "  • %s\n", item)
			}
		}
	}
}
