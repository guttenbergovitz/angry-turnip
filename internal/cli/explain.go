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
)

// Explain executes the `vigil explain <vuln-id>` command, printing an auditable breakdown
// of why a vulnerability is allowed, flagged for review, or blocked, together with any
// missing evidence required to reach a higher-confidence decision.
func Explain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to YAML policy file (defaults to built-in policy)")
	baselinePath := fs.String("baseline", "", "Path to baseline JSON file for delta analysis")
	format := fs.String("format", "text", "Output format (text, json)")

	if err := fs.Parse(args); err != nil {
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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(matched)
	case "text":
		renderExplanations(os.Stdout, matched)
		return nil
	default:
		return fmt.Errorf("unknown format: %s (allowed: text, json)", *format)
	}
}

func renderExplanations(out io.Writer, decisions []policy.FindingDecision) {
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
		if len(f.Aliases) > 0 {
			fmt.Fprintf(out, "Aliases:             %s\n", strings.Join(f.Aliases, ", "))
		}
		fmt.Fprintf(out, "Package:             %s@%s (%s, %s, %s)\n", f.Package, f.Version, f.Ecosystem, f.DependencyType, scope)
		fmt.Fprintf(out, "Severity:            %s", strings.ToUpper(string(f.Severity)))
		if f.CVSSScore > 0 {
			fmt.Fprintf(out, " (CVSS %.1f)", f.CVSSScore)
		}
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "Sources:             %s\n", sources)
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
