package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Table generates a compact tabular report.
func Table(result *types.ScanResult, out io.Writer) error {
	if result.Coverage.FailedPackages > 0 {
		fmt.Fprintf(out, "⚠️  Incomplete scan: %d of %d package(s) failed vulnerability lookup\n",
			result.Coverage.FailedPackages, result.Coverage.TotalPackages)
	}

	if result.TotalVulns == 0 {
		if result.Coverage.FailedPackages > 0 {
			fmt.Fprintf(out, "No vulnerabilities reported for scanned packages, but scan coverage is incomplete.\n")
			return nil
		}
		fmt.Fprintf(out, "✓ No vulnerabilities found\n")
		return nil
	}

	entries := processVulnerabilities(result)
	bySeverity := groupBySeverity(entries)
	gate, gateReasons := determineReleaseGate(result, entries)

	fmt.Fprintf(out, "\n")
	writeTableHeader(out)

	severityOrder := []types.Severity{types.Critical, types.High, types.Medium, types.Low, types.Unknown}
	first := true

	for _, severity := range severityOrder {
		vulns, ok := bySeverity[severity]
		if !ok || len(vulns) == 0 {
			continue
		}

		if !first {
			fmt.Fprintf(out, "\n")
		}
		first = false

		for _, entry := range vulns {
			writeTableRow(out, entry)
		}
	}

	fmt.Fprintf(out, "\n")
	writeTableSummary(out, result, entries, gate, gateReasons)

	return nil
}

func writeTableHeader(out io.Writer) {
	fmt.Fprintf(out, "%-25s │ %-20s │ %-10s │ %-15s │ %-23s │ %-12s │ %s\n",
		"Library", "Vuln ID", "Severity", "Exploit Type", "Exploitability", "Fix Available", "Recommended Action")
	fmt.Fprintf(out, "%s┼%s┼%s┼%s┼%s┼%s┼%s\n",
		strings.Repeat("─", 26),
		strings.Repeat("─", 22),
		strings.Repeat("─", 12),
		strings.Repeat("─", 17),
		strings.Repeat("─", 25),
		strings.Repeat("─", 14),
		strings.Repeat("─", 30))
}

func writeTableRow(out io.Writer, entry VulnEntry) {
	library := truncate(entry.Library+"@"+entry.Version, 24)
	vulnID := truncate(entry.VulnID, 19)
	severity := colourSeverity(entry.Severity)
	exploitType := truncate(string(entry.ExploitType), 14)
	exploitability := truncate(string(entry.Exploitability), 23)
	fixStatus := truncate(entry.FixStatus, 11)
	action := truncate(string(entry.RecommendedAction), 28)

	if entry.Environment == "dev" {
		library = library + " (dev)"
	}

	fmt.Fprintf(out, "%-25s │ %-20s │ %-10s │ %-15s │ %-23s │ %-12s │ %s\n",
		library, vulnID, severity, exploitType, exploitability, fixStatus, action)
}

func writeTableSummary(out io.Writer, result *types.ScanResult, entries []VulnEntry, gate ReleaseGate, reasons []string) {
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "SUMMARY\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n\n")

	fmt.Fprintf(out, "Total Findings: %d", result.TotalVulns)
	if result.CriticalVulns > 0 {
		fmt.Fprintf(out, "  │  🔴 CRITICAL: %d", result.CriticalVulns)
	}
	if result.HighVulns > 0 {
		fmt.Fprintf(out, "  │  🟠 HIGH: %d", result.HighVulns)
	}
	if result.MediumVulns > 0 {
		fmt.Fprintf(out, "  │  🟡 MEDIUM: %d", result.MediumVulns)
	}
	if result.LowVulns > 0 {
		fmt.Fprintf(out, "  │  🔵 LOW: %d", result.LowVulns)
	}
	if result.UnknownVulns > 0 {
		fmt.Fprintf(out, "  │  ⚪ UNKNOWN: %d", result.UnknownVulns)
	}
	fmt.Fprintf(out, "\n\n")

	prodPotential := 0
	for _, entry := range entries {
		if entry.Environment == "production" && entry.Exploitability == ExploitabilityPotentiallyExploitable {
			prodPotential++
		}
	}

	if prodPotential > 0 {
		fmt.Fprintf(out, "⚠️  Potentially Exploitable (Production): %d finding(s) require reachability review\n", prodPotential)
	}

	fmt.Fprintf(out, "\n%s\n", gate)
	if len(reasons) > 0 {
		for _, reason := range reasons {
			fmt.Fprintf(out, "  • %s\n", reason)
		}
	}

	fmt.Fprintf(out, "\n")
}

func colourSeverity(severity types.Severity) string {
	switch types.NormaliseSeverity(severity) {
	case types.Critical:
		return "CRITICAL"
	case types.High:
		return "HIGH"
	case types.Medium:
		return "MEDIUM"
	case types.Low:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-1] + "…"
}
