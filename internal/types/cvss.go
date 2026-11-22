package types

import "strings"

// DeriveCVSSFromSeverity derives an approximate CVSS score from a known severity level
// as a last-resort fallback. Unknown severity returns 0.0 rather than fabricating a score.
func DeriveCVSSFromSeverity(severity Severity) float64 {
	switch strings.ToLower(strings.TrimSpace(string(severity))) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 0.0
	}
}

// SeverityFromCVSS maps a CVSS score to a canonical Severity level.
// A zero or negative score indicates missing CVSS data and maps to Unknown.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Unknown
	}
}
