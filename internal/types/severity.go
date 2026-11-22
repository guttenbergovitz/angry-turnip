package types

import "strings"

// SeverityMap maps normalised lowercase severity names to Severity values.
var SeverityMap = map[string]Severity{
	"unknown":  Unknown,
	"low":      Low,
	"medium":   Medium,
	"high":     High,
	"critical": Critical,
}

// SeverityRank provides numeric ordering for severity comparison.
var SeverityRank = map[Severity]int{
	Unknown:  0,
	Low:      1,
	Medium:   2,
	High:     3,
	Critical: 4,
}

// ParseSeverity parses a severity string (case-insensitive) into a Severity value.
func ParseSeverity(s string) (Severity, bool) {
	sev, ok := SeverityMap[strings.ToLower(strings.TrimSpace(s))]
	return sev, ok
}

// NormaliseSeverity converts any raw severity string into a canonical Severity value,
// returning Unknown when the input is empty or unrecognised.
func NormaliseSeverity(s Severity) Severity {
	if sev, ok := ParseSeverity(string(s)); ok {
		return sev
	}
	return Unknown
}

// HigherOrEqualThan returns true if this severity is greater than or equal to min.
func (s Severity) HigherOrEqualThan(min Severity) bool {
	return SeverityRank[NormaliseSeverity(s)] >= SeverityRank[NormaliseSeverity(min)]
}
