package types

import (
	"testing"
	"time"
)

func TestComputeTemporalMetadata(t *testing.T) {
	pkgReleased := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	before := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	same := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	after := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		packageReleased *time.Time
		vuln            Vulnerability
		wantBefore      bool
	}{
		{
			name:            "nil_release_date",
			packageReleased: nil,
			vuln:            Vulnerability{ID: "CVE-2024-0001", PublishedAt: &before},
			wantBefore:      false,
		},
		{
			name:            "nil_published_date",
			packageReleased: &pkgReleased,
			vuln:            Vulnerability{ID: "CVE-2024-0002", PublishedAt: nil},
			wantBefore:      false,
		},
		{
			name:            "published_before_release_flagged_as_metadata_only",
			packageReleased: &pkgReleased,
			vuln:            Vulnerability{ID: "CVE-2024-0003", PublishedAt: &before},
			wantBefore:      true,
		},
		{
			name:            "published_on_release_day",
			packageReleased: &pkgReleased,
			vuln:            Vulnerability{ID: "CVE-2024-0004", PublishedAt: &same},
			wantBefore:      false,
		},
		{
			name:            "published_after_release",
			packageReleased: &pkgReleased,
			vuln:            Vulnerability{ID: "CVE-2024-0005", PublishedAt: &after},
			wantBefore:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := ComputeTemporalMetadata(tt.packageReleased, tt.vuln)
			if meta.PublishedBeforeRelease != tt.wantBefore {
				t.Errorf("PublishedBeforeRelease = %v, want %v", meta.PublishedBeforeRelease, tt.wantBefore)
			}
		})
	}
}

func TestSeverityNormalisationAndComparison(t *testing.T) {
	if got := NormaliseSeverity(""); got != Unknown {
		t.Errorf("NormaliseSeverity(\"\") = %q, want %q", got, Unknown)
	}
	if got := NormaliseSeverity("unrecognised"); got != Unknown {
		t.Errorf("NormaliseSeverity(\"unrecognised\") = %q, want %q", got, Unknown)
	}
	if got := NormaliseSeverity("HIGH"); got != High {
		t.Errorf("NormaliseSeverity(\"HIGH\") = %q, want %q", got, High)
	}
	if !High.HigherOrEqualThan(Medium) {
		t.Error("expected High >= Medium to be true")
	}
	if Unknown.HigherOrEqualThan(Low) {
		t.Error("expected Unknown >= Low to be false")
	}
	if got := SeverityFromCVSS(0); got != Unknown {
		t.Errorf("SeverityFromCVSS(0) = %q, want %q", got, Unknown)
	}
	if got := DeriveCVSSFromSeverity(Unknown); got != 0.0 {
		t.Errorf("DeriveCVSSFromSeverity(Unknown) = %v, want 0.0", got)
	}
}
