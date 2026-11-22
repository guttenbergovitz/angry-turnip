package report

import (
	"testing"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

func TestDetermineRecommendedAction(t *testing.T) {
	potential := ExploitabilityAssessment{Status: ExploitabilityPotentiallyExploitable, Confidence: "low"}
	unknown := ExploitabilityAssessment{Status: ExploitabilityUnknown, Confidence: "low"}
	notAffected := ExploitabilityAssessment{Status: ExploitabilityConfirmedNotAffected, Confidence: "high"}

	tests := []struct {
		name        string
		severity    types.Severity
		depType     types.DependencyType
		exploitType ExploitType
		assessment  ExploitabilityAssessment
		want        RecommendedAction
	}{
		{
			// Regression test for lexicographical string comparison bug ("high" >= "medium" was false).
			name:        "dev_high_rce_upgrades_next_release",
			severity:    types.High,
			depType:     types.Development,
			exploitType: ExploitRCE,
			assessment:  unknown,
			want:        ActionUpgradeNextRelease,
		},
		{
			name:        "prod_critical_immediate_hotfix",
			severity:    types.Critical,
			depType:     types.Production,
			exploitType: ExploitRCE,
			assessment:  potential,
			want:        ActionImmediateHotfix,
		},
		{
			name:        "prod_high_potentially_exploitable_requires_review",
			severity:    types.High,
			depType:     types.Production,
			exploitType: ExploitDoS,
			assessment:  potential,
			want:        ActionReviewRequired,
		},
		{
			name:        "unknown_severity_requires_review",
			severity:    types.Unknown,
			depType:     types.Production,
			exploitType: ExploitOther,
			assessment:  unknown,
			want:        ActionReviewRequired,
		},
		{
			name:        "confirmed_not_affected_monitoring_only",
			severity:    types.Critical,
			depType:     types.Production,
			exploitType: ExploitRCE,
			assessment:  notAffected,
			want:        ActionMonitoringOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineRecommendedAction(
				types.Vulnerability{Severity: tt.severity},
				tt.depType,
				tt.exploitType,
				tt.assessment,
			)
			if got != tt.want {
				t.Errorf("DetermineRecommendedAction() = %q, want %q", got, tt.want)
			}
		})
	}
}
