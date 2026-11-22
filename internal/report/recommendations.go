package report

import (
	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

// RecommendedAction represents the recommended remediation action.
type RecommendedAction string

const (
	ActionImmediateHotfix    RecommendedAction = "Immediate hotfix"
	ActionUpgradeNextRelease RecommendedAction = "Upgrade in next release"
	ActionReviewRequired     RecommendedAction = "Manual review required"
	ActionInfraMitigation    RecommendedAction = "Infra mitigation required"
	ActionMonitoringOnly     RecommendedAction = "Monitoring only"
	ActionRiskAcceptance     RecommendedAction = "Risk acceptance candidate"
)

// DetermineRecommendedAction determines a remediation recommendation using canonical
// severity ordering, dependency scope, and evidence-based exploitability assessment.
func DetermineRecommendedAction(
	vuln types.Vulnerability,
	depType types.DependencyType,
	exploitType ExploitType,
	assessment ExploitabilityAssessment,
) RecommendedAction {
	isProduction := depType == types.Production
	severity := types.NormaliseSeverity(vuln.Severity)

	// Verified non-affected findings do not require urgent remediation.
	if assessment.Status == ExploitabilityConfirmedNotAffected {
		return ActionMonitoringOnly
	}

	// Unknown severity cannot be safely dismissed; require manual review.
	if severity == types.Unknown {
		return ActionReviewRequired
	}

	// CRITICAL in production requires immediate triage/hotfix.
	if severity == types.Critical && isProduction {
		return ActionImmediateHotfix
	}

	// HIGH in production with potential exploitability signals requires urgent review/upgrade.
	if severity == types.High && isProduction && assessment.Status == ExploitabilityPotentiallyExploitable {
		return ActionReviewRequired
	}

	// HIGH or MEDIUM in production should be scheduled for the next release.
	if severity.HigherOrEqualThan(types.Medium) && isProduction {
		return ActionUpgradeNextRelease
	}

	// RCE/Injection at Medium severity or above should be upgraded even in development dependencies.
	if (exploitType == ExploitRCE || exploitType == ExploitInjection) && severity.HigherOrEqualThan(types.Medium) {
		return ActionUpgradeNextRelease
	}

	// Development-only or LOW severity findings can be monitored or considered for risk acceptance.
	if !isProduction || severity == types.Low {
		if assessment.Status == ExploitabilityPotentiallyExploitable && (exploitType == ExploitRCE || exploitType == ExploitInjection) {
			return ActionMonitoringOnly
		}
		return ActionRiskAcceptance
	}

	return ActionUpgradeNextRelease
}
