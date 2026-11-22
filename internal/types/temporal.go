package types

import "time"

// TemporalMetadata describes the chronological relationship between a package release
// and a vulnerability publication date. It is strictly informational and must never be
// used to discard vulnerabilities: a vulnerability disclosed before a package release can
// still affect that release if the issue was not fixed.
type TemporalMetadata struct {
	PackageReleasedAt      *time.Time
	VulnPublishedAt        *time.Time
	PublishedBeforeRelease bool
}

// ComputeTemporalMetadata computes informational timing metadata for a vulnerability
// relative to a package release date without filtering or suppressing any findings.
func ComputeTemporalMetadata(packageReleased *time.Time, vuln Vulnerability) TemporalMetadata {
	meta := TemporalMetadata{
		PackageReleasedAt: packageReleased,
		VulnPublishedAt:   vuln.PublishedAt,
	}

	if packageReleased != nil && vuln.PublishedAt != nil {
		meta.PublishedBeforeRelease = vuln.PublishedAt.Before(*packageReleased)
	}

	return meta
}
