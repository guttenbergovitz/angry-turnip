package types

import "time"

// Ecosystem represents a package manager ecosystem supported by Vigil.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemGo        Ecosystem = "Go"
	EcosystemCargo     Ecosystem = "Cargo"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemMaven     Ecosystem = "Maven"
)

// PackageScanStatus represents the outcome of scanning an individual dependency.
type PackageScanStatus string

const (
	// StatusScanned indicates the dependency was queried against vulnerability sources without error.
	StatusScanned PackageScanStatus = "scanned"
	// StatusFailed indicates vulnerability lookup failed for this dependency.
	StatusFailed PackageScanStatus = "failed"
	// StatusSkipped indicates the dependency was intentionally excluded from scanning (for example via --skip-devdeps).
	StatusSkipped PackageScanStatus = "skipped"
	// StatusUnsupported indicates the dependency could not be queried due to unsupported ecosystem or missing version metadata.
	StatusUnsupported PackageScanStatus = "unsupported"
)

// Dependency represents a single package and its metadata.
type Dependency struct {
	Name            string
	Version         string
	Ecosystem       Ecosystem         // Package manager ecosystem (npm, PyPI, Go, Cargo, etc.)
	Type            DependencyType    // Production or development classification
	Direct          bool              // Whether declared directly or pulled in transitively
	DependsOn       []string          // Canonical "name@version" keys of direct child dependencies
	ReleasedAt      *time.Time        // Package release date (informational metadata only)
	ScanStatus      PackageScanStatus // Explicit scan outcome for this package
	ScanError       string            // Error message when ScanStatus is StatusFailed
	Vulnerabilities []Vulnerability
}

// DependencyType indicates whether a dependency is used in production or only for development.
type DependencyType string

const (
	Production  DependencyType = "production"
	Development DependencyType = "development"
)

// Vulnerability represents a single CVE or security advisory.
type Vulnerability struct {
	ID             string
	Summary        string
	Description    string     // Full description/details from database
	Severity       Severity
	CVSSScore      float64    // CVSS v3.0+ score (0.0-10.0)
	CVSSVector     string     // CVSS vector string for detailed analysis
	RiskScore      int        // Vigil's computed risk score (0-100)
	References     []string
	PublishedAt    *time.Time
	ModifiedAt     *time.Time
	Sources        []string   // Sources where the vulnerability was found (osv, nvd, github, etc.)
	CVEID          string     // CVE-YYYY-*** identifier from MITRE
	CVETitle       string     // Title from NVD/MITRE
	CVEDescription string     // Full description from NVD/MITRE
	CVESeverity    Severity   // Severity from MITRE/NVD
}

// Severity represents a vulnerability severity level.
type Severity string

const (
	Unknown  Severity = "unknown"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// PackageScanError records a vulnerability lookup failure for a specific package.
type PackageScanError struct {
	Package string
	Version string
	Error   string
}

// ScanCoverage summarises how completely dependencies were evaluated during a scan.
type ScanCoverage struct {
	TotalPackages       int
	ScannedPackages     int
	FailedPackages      int
	SkippedPackages     int
	UnsupportedPackages int
	Errors              []PackageScanError
}

// ScanResult contains the results and coverage metadata of a single scan operation.
type ScanResult struct {
	Version       int
	ProjectPath   string
	ScannedAt     time.Time
	LockFile      string
	LockFileHash  string // SHA-256 hash for cache invalidation
	Dependencies  []Dependency
	Coverage      ScanCoverage
	TotalVulns    int
	CriticalVulns int
	HighVulns     int
	MediumVulns   int
	LowVulns      int
	UnknownVulns  int
	SecretCount   int
}
