package scan

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/github"
	"github.com/guttenbergovitz/vigil-cli/internal/npm"
	"github.com/guttenbergovitz/vigil-cli/internal/nvd"
	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// VulnerabilitySource queries an upstream advisory database for a package and version.
type VulnerabilitySource interface {
	QueryWithEcosystemContext(ctx context.Context, pkg, version string, ecosystem types.Ecosystem) ([]types.Vulnerability, error)
}

// CVEEnricher fetches authoritative CVE metadata (such as NVD) by CVE identifier.
type CVEEnricher interface {
	QueryCVE(cveID string) (*types.Vulnerability, error)
}

// GHSAEnricher fetches GitHub Security Advisory metadata by GHSA identifier.
type GHSAEnricher interface {
	QueryGHSA(ghsaID string) (*types.Vulnerability, error)
}

// ReleaseDateFetcher fetches package release timestamps for informational metadata.
type ReleaseDateFetcher interface {
	GetReleaseDate(pkg, version string) (*time.Time, error)
}

// RateLimiter coordinates a global minimum interval between requests across concurrent workers.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewRateLimiter creates a global rate limiter enforcing at least interval between ticks.
func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{interval: interval}
}

// Wait blocks until the next slot is available or ctx is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		return nil
	}

	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	waitUntil := r.next
	r.next = waitUntil.Add(r.interval)
	r.mu.Unlock()

	delay := time.Until(waitUntil)
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Scanner orchestrates dependency vulnerability scanning with injected dependencies.
type Scanner struct {
	VulnSource   VulnerabilitySource
	CVEEnricher  CVEEnricher
	GHSAEnricher GHSAEnricher
	ReleaseDates ReleaseDateFetcher
	NVDLimiter   *RateLimiter
	NVDEnabled   bool
}

// DefaultScanner constructs a Scanner configured with standard upstream clients and environment variables.
func DefaultScanner() *Scanner {
	nvdAPIKey := os.Getenv("NVD_API_KEY")
	githubToken := os.Getenv("GITHUB_TOKEN")

	var nvdClient CVEEnricher
	var nvdLimiter *RateLimiter
	if nvdAPIKey != "" {
		nvdClient = nvd.New("https://services.nvd.nist.gov/rest/json/cves/2.0", nvdAPIKey, 10)
		// Global 600ms interval across all workers respects NVD's 50 requests per 30 seconds limit.
		nvdLimiter = NewRateLimiter(600 * time.Millisecond)
	}

	return &Scanner{
		VulnSource:   osv.New("https://api.osv.dev/v1/query", 10),
		CVEEnricher:  nvdClient,
		GHSAEnricher: github.New(githubToken, 10),
		ReleaseDates: npm.New("https://registry.npmjs.org", 10),
		NVDLimiter:   nvdLimiter,
		NVDEnabled:   nvdAPIKey != "",
	}
}
