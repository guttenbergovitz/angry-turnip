package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/scan"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// CIGateOptions configures the CI security gate evaluation.
type CIGateOptions struct {
	MinSeverity     types.Severity
	FailOnCVSS      float64
	FailOnScanError bool
}

// CIGateOutcome captures the deterministic result of evaluating a ScanResult against CI policy.
type CIGateOutcome struct {
	SeverityViolations int
	CVSSViolations     int
	FailedPackages     int
	ExitCode           int
	Reason             string
}

// EvaluateCIGate evaluates scan results against CI policy thresholds and scan coverage guarantees.
// Absence of vulnerability findings is not treated as proof of safety when packages failed to scan.
func EvaluateCIGate(result *types.ScanResult, opts CIGateOptions) CIGateOutcome {
	outcome := CIGateOutcome{
		FailedPackages: result.Coverage.FailedPackages,
	}

	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			if vuln.Severity.HigherOrEqualThan(opts.MinSeverity) {
				outcome.SeverityViolations++
			}
			if opts.FailOnCVSS > 0.0 && vuln.CVSSScore >= opts.FailOnCVSS {
				outcome.CVSSViolations++
			}
		}
	}

	if opts.FailOnScanError && outcome.FailedPackages > 0 {
		outcome.ExitCode = 2
		outcome.Reason = fmt.Sprintf("incomplete scan: %d package(s) failed vulnerability lookup", outcome.FailedPackages)
		return outcome
	}

	if outcome.SeverityViolations > 0 || outcome.CVSSViolations > 0 {
		outcome.ExitCode = 1
		outcome.Reason = "vulnerabilities exceeded CI policy threshold"
		return outcome
	}

	outcome.ExitCode = 0
	return outcome
}

// validateCachedResult verifies that a cached ScanResult matches the current lock file
// hash and does not exceed maxAge.
func validateCachedResult(result *types.ScanResult, currentLockFile, currentLockHash string, maxAge time.Duration, now time.Time) error {
	if result == nil {
		return fmt.Errorf("cached scan result is empty")
	}
	if result.LockFile != currentLockFile {
		return fmt.Errorf("cache lock file mismatch: cached %q, current %q (re-run scan)", result.LockFile, currentLockFile)
	}
	if result.LockFileHash == "" || result.LockFileHash != currentLockHash {
		return fmt.Errorf("cache is stale: lock file %q has changed since last scan", currentLockFile)
	}
	if maxAge > 0 && now.Sub(result.ScannedAt) > maxAge {
		return fmt.Errorf("cache expired: last scanned %s ago (max allowed: %s)", now.Sub(result.ScannedAt).Round(time.Second), maxAge)
	}
	return nil
}

// CI executes the ci command. By default it performs a fresh scan of the current project
// so that CI gates never pass on stale cached results.
func CI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	failOn := fs.String("fail-on", "high", "Fail if vulnerabilities at or above level exist (low, medium, high, critical)")
	failOnCVSS := fs.Float64("fail-on-cvss", 0.0, "Fail if any vulnerability has CVSS >= this threshold (0.0-10.0)")
	failOnScanError := fs.Bool("fail-on-scan-error", true, "Fail CI gate if any dependency fails vulnerability lookup")
	skipDevDeps := fs.Bool("skip-devdeps", false, "Skip development dependencies during scan")
	customLockFile := fs.String("lockfile", "", "Explicitly specify lock file name (e.g. go.mod, package-lock.json)")
	useCache := fs.Bool("use-cache", false, "Evaluate .vigil.cache instead of running a fresh scan (requires matching lock file hash and fresh timestamp)")
	maxCacheAge := fs.Duration("max-cache-age", 24*time.Hour, "Maximum allowed age of .vigil.cache when --use-cache is enabled")
	format := fs.String("format", "text", "Output format (text, csv, markdown, json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if *failOnCVSS < 0.0 || *failOnCVSS > 10.0 {
		return fmt.Errorf("invalid CVSS threshold: must be between 0.0 and 10.0")
	}

	minSev, ok := types.ParseSeverity(*failOn)
	if !ok || minSev == types.Unknown {
		return fmt.Errorf("invalid fail-on level: %s (allowed: low, medium, high, critical)", *failOn)
	}

	projectPath := "./"
	if fs.NArg() > 0 {
		projectPath = fs.Arg(0)
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	lockFile, lockType, err := resolveLockFile(absPath, *customLockFile)
	if err != nil {
		return err
	}

	lockFilePath := filepath.Join(absPath, lockFile)
	lockHash, err := lockfile.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	var result *types.ScanResult
	if *useCache {
		cachePath := filepath.Join(absPath, ".vigil.cache")
		cached, err := lockfile.LoadCache(cachePath)
		if err != nil {
			return fmt.Errorf("load cache: %w", err)
		}
		if err := validateCachedResult(cached, lockFile, lockHash, *maxCacheAge, time.Now().UTC()); err != nil {
			return err
		}
		result = cached
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		result, err = scan.Scan(ctx, absPath, lockFile, lockType, lockHash, lockFilePath, *skipDevDeps, nil)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
	}

	outcome := EvaluateCIGate(result, CIGateOptions{
		MinSeverity:     minSev,
		FailOnCVSS:      *failOnCVSS,
		FailOnScanError: *failOnScanError,
	})

	if err := renderCIOutput(os.Stdout, result, outcome, *format, *failOn, *failOnCVSS); err != nil {
		return err
	}

	if outcome.ExitCode != 0 {
		return &ExitError{Code: outcome.ExitCode}
	}

	return nil
}

func renderCIOutput(out io.Writer, result *types.ScanResult, outcome CIGateOutcome, format, failOn string, failOnCVSS float64) error {
	switch format {
	case "text":
		if failOnCVSS > 0.0 {
			fmt.Fprintf(out, "CI Check: severity=%s, CVSS>=%.1f\n", failOn, failOnCVSS)
		} else {
			fmt.Fprintf(out, "CI Check: %s and above\n", failOn)
		}
		if result.Coverage.TotalPackages > 0 {
			fmt.Fprintf(out, "Coverage: %d scanned, %d failed, %d skipped, %d unsupported (total %d)\n",
				result.Coverage.ScannedPackages,
				result.Coverage.FailedPackages,
				result.Coverage.SkippedPackages,
				result.Coverage.UnsupportedPackages,
				result.Coverage.TotalPackages,
			)
		}
		if outcome.FailedPackages > 0 {
			fmt.Fprintf(out, "✗ Scan incomplete: %d package(s) failed vulnerability lookup\n", outcome.FailedPackages)
		}
		if outcome.SeverityViolations > 0 {
			fmt.Fprintf(out, "✗ Found %d vulnerability/vulnerabilities at or above %s level\n", outcome.SeverityViolations, failOn)
		}
		if failOnCVSS > 0.0 && outcome.CVSSViolations > 0 {
			fmt.Fprintf(out, "✗ Found %d vulnerability/vulnerabilities with CVSS >= %.1f\n", outcome.CVSSViolations, failOnCVSS)
		}
		if outcome.ExitCode == 0 {
			fmt.Fprintf(out, "✓ CI security gate passed\n")
		}
		return nil
	case "json":
		return export.JSON(result, out)
	case "csv":
		return export.CSV(result, out)
	case "markdown":
		return export.Markdown(result, out)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}
