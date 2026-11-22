package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
)

// Baseline executes the `vigil baseline` command, writing a deterministic JSON baseline
// snapshot from a verified, fresh, and complete .vigil.cache.
func Baseline(args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	outputPath := fs.String("output", "", "Path to write baseline JSON (default: <project>/.vigil.baseline.json)")
	customLockFile := fs.String("lockfile", "", "Explicitly specify lock file name (e.g. go.mod, package-lock.json)")
	maxCacheAge := fs.Duration("max-cache-age", 24*time.Hour, "Maximum allowed age of .vigil.cache")

	reordered := reorderFlagsFirst(args, map[string]bool{
		"output":        true,
		"lockfile":      true,
		"max-cache-age": true,
	})
	if err := fs.Parse(reordered); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	projectPath := "./"
	if fs.NArg() > 0 {
		projectPath = fs.Arg(0)
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	lockFile, _, err := resolveLockFile(absPath, *customLockFile)
	if err != nil {
		return err
	}
	lockFilePath := filepath.Join(absPath, lockFile)
	lockHash, err := lockfile.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	cachePath := filepath.Join(absPath, ".vigil.cache")
	result, err := lockfile.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache (run `vigil scan` first): %w", err)
	}

	if err := validateCachedResult(result, lockFile, lockHash, *maxCacheAge, time.Now().UTC()); err != nil {
		return fmt.Errorf("refusing to build baseline from invalid cache: %w", err)
	}
	if err := policy.ValidateForBaseline(result); err != nil {
		return err
	}

	target := *outputPath
	if target == "" {
		target = filepath.Join(absPath, ".vigil.baseline.json")
	}

	baseline := policy.BuildBaseline(result)
	if err := policy.SaveBaseline(target, baseline); err != nil {
		return err
	}

	fmt.Printf("✓ Baseline written to %s (%d finding(s) recorded)\n", target, len(baseline.FindingKeys))
	return nil
}
