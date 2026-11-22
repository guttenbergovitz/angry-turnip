package cli

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
)

// Baseline executes the `vigil baseline` command, writing a deterministic JSON baseline
// snapshot from the current .vigil.cache for future delta analysis.
func Baseline(args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	outputPath := fs.String("output", "", "Path to write baseline JSON (default: <project>/.vigil.baseline.json)")

	if err := fs.Parse(args); err != nil {
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

	cachePath := filepath.Join(absPath, ".vigil.cache")
	result, err := lockfile.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache (run `vigil scan` first): %w", err)
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
