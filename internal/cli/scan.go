package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/git"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/policy"
	"github.com/guttenbergovitz/vigil-cli/internal/scan"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
	"github.com/guttenbergovitz/vigil-cli/internal/ui"
)

// Scan executes the scan command
func Scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	skipDevDeps := fs.Bool("skip-devdeps", false, "Skip development dependencies")
	outputFmt := fs.String("output", "", "Output format (json, csv, markdown)")
	noTUI := fs.Bool("no-tui", false, "Disable interactive TUI (useful for CI/testing)")
	customLockFile := fs.String("lockfile", "", "Explicitly specify lockfile name (e.g. uv.lock, requirements.txt)")
	scanSecrets := fs.Bool("secrets", false, "Scan codebase for hardcoded secrets and leaked credentials")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("scan: missing project path argument")
	}

	projectPath := fs.Arg(0)

	var absPath string
	var cleanup func()

	// Check if projectPath is a git URL
	if git.IsGitURL(projectPath) {
		fmt.Printf("Cloning repository: %s\n", projectPath)
		clonedPath, cleanupFn, err := git.CloneToTemp(projectPath)
		if err != nil {
			return fmt.Errorf("clone repository: %w", err)
		}
		absPath = clonedPath
		cleanup = cleanupFn
		defer cleanup()
		fmt.Printf("Repository cloned to: %s\n", absPath)
	} else {
		// Resolve absolute path for local directory
		var err error
		absPath, err = filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
	}

	lockFile, lockType, err := resolveLockFile(absPath, *customLockFile)
	if err != nil {
		return err
	}

	lockFilePath := filepath.Join(absPath, lockFile)

	// Hash the lock file
	lockHash, err := lockfile.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	// Channel for scan results
	resultChan := make(chan *types.ScanResult, 1)
	errorChan := make(chan error, 1)
	var wg sync.WaitGroup

	// Create context with timeout for scan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var program *tea.Program
	var finalModel tea.Model
	var reporter scan.ProgressReporter

	if !*noTUI {
		// Create Bubbletea model for progress display with alt screen
		model := ui.NewModel()
		model.SetCancelFunc(cancel) // Allow early quit to cancel scan
		program = tea.NewProgram(model, tea.WithAltScreen())
		reporter = &TUIAdapter{program: program}
	} else if *outputFmt == "" {
		// Only print human status banner when machine-readable --output is not requested.
		fmt.Println("Scanning...")
	}

	// Start full-spectrum scan (SCA + Secrets + IaC + Licenses + Policy Evaluation) in goroutine
	// so all domains finish before the TUI transitions to explorer mode.
	var (
		secList []secrets.SecretFinding
		iacList []container.SecurityIssue
		licList []license.LicenseFinding
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := scan.Scan(ctx, absPath, lockFile, lockType, lockHash, lockFilePath, *skipDevDeps, reporter)
		if err != nil {
			errorChan <- err
			return
		}
		secList, _ = secrets.NewScanner().ScanDirectory(absPath)
		iacList, _ = container.AuditProject(absPath)
		licList = license.AnalyzeResultLicenses(result, nil)
		if *scanSecrets || program != nil {
			result.SecretCount = len(secList)
		}
		eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Now().UTC())
		if program != nil {
			program.Send(ui.DoneMsg{
				Result:     result,
				Evaluation: &eval,
				Secrets:    secList,
				IaC:        iacList,
				Licenses:   licList,
			})
		}
		resultChan <- result
	}()

	// Run TUI if enabled
	if !*noTUI {
		var err error
		finalModel, err = program.Run()
		if err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
	}

	// If context canceled (user quit), wait for scan to finish and exit early
	if ctx.Err() != nil {
		wg.Wait() // Wait for scan goroutine to exit
		return nil
	}

	// Wait for scan to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Check for scan errors or results
	select {
	case err := <-errorChan:
		return err
	case result := <-resultChan:
		// Print masked secret findings in CLI mode when requested (never raw plaintext).
		if *scanSecrets && len(secList) > 0 {
			fmt.Printf("\n󰌆 Secret Scan Findings (%d leaked credentials/secrets detected):\n", len(secList))
			for _, f := range secList {
				relPath, _ := filepath.Rel(absPath, f.FilePath)
				if relPath == "" {
					relPath = f.FilePath
				}
				fmt.Printf("  • [%s] %s:%d -> %s (masked)\n", f.Type, relPath, f.LineNumber, secrets.MaskSecret(f.Match))
			}
		}

		// Handle result
		var model *ui.Model
		if finalModel != nil {
			model = finalModel.(*ui.Model)
		}
		return handleScanResult(result, *outputFmt, model)
	case <-done:
		// Scan completed but no result was sent
		return fmt.Errorf("scan completed with no results")
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("scan timeout: took longer than 5 minutes")
	}
}

// handleScanResult displays results and handles output
func handleScanResult(result *types.ScanResult, outputFmt string, finalModel *ui.Model) error {
	if outputFmt != "" {
		switch outputFmt {
		case "csv":
			if err := export.CSV(result, os.Stdout); err != nil {
				return err
			}
		case "markdown":
			if err := export.Markdown(result, os.Stdout); err != nil {
				return err
			}
		case "json":
			if err := export.JSON(result, os.Stdout); err != nil {
				return err
			}
		case "cyclonedx":
			if err := export.CycloneDX(result, os.Stdout); err != nil {
				return err
			}
		case "spdx":
			if err := export.SPDX(result, os.Stdout); err != nil {
				return err
			}
		case "sarif":
			eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Now().UTC())
			if err := policy.WriteSARIF(os.Stdout, result.LockFile, eval); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown output format: %s", outputFmt)
		}
	} else {
		// Print summary
		fmt.Printf("\n󰄬 Scan complete: %d dependencies, %d vulnerabilities\n",
			len(result.Dependencies), result.TotalVulns)
		if result.Coverage.TotalPackages > 0 {
			fmt.Printf("  Coverage: %d scanned, %d failed, %d skipped, %d unsupported\n",
				result.Coverage.ScannedPackages,
				result.Coverage.FailedPackages,
				result.Coverage.SkippedPackages,
				result.Coverage.UnsupportedPackages,
			)
		}
		if result.Coverage.FailedPackages > 0 {
			fmt.Printf("  ⚠️  Incomplete scan: %d package(s) failed vulnerability lookup\n", result.Coverage.FailedPackages)
		}
		if result.CriticalVulns > 0 {
			fmt.Printf("  󰅚 Critical: %d\n", result.CriticalVulns)
		}
		if result.HighVulns > 0 {
			fmt.Printf("  󰀦 High:     %d\n", result.HighVulns)
		}
		if result.MediumVulns > 0 {
			fmt.Printf("  󰀦 Medium:   %d\n", result.MediumVulns)
		}
		if result.LowVulns > 0 {
			fmt.Printf("  󰌵 Low:      %d\n", result.LowVulns)
		}
		if result.UnknownVulns > 0 {
			fmt.Printf("  󰌵 Unknown:  %d\n", result.UnknownVulns)
		}
	}

	if result.CriticalVulns > 0 || result.HighVulns > 0 {
		return &ExitError{Code: 1}
	}

	return nil
}

// TUIAdapter adapts the scan.ProgressReporter interface to Bubbletea messages
type TUIAdapter struct {
	program *tea.Program
}

func (t *TUIAdapter) Error(msg string) {
	if t.program != nil {
		t.program.Send(ui.ErrorMsg{Err: msg})
	}
}

func (t *TUIAdapter) Progress(current, total int, currentPkg string, currentVulns int) {
	if t.program != nil {
		t.program.Send(ui.ProgressMsg{
			Progress: ui.ScanProgress{
				Current:      current,
				Total:        total,
				CurrentPkg:   currentPkg,
				CurrentVulns: currentVulns,
			},
		})
	}
}

func (t *TUIAdapter) Vulnerability(vuln types.Vulnerability, pkg string, path []string) {
	if t.program != nil {
		// Determine display CVE ID (prefer CVE-* over GHSA-*)
		displayCVE := vuln.ID
		if vuln.CVEID != "" {
			displayCVE = vuln.CVEID
		}

		// Determine display severity (prefer CVESeverity from NVD if available)
		displaySeverity := string(vuln.Severity)
		if vuln.CVESeverity != "" {
			displaySeverity = string(vuln.CVESeverity)
		}
		if displaySeverity == "" {
			displaySeverity = "unknown"
		}

		// Format published date
		publishedStr := ""
		if vuln.PublishedAt != nil {
			publishedStr = vuln.PublishedAt.Format("2006-01-02")
		}

		t.program.Send(ui.VulnMsg{
			Entry: ui.VulnEntry{
				Package:        pkg,
				CVE:            displayCVE,
				CVEID:          vuln.CVEID,
				Severity:       displaySeverity,
				CVSS:           vuln.CVSSScore,
				Description:    vuln.Summary,
				CVETitle:       vuln.CVETitle,
				CVEDescription: vuln.CVEDescription,
				PublishedAt:    publishedStr,
				DependencyPath: path,
			},
		})
	}
}

func (t *TUIAdapter) Done(_ *types.ScanResult) {
	// DoneMsg is sent by cli.Scan after all secondary scanners (Secrets, IaC, Licenses)
	// and policy evaluation complete so the TUI never enters explorer mode with empty tabs.
}
