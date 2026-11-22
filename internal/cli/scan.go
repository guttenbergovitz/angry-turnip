package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/angry-turnip/internal/container"
	"github.com/guttenbergovitz/angry-turnip/internal/export"
	"github.com/guttenbergovitz/angry-turnip/internal/git"
	"github.com/guttenbergovitz/angry-turnip/internal/license"
	"github.com/guttenbergovitz/angry-turnip/internal/lockfile"
	"github.com/guttenbergovitz/angry-turnip/internal/policy"
	"github.com/guttenbergovitz/angry-turnip/internal/scan"
	"github.com/guttenbergovitz/angry-turnip/internal/secrets"
	"github.com/guttenbergovitz/angry-turnip/internal/types"
	"github.com/guttenbergovitz/angry-turnip/internal/ui"
)

// Scan executes the scan command
func Scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	skipDevDeps := fs.Bool("skip-devdeps", false, "Skip development dependencies")
	outputFmt := fs.String("output", "", "Output format (json, sarif, csv, markdown, cyclonedx, spdx)")
	noTUI := fs.Bool("no-tui", false, "Disable interactive TUI (useful for CI/testing)")
	customLockFile := fs.String("lockfile", "", "Explicitly specify lockfile name (e.g. uv.lock, requirements.txt)")
	scanSecrets := fs.Bool("secrets", false, "Scan codebase for hardcoded secrets and leaked credentials")
	scopeFlag := fs.String("scope", "all", "Scan scope: 'all' (SCA, Secrets, IaC, Licences) or 'sca' (SCA only)")
	progressFlag := fs.String("progress", "auto", "Progress display mode: 'auto', 'plain' (on stderr), or 'none'")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("scan: missing project path argument")
	}

	scope := strings.ToLower(strings.TrimSpace(*scopeFlag))
	if scope != "all" && scope != "sca" {
		return fmt.Errorf("invalid --scope %q (allowed: all, sca)", *scopeFlag)
	}
	progressMode := strings.ToLower(strings.TrimSpace(*progressFlag))
	if progressMode != "auto" && progressMode != "plain" && progressMode != "none" {
		return fmt.Errorf("invalid --progress %q (allowed: auto, plain, none)", *progressFlag)
	}

	// Never launch full-screen Bubble Tea TUI when machine-readable --output is requested,
	// when --progress plain/none is requested, or when stdout is not an interactive terminal.
	useTUI := !*noTUI && *outputFmt == "" && progressMode == "auto" && isInteractiveTerminal(os.Stdout)

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

	if useTUI {
		// Create Bubbletea model for progress display with alt screen
		model := ui.NewModel()
		model.SetTargetMetadata(projectPath, lockFile)
		model.SetCancelFunc(cancel) // Allow early quit to cancel scan
		program = tea.NewProgram(model, tea.WithAltScreen())
		reporter = &TUIAdapter{program: program}
	} else if progressMode == "plain" {
		reporter = &PlainStageReporter{out: os.Stderr}
	} else if *outputFmt == "" && progressMode != "none" {
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

		runSecondary := scope == "all" || *scanSecrets
		if runSecondary {
			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageSecrets, Status: scan.StageRunning, Message: "Scanning codebase for leaked credentials"})
			var secErr error
			secList, secErr = secrets.NewScanner().ScanDirectory(absPath)
			if secErr != nil {
				emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageSecrets, Status: scan.StageFailed, Message: "Secrets scan failed", Error: secErr.Error()})
			} else {
				emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageSecrets, Status: scan.StageCompleted, Current: len(secList), Message: fmt.Sprintf("%d secret finding(s)", len(secList))})
			}
		} else {
			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageSecrets, Status: scan.StageSkipped, Message: "Skipped (--scope sca)"})
		}

		if scope == "all" {
			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageIaC, Status: scan.StageRunning, Message: "Auditing Dockerfiles and CI workflows"})
			var iacErr error
			iacList, iacErr = container.AuditProject(absPath)
			if iacErr != nil {
				emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageIaC, Status: scan.StageFailed, Message: "IaC audit failed", Error: iacErr.Error()})
			} else {
				emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageIaC, Status: scan.StageCompleted, Current: len(iacList), Message: fmt.Sprintf("%d IaC issue(s)", len(iacList))})
			}

			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageLicences, Status: scan.StageRunning, Message: "Extracting package licence metadata"})
			licMap := license.ExtractLockfileLicenses(lockFilePath)
			licList = license.AnalyzeResultLicenses(result, licMap)
			knownLic := 0
			for _, l := range licList {
				if l.Category != license.Unknown {
					knownLic++
				}
			}
			licStatus := scan.StageCompleted
			if len(licList) > 0 && knownLic == 0 {
				licStatus = scan.StagePartial
			}
			emitCLIStage(reporter, scan.ScanEvent{
				Stage:   scan.StageLicences,
				Status:  licStatus,
				Current: knownLic,
				Message: fmt.Sprintf("%d/%d package licence(s) identified from lockfile", knownLic, len(licList)),
			})
		} else {
			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageIaC, Status: scan.StageSkipped, Message: "Skipped (--scope sca)"})
			emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StageLicences, Status: scan.StageSkipped, Message: "Skipped (--scope sca)"})
		}

		if *scanSecrets || scope == "all" || program != nil {
			result.SecretCount = len(secList)
		}

		emitCLIStage(reporter, scan.ScanEvent{Stage: scan.StagePolicy, Status: scan.StageRunning, Message: "Evaluating security policy"})
		eval := policy.Evaluate(result, policy.DefaultPolicy(), nil, time.Now().UTC())
		emitCLIStage(reporter, scan.ScanEvent{
			Stage:   scan.StagePolicy,
			Status:  scan.StageCompleted,
			Message: fmt.Sprintf("Decision: %s (Evidence: %s)", eval.OverallDecision, eval.EvidenceState),
		})

		if program != nil {
			program.Send(ui.DoneMsg{
				Result:     result,
				Evaluation: &eval,
				Graph:      result.Graph,
				Secrets:    secList,
				IaC:        iacList,
				Licenses:   licList,
			})
		}
		resultChan <- result
	}()

	// Run TUI if enabled
	if useTUI {
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

func (t *TUIAdapter) OnStageEvent(ev scan.ScanEvent) {
	if t.program != nil {
		t.program.Send(ui.StageEventMsg{
			Stage:     string(ev.Stage),
			Status:    string(ev.Status),
			Current:   ev.Current,
			Total:     ev.Total,
			Queued:    ev.Queued,
			Active:    ev.Active,
			Failed:    ev.Failed,
			Skipped:   ev.Skipped,
			Workers:   ev.Workers,
			Message:   ev.Message,
			Error:     ev.Error,
			Timestamp: ev.Timestamp,
		})
	}
}

// PlainStageReporter writes concise stage progress lines to an io.Writer (typically os.Stderr).
type PlainStageReporter struct {
	out *os.File
}

func (p *PlainStageReporter) Error(msg string) {
	if p.out != nil {
		fmt.Fprintf(p.out, "[error] %s\n", msg)
	}
}

func (p *PlainStageReporter) Progress(_, _ int, _ string, _ int)                        {}
func (p *PlainStageReporter) Vulnerability(_ types.Vulnerability, _ string, _ []string) {}
func (p *PlainStageReporter) Done(_ *types.ScanResult)                                  {}

func (p *PlainStageReporter) OnStageEvent(ev scan.ScanEvent) {
	if p.out == nil {
		return
	}
	if ev.Status == scan.StageCompleted || ev.Status == scan.StagePartial || ev.Status == scan.StageFailed || ev.Status == scan.StageSkipped {
		line := fmt.Sprintf("[%s] %s: %s", ev.Status, ev.Stage, ev.Message)
		if ev.Error != "" {
			line += " (" + ev.Error + ")"
		}
		fmt.Fprintln(p.out, line)
	}
}

func emitCLIStage(reporter scan.ProgressReporter, ev scan.ScanEvent) {
	if sr, ok := reporter.(scan.StageReporter); ok {
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now().UTC()
		}
		sr.OnStageEvent(ev)
	}
}

func isInteractiveTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
