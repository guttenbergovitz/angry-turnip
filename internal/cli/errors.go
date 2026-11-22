package cli

import (
	"fmt"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
)

// ExitError signals that a CLI command completed with a specific process exit code
// (for example exit code 1 for policy violations or exit code 2 for operational errors).
// Commands return ExitError instead of calling os.Exit directly so they remain testable.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

// resolveLockFile resolves either an explicitly provided lock file name or auto-detects
// a supported lock file in absPath.
func resolveLockFile(absPath, customLockFile string) (string, lockfile.LockFileType, error) {
	if customLockFile != "" {
		switch customLockFile {
		case "uv.lock":
			return customLockFile, lockfile.UVLock, nil
		case "poetry.lock":
			return customLockFile, lockfile.PoetryLock, nil
		case "Pipfile.lock":
			return customLockFile, lockfile.PipfileLock, nil
		case "requirements.txt":
			return customLockFile, lockfile.RequirementsTxt, nil
		case "package-lock.json":
			return customLockFile, lockfile.NPMLock, nil
		case "yarn.lock":
			return customLockFile, lockfile.YarnLock, nil
		case "pnpm-lock.yaml":
			return customLockFile, lockfile.PnpmLock, nil
		case "Cargo.lock":
			return customLockFile, lockfile.CargoLock, nil
		case "composer.lock":
			return customLockFile, lockfile.ComposerLock, nil
		case "go.mod":
			return customLockFile, lockfile.GoModLock, nil
		case "pom.xml":
			return customLockFile, lockfile.PomXml, nil
		case "gradle.lockfile":
			return customLockFile, lockfile.GradleLock, nil
		default:
			return "", "", fmt.Errorf("unsupported custom lock file: %s", customLockFile)
		}
	}

	lockFile, lockType, err := lockfile.FindLockFile(absPath)
	if err != nil {
		return "", "", fmt.Errorf("no lock file found in %s: %w\n\nSupported lock files: uv.lock, poetry.lock, Pipfile.lock, requirements.txt, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, composer.lock, go.mod, pom.xml, gradle.lockfile", absPath, err)
	}
	return lockFile, lockType, nil
}
