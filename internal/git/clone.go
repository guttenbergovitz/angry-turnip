package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultCloneTimeout = 2 * time.Minute

// IsGitURL checks whether the path is a git repository URL.
func IsGitURL(path string) bool {
	return strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "git@") ||
		strings.HasPrefix(path, "ssh://")
}

// CloneToTemp clones a git repository to a temporary directory using a default timeout.
// Returns the temporary repository directory path and a cleanup function.
func CloneToTemp(repoURL string) (string, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloneTimeout)
	defer cancel()
	return CloneToTempContext(ctx, repoURL)
}

// CloneToTempContext clones a git repository to a temporary directory with context cancellation.
// When GITHUB_TOKEN is set for HTTPS GitHub URLs, credentials are passed via git environment
// configuration headers rather than embedded in the command-line URL, preventing exposure in
// process listings and error diagnostics.
func CloneToTempContext(ctx context.Context, repoURL string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "atnp-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	repoDir := filepath.Join(tmpDir, "repo")
	token := os.Getenv("GITHUB_TOKEN")

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, repoDir)
	cmd.Env = buildCloneEnv(os.Environ(), repoURL, token)

	output, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		redacted := redactSecret(string(output), token)
		return "", nil, fmt.Errorf("git clone failed: %w\nOutput: %s", err, redacted)
	}

	return repoDir, cleanup, nil
}

// buildCloneEnv constructs the environment for git clone, disabling interactive prompts and
// attaching a GitHub Basic Authorization extraheader via GIT_CONFIG_* environment variables
// when cloning an HTTPS github.com repository with a token.
func buildCloneEnv(baseEnv []string, repoURL, token string) []string {
	env := make([]string, 0, len(baseEnv)+4)
	env = append(env, baseEnv...)
	env = append(env, "GIT_TERMINAL_PROMPT=0")

	if token == "" || !isGitHubHTTPS(repoURL) {
		return env
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	env = append(env,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+encoded,
	)
	return env
}

func isGitHubHTTPS(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && strings.EqualFold(u.Hostname(), "github.com")
}

// redactSecret replaces any occurrence of secret (or its base64 encoding) in text with [REDACTED].
func redactSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	redacted := strings.ReplaceAll(text, secret, "[REDACTED]")
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + secret))
	redacted = strings.ReplaceAll(redacted, encoded, "[REDACTED]")
	return redacted
}
