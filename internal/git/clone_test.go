package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"https://github.com/user/repo", true},
		{"http://github.com/user/repo", true},
		{"git@github.com:user/repo.git", true},
		{"ssh://git@github.com/user/repo.git", true},
		{"/path/to/local/dir", false},
		{"./relative/path", false},
		{"C:\\Windows\\Path", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsGitURL(tt.path)
			if result != tt.expected {
				t.Errorf("IsGitURL(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestBuildCloneEnvUsesExtraHeaderNotURL(t *testing.T) {
	token := "ghp_super_secret_token_123"
	env := buildCloneEnv(nil, "https://github.com/org/private-repo", token)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GIT_TERMINAL_PROMPT=0") {
		t.Error("expected GIT_TERMINAL_PROMPT=0 in clone env")
	}
	if !strings.Contains(joined, "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader") {
		t.Error("expected GIT_CONFIG_KEY_0 extraheader for github.com HTTPS URL")
	}
	if strings.Contains(joined, token) {
		t.Error("raw token must not appear unencoded in env")
	}

	// Non-GitHub HTTPS URL must not receive GitHub token header.
	nonGH := buildCloneEnv(nil, "https://gitlab.com/org/repo", token)
	if strings.Contains(strings.Join(nonGH, "\n"), "GIT_CONFIG_COUNT") {
		t.Error("GitHub token header must not be attached to non-GitHub URLs")
	}
}

func TestRedactSecret(t *testing.T) {
	token := "ghp_secret_value"
	msg := "fatal: auth failed with " + token
	redacted := redactSecret(msg, token)
	if strings.Contains(redacted, token) {
		t.Errorf("token was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in output: %s", redacted)
	}
}

func TestCloneToTemp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network git clone test in -short mode")
	}

	url := "https://github.com/guttenbergovitz/vigil-cli"
	t.Logf("Cloning %s", url)

	repoDir, cleanup, err := CloneToTemp(url)
	if err != nil {
		t.Fatalf("CloneToTemp failed: %v", err)
	}

	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		cleanup()
		t.Fatalf("Repository directory does not exist: %s", repoDir)
	}

	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cleanup()
		t.Fatalf(".git directory does not exist: %s", gitDir)
	}

	cleanup()

	if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
		t.Errorf("Cleanup failed: directory still exists: %s", repoDir)
	}
}
