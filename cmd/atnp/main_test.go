package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionAndUsage(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"version"}, &buf); err != nil {
		t.Fatalf("run(version) returned error: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "atnp ") {
		t.Errorf("expected version output to start with 'atnp ', got %q", buf.String())
	}

	err := run(nil, &buf)
	if err == nil || !strings.Contains(err.Error(), "usage: atnp <scan|report|ci|explain|baseline|version> [args]") {
		t.Errorf("expected canonical atnp usage error when no args given, got %v", err)
	}

	err = run([]string{"unknown-subcmd"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "unknown command: unknown-subcmd") || !strings.Contains(err.Error(), "usage: atnp ") {
		t.Errorf("expected unknown command error with atnp usage, got %v", err)
	}
}
