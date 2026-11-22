package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseCargoLock verifies parsing of Rust Cargo.lock TOML file.
func TestParseCargoLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "rust", "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Cargo.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParseCargoLock(f)
	if err != nil {
		t.Fatalf("ParseCargoLock returned error: %v", err)
	}

	if deps.Production["smallvec"] != "1.6.0" {
		t.Errorf("expected smallvec 1.6.0, got %s", deps.Production["smallvec"])
	}
	if deps.Production["tokio"] != "1.8.0" {
		t.Errorf("expected tokio 1.8.0, got %s", deps.Production["tokio"])
	}
	if deps.Production["bytes"] != "1.0.1" {
		t.Errorf("expected bytes 1.0.1, got %s", deps.Production["bytes"])
	}
}

// TestParseCargoLockGraph verifies graph building for Rust Cargo.lock.
func TestParseCargoLockGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "rust", "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Cargo.lock: %v", err)
	}
	defer f.Close()

	graph, err := ParseCargoLockGraph(f)
	if err != nil {
		t.Fatalf("ParseCargoLockGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemCargo {
		t.Errorf("expected Cargo ecosystem, got %s", graph.Ecosystem)
	}

	tokioNode := graph.Nodes["tokio@1.8.0"]
	if tokioNode == nil {
		t.Fatalf("tokio@1.8.0 node not found in graph")
	}
	if tokioNode.Ecosystem != types.EcosystemCargo {
		t.Errorf("expected node ecosystem Cargo, got %s", tokioNode.Ecosystem)
	}

	// Verify child connections for tokio -> bytes
	hasBytes := false
	for _, child := range tokioNode.Children {
		if child == "bytes@1.0.1" {
			hasBytes = true
			break
		}
	}
	if !hasBytes {
		t.Errorf("expected tokio to have child bytes@1.0.1")
	}
}

func TestCargoMultiVersionExactAndAmbiguousEdges(t *testing.T) {
	// Version-qualified dependency ("syn 1.0.109") links to exact crate version;
	// unversioned dependency ("quote") when 2 versions exist records Ambiguous without fabricating edges.
	content := `
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "syn 1.0.109",
 "quote",
]

[[package]]
name = "syn"
version = "1.0.109"

[[package]]
name = "syn"
version = "2.0.39"

[[package]]
name = "quote"
version = "1.0.33"

[[package]]
name = "quote"
version = "0.6.13"
`
	graph, err := ParseCargoLockGraph(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParseCargoLockGraph error: %v", err)
	}
	app := graph.Nodes["my-app@0.1.0"]
	if app == nil || len(app.Children) != 1 || app.Children[0] != "syn@1.0.109" {
		t.Errorf("expected my-app@0.1.0 to link exclusively to syn@1.0.109 (no fabricated quote edges), got children=%v", app.Children)
	}
	if len(graph.Ambiguous) != 1 || graph.Ambiguous[0].Dependency != "quote" || len(graph.Ambiguous[0].Candidates) != 2 {
		t.Errorf("expected 1 AmbiguousDependency for quote with 2 candidates, got %+v", graph.Ambiguous)
	}
	if graph.Nodes["quote@1.0.33"].Direct || graph.Nodes["quote@0.6.13"].Direct {
		t.Error("expected ambiguously referenced quote versions not to be marked Direct=true")
	}
}
