package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseGoMod verifies that direct and indirect Go requirements are both classified
// as production dependencies (since // indirect denotes transitive, not development).
func TestParseGoMod(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "go", "go.mod")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open go.mod: %v", err)
	}
	defer f.Close()

	deps, err := ParseGoMod(f)
	if err != nil {
		t.Fatalf("ParseGoMod returned error: %v", err)
	}

	if deps.Production["github.com/gin-gonic/gin"] != "v1.7.0" {
		t.Errorf("expected gin v1.7.0 in production, got %q", deps.Production["github.com/gin-gonic/gin"])
	}
	if deps.Production["github.com/gofiber/fiber/v2"] != "v2.20.0" {
		t.Errorf("expected fiber v2.20.0 in production, got %q", deps.Production["github.com/gofiber/fiber/v2"])
	}
	if deps.Production["github.com/valyala/fasthttp"] != "v1.30.0" {
		t.Errorf("expected indirect fasthttp v1.30.0 in production, got %q", deps.Production["github.com/valyala/fasthttp"])
	}
	if len(deps.Development) != 0 {
		t.Errorf("expected no development dependencies for go.mod, got %v", deps.Development)
	}
}

// TestParseGoModGraph verifies direct vs indirect separation while preserving Production type.
func TestParseGoModGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "go", "go.mod")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open go.mod: %v", err)
	}
	defer f.Close()

	graph, err := ParseGoModGraph(f)
	if err != nil {
		t.Fatalf("ParseGoModGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemGo {
		t.Errorf("expected Go ecosystem, got %s", graph.Ecosystem)
	}

	ginNode := graph.Nodes["github.com/gin-gonic/gin@v1.7.0"]
	if ginNode == nil {
		t.Fatalf("github.com/gin-gonic/gin@v1.7.0 node not found in graph")
	}
	if ginNode.Ecosystem != types.EcosystemGo {
		t.Errorf("expected node ecosystem Go, got %s", ginNode.Ecosystem)
	}
	if ginNode.Type != types.Production {
		t.Errorf("expected direct module type Production, got %s", ginNode.Type)
	}
	if !ginNode.Direct || ginNode.Depth != 0 {
		t.Errorf("expected direct module with depth 0, got direct=%v depth=%d", ginNode.Direct, ginNode.Depth)
	}

	fasthttpNode := graph.Nodes["github.com/valyala/fasthttp@v1.30.0"]
	if fasthttpNode == nil {
		t.Fatalf("github.com/valyala/fasthttp@v1.30.0 node not found in graph")
	}
	if fasthttpNode.Type != types.Production {
		t.Errorf("expected indirect module type Production, got %s", fasthttpNode.Type)
	}
	if fasthttpNode.Direct {
		t.Errorf("expected indirect module to have Direct=false")
	}
	if fasthttpNode.Depth != 1 {
		t.Errorf("expected indirect module depth 1, got %d", fasthttpNode.Depth)
	}
}

// TestParseGoModReplaceAndExclude verifies that replace and exclude directives are honoured.
func TestParseGoModReplaceAndExclude(t *testing.T) {
	content := `module example.com/app

go 1.24.0

require (
	example.com/direct v1.0.0
	example.com/replaced v1.0.0
	example.com/excluded v0.1.0
	example.com/transitive/v2 v2.0.0 // indirect
)

exclude example.com/excluded v0.1.0

replace example.com/replaced v1.0.0 => example.com/fork v1.2.3
`

	graph, err := ParseGoModGraph(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParseGoModGraph returned error: %v", err)
	}

	if _, exists := graph.Nodes["example.com/excluded@v0.1.0"]; exists {
		t.Error("expected excluded module to be omitted")
	}
	if _, exists := graph.Nodes["example.com/replaced@v1.0.0"]; exists {
		t.Error("expected replaced module original version to be substituted")
	}
	if _, exists := graph.Nodes["example.com/fork@v1.2.3"]; !exists {
		t.Error("expected replacement module example.com/fork@v1.2.3 to be present")
	}
	transitive := graph.Nodes["example.com/transitive/v2@v2.0.0"]
	if transitive == nil {
		t.Fatal("expected transitive module to be present")
	}
	if transitive.Type != types.Production || transitive.Direct {
		t.Errorf("expected transitive module to be Production and Direct=false, got type=%s direct=%v", transitive.Type, transitive.Direct)
	}
}

// TestParseGoModInvalid verifies that malformed go.mod input returns an error.
func TestParseGoModInvalid(t *testing.T) {
	_, err := ParseGoMod(strings.NewReader("this is not valid go.mod syntax {{{"))
	if err == nil {
		t.Fatal("expected error for invalid go.mod, got nil")
	}
}
