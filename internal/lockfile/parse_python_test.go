package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseUVLock verifies parsing of uv.lock TOML file.
func TestParseUVLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "uv.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open uv.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParseUVLock(f)
	if err != nil {
		t.Fatalf("ParseUVLock returned error: %v", err)
	}

	if deps.Production["requests"] != "2.25.0" {
		t.Errorf("expected requests 2.25.0, got %s", deps.Production["requests"])
	}
	if deps.Production["urllib3"] != "1.26.4" {
		t.Errorf("expected urllib3 1.26.4, got %s", deps.Production["urllib3"])
	}
	if deps.Development["pytest"] != "6.2.2" {
		t.Errorf("expected pytest 6.2.2 in dev, got %s", deps.Development["pytest"])
	}
}

// TestParseUVLockGraph verifies graph building for uv.lock.
func TestParseUVLockGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "uv.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open uv.lock: %v", err)
	}
	defer f.Close()

	graph, err := ParseUVLockGraph(f)
	if err != nil {
		t.Fatalf("ParseUVLockGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemPyPI {
		t.Errorf("expected PyPI ecosystem, got %s", graph.Ecosystem)
	}

	reqNode := graph.Nodes["requests@2.25.0"]
	if reqNode == nil {
		t.Fatalf("requests@2.25.0 node not found in graph")
	}
	if reqNode.Ecosystem != types.EcosystemPyPI {
		t.Errorf("expected node ecosystem PyPI, got %s", reqNode.Ecosystem)
	}

	// Check child connection requests -> urllib3
	hasUrllib3 := false
	for _, child := range reqNode.Children {
		if child == "urllib3@1.26.4" {
			hasUrllib3 = true
			break
		}
	}
	if !hasUrllib3 {
		t.Errorf("expected requests to have child urllib3@1.26.4")
	}
}

// TestParsePoetryLock verifies parsing of poetry.lock TOML file.
func TestParsePoetryLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "poetry.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open poetry.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParsePoetryLock(f)
	if err != nil {
		t.Fatalf("ParsePoetryLock returned error: %v", err)
	}

	if deps.Production["jinja2"] != "2.11.2" {
		t.Errorf("expected jinja2 2.11.2, got %s", deps.Production["jinja2"])
	}
	if deps.Development["black"] != "20.8b1" {
		t.Errorf("expected black 20.8b1 in dev, got %s", deps.Development["black"])
	}
}

// TestParsePipfileLock verifies parsing of Pipfile.lock JSON file.
func TestParsePipfileLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "Pipfile.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Pipfile.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParsePipfileLock(f)
	if err != nil {
		t.Fatalf("ParsePipfileLock returned error: %v", err)
	}

	if deps.Production["django"] != "3.2.0" {
		t.Errorf("expected django 3.2.0, got %s", deps.Production["django"])
	}
	if deps.Development["flake8"] != "3.9.0" {
		t.Errorf("expected flake8 3.9.0 in dev, got %s", deps.Development["flake8"])
	}
}

// TestParseRequirementsTxt verifies parsing of requirements.txt text file.
func TestParseRequirementsTxt(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "requirements.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open requirements.txt: %v", err)
	}
	defer f.Close()

	deps, err := ParseRequirementsTxt(f)
	if err != nil {
		t.Fatalf("ParseRequirementsTxt returned error: %v", err)
	}

	if deps.Production["requests"] != "2.25.0" {
		t.Errorf("expected requests 2.25.0, got %s", deps.Production["requests"])
	}
	if deps.Production["urllib3"] != "1.26.4" {
		t.Errorf("expected urllib3 1.26.4, got %s", deps.Production["urllib3"])
	}
	if deps.Production["flask"] != "2.0.1" {
		t.Errorf("expected flask 2.0.1, got %s", deps.Production["flask"])
	}
	if deps.Production["gunicorn"] != "20.1.0" {
		t.Errorf("expected gunicorn 20.1.0, got %s", deps.Production["gunicorn"])
	}
}

func TestParsePoetryLockGraphAndGroups(t *testing.T) {
	content := `
[[package]]
name = "flask"
version = "2.3.2"
groups = ["main"]

[package.dependencies]
werkzeug = ">=2.3.3"

[[package]]
name = "werkzeug"
version = "2.3.6"
groups = ["main"]

[[package]]
name = "pytest"
version = "7.4.0"
groups = ["dev"]
`
	graph, err := ParsePoetryLockGraph(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParsePoetryLockGraph error: %v", err)
	}
	flask := graph.Nodes["flask@2.3.2"]
	werkzeug := graph.Nodes["werkzeug@2.3.6"]
	pytest := graph.Nodes["pytest@7.4.0"]
	if flask == nil || !flask.Direct || flask.Type != types.Production {
		t.Errorf("expected flask as direct production node, got %+v", flask)
	}
	if werkzeug == nil || werkzeug.Direct || werkzeug.Depth != 1 {
		t.Errorf("expected werkzeug as transitive depth-1 node, got %+v", werkzeug)
	}
	if pytest == nil || pytest.Type != types.Development {
		t.Errorf("expected pytest with groups=[\"dev\"] as Development, got %+v", pytest)
	}
}

func TestParseRequirementsTxtFlagsUnpinnedAsUnresolved(t *testing.T) {
	content := `
requests==2.31.0
urllib3>=1.26.0
flask
`
	deps, err := ParseRequirementsTxt(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParseRequirementsTxt error: %v", err)
	}
	if deps.Production["requests"] != "2.31.0" {
		t.Errorf("expected pinned requests==2.31.0, got %q", deps.Production["requests"])
	}
	if len(deps.Unresolved) != 2 || deps.Unresolved[0] != "flask" || deps.Unresolved[1] != "urllib3" {
		t.Errorf("expected unpinned/range entries [flask urllib3] in Unresolved, got %v", deps.Unresolved)
	}
}

func TestParseUVLockGraphDeterministicMultiVersionEdges(t *testing.T) {
	// Two versions of urllib3 exist in the lockfile; app-a pins 1.26.4 via inline table version,
	// confirming deterministic version-specific edge resolution across 20 runs.
	content := `
version = 1
revision = 1

[[package]]
name = "app-a"
version = "1.0.0"
dependencies = [
    { name = "urllib3", version = "1.26.4" },
]

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "urllib3"
version = "1.26.4"
`
	for i := 0; i < 20; i++ {
		graph, err := ParseUVLockGraph(strings.NewReader(content))
		if err != nil {
			t.Fatalf("ParseUVLockGraph error: %v", err)
		}
		appNode := graph.Nodes["app-a@1.0.0"]
		if appNode == nil || len(appNode.Children) != 1 || appNode.Children[0] != "urllib3@1.26.4" {
			t.Fatalf("iteration %d: expected app-a@1.0.0 to link exclusively to urllib3@1.26.4, got %+v", i, appNode)
		}
		if u2 := graph.Nodes["urllib3@2.0.7"]; u2 == nil || !u2.Direct {
			t.Fatalf("iteration %d: expected unreferenced urllib3@2.0.7 to remain root, got %+v", i, u2)
		}
	}
}

func TestPythonMultiVersionConstraintDisambiguationAndAmbiguityRefusal(t *testing.T) {
	// Case 1: Poetry lockfile with 2 versions of urllib3, disambiguated by ">=1.26,<2.0".
	disambiguated := `
[[package]]
name = "app"
version = "1.0.0"

[package.dependencies]
urllib3 = ">=1.26,<2.0"

[[package]]
name = "urllib3"
version = "1.26.4"

[[package]]
name = "urllib3"
version = "2.0.7"
`
	g1, err := ParsePoetryLockGraph(strings.NewReader(disambiguated))
	if err != nil {
		t.Fatalf("ParsePoetryLockGraph error: %v", err)
	}
	if len(g1.Ambiguous) != 0 {
		t.Errorf("expected 0 ambiguous edges when constraint uniquely selects 1.26.4, got %+v", g1.Ambiguous)
	}
	if app := g1.Nodes["app@1.0.0"]; app == nil || len(app.Children) != 1 || app.Children[0] != "urllib3@1.26.4" {
		t.Errorf("expected app@1.0.0 to link only to urllib3@1.26.4, got %+v", app)
	}

	// Case 2: Poetry lockfile with environment-marker array dependencies matching 2 versions
	// without target environment evaluation -> must NOT fabricate edges; must record Ambiguous.
	ambiguousTOML := `
[[package]]
name = "app"
version = "1.0.0"

[package.dependencies]
urllib3 = [
    {version = ">=1.26,<2.0", markers = "python_version < '3.11'"},
    {version = ">=2.0", markers = "python_version >= '3.11'"},
]

[[package]]
name = "urllib3"
version = "1.26.4"

[[package]]
name = "urllib3"
version = "2.0.7"
`
	g2, err := ParsePoetryLockGraph(strings.NewReader(ambiguousTOML))
	if err != nil {
		t.Fatalf("ParsePoetryLockGraph error on ambiguous TOML: %v", err)
	}
	if app := g2.Nodes["app@1.0.0"]; app == nil || len(app.Children) != 0 {
		t.Errorf("expected 0 fabricated edges on app@1.0.0 when resolution is ambiguous, got children=%v", app.Children)
	}
	if len(g2.Ambiguous) != 1 || len(g2.Ambiguous[0].Candidates) != 2 {
		t.Errorf("expected 1 AmbiguousDependency with 2 candidates, got %+v", g2.Ambiguous)
	}
	if g2.Nodes["urllib3@1.26.4"].Direct || g2.Nodes["urllib3@2.0.7"].Direct {
		t.Error("expected ambiguously referenced child nodes not to be falsely promoted to Direct=true")
	}
}

func TestPythonNegativeResolutionContracts(t *testing.T) {
	// Contract 1: Exact pin in uv.lock points to a version not present in lockfile ->
	// must record missing_exact_dependency in Unresolved and add zero edges (even if another version exists).
	missingPinUV := `
version = 1
revision = 1

[[package]]
name = "app"
version = "1.0.0"
dependencies = [
    { name = "urllib3", version = "1.26.4" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
`
	gPin, err := ParseUVLockGraph(strings.NewReader(missingPinUV))
	if err != nil {
		t.Fatalf("ParseUVLockGraph error: %v", err)
	}
	if app := gPin.Nodes["app@1.0.0"]; app == nil || len(app.Children) != 0 {
		t.Errorf("expected 0 edges when exact pin 1.26.4 is missing (must NOT link to 2.0.7), got %v", app.Children)
	}
	if len(gPin.Unresolved) != 1 || !strings.Contains(gPin.Unresolved[0].Reason, "missing_exact_dependency") {
		t.Errorf("expected 1 missing_exact_dependency in Unresolved, got %+v", gPin.Unresolved)
	}

	// Contract 2: Constraint in poetry.lock matches ZERO versions in lockfile (even with 1 candidate present) ->
	// must record constraint_unsatisfied in Unresolved and add zero edges.
	unsatisfiedPoetry := `
[[package]]
name = "app"
version = "1.0.0"

[package.dependencies]
urllib3 = "==1.26.4"

[[package]]
name = "urllib3"
version = "2.0.7"
`
	gUnsat, err := ParsePoetryLockGraph(strings.NewReader(unsatisfiedPoetry))
	if err != nil {
		t.Fatalf("ParsePoetryLockGraph error: %v", err)
	}
	if app := gUnsat.Nodes["app@1.0.0"]; app == nil || len(app.Children) != 0 {
		t.Errorf("expected 0 edges when constraint ==1.26.4 is unsatisfied by 2.0.7, got %v", app.Children)
	}
	if len(gUnsat.Unresolved) != 1 || !strings.Contains(gUnsat.Unresolved[0].Reason, "constraint_unsatisfied") {
		t.Errorf("expected 1 constraint_unsatisfied in Unresolved, got %+v", gUnsat.Unresolved)
	}

	// Contract 3: PEP 440 compatible release ~=1.4.5 must match 1.4.9 but reject 1.5.0.
	if ok, sup := matchesPythonVersionSpec("1.4.9", "~=1.4.5"); !sup || !ok {
		t.Errorf("expected 1.4.9 to satisfy ~=1.4.5, got ok=%v sup=%v", ok, sup)
	}
	if ok, sup := matchesPythonVersionSpec("1.5.0", "~=1.4.5"); !sup || ok {
		t.Errorf("expected 1.5.0 to be rejected by ~=1.4.5 (<1.5.0), got ok=%v sup=%v", ok, sup)
	}
}
