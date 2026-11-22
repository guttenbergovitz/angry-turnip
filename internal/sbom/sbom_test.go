package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

var uuidV4Regex = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func createSampleGraph() (*types.ScanResult, *types.DependencyGraph) {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemNPM
	graph.AddNode("express", "4.18.2", types.Production, true)
	graph.AddNode("body-parser", "1.19.0", types.Production, false)
	graph.AddEdge("express@4.18.2", "body-parser@1.19.0")

	result := &types.ScanResult{
		Version:     1,
		ProjectPath: "/app",
		ScannedAt:   time.Now().UTC(),
		LockFile:    "package-lock.json",
		Dependencies: []types.Dependency{
			{
				Name:      "express",
				Version:   "4.18.2",
				Type:      types.Production,
				Direct:    true,
				Ecosystem: types.EcosystemNPM,
				DependsOn: []string{"body-parser@1.19.0"},
			},
			{
				Name:      "body-parser",
				Version:   "1.19.0",
				Type:      types.Production,
				Direct:    false,
				Ecosystem: types.EcosystemNPM,
			},
		},
	}

	return result, graph
}

func TestGenerateCycloneDXIncludesValidUUIDAndDependencies(t *testing.T) {
	result, graph := createSampleGraph()
	var buf bytes.Buffer

	if err := GenerateCycloneDX(result, graph, &buf); err != nil {
		t.Fatalf("GenerateCycloneDX returned error: %v", err)
	}

	var jsonOut map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonOut); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if jsonOut["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", jsonOut["bomFormat"])
	}
	if jsonOut["specVersion"] != "1.5" {
		t.Errorf("expected specVersion 1.5, got %v", jsonOut["specVersion"])
	}

	serial, _ := jsonOut["serialNumber"].(string)
	if !uuidV4Regex.MatchString(serial) {
		t.Errorf("expected valid RFC 4122 UUID v4 serialNumber, got %q", serial)
	}

	components, ok := jsonOut["components"].([]interface{})
	if !ok || len(components) != 2 {
		t.Fatalf("expected 2 components in CycloneDX output, got %v", jsonOut["components"])
	}

	// Verify deterministic ordering: body-parser before express.
	firstComp := components[0].(map[string]interface{})
	if firstComp["name"] != "body-parser" {
		t.Errorf("expected deterministic alphabetical ordering with body-parser first, got %v", firstComp["name"])
	}

	deps, ok := jsonOut["dependencies"].([]interface{})
	if !ok || len(deps) != 3 {
		t.Fatalf("expected 3 dependency entries (root + 2 components), got %v", jsonOut["dependencies"])
	}

	// Verify express dependsOn body-parser.
	foundEdge := false
	for _, raw := range deps {
		entry := raw.(map[string]interface{})
		if entry["ref"] == "pkg:npm/express@4.18.2" {
			dependsOn := entry["dependsOn"].([]interface{})
			if len(dependsOn) == 1 && dependsOn[0] == "pkg:npm/body-parser@1.19.0" {
				foundEdge = true
			}
		}
	}
	if !foundEdge {
		t.Errorf("expected CycloneDX dependencies to contain express -> body-parser edge, got %v", deps)
	}
}

func TestGenerateCycloneDXFromScanResultWithoutGraph(t *testing.T) {
	result, _ := createSampleGraph()
	var buf bytes.Buffer

	// Passing nil graph must still emit dependency relationships from ScanResult.Dependencies.
	if err := GenerateCycloneDX(result, nil, &buf); err != nil {
		t.Fatalf("GenerateCycloneDX(nil graph) returned error: %v", err)
	}

	if !strings.Contains(buf.String(), `"pkg:npm/body-parser@1.19.0"`) {
		t.Errorf("expected body-parser dependency reference in output")
	}
}

func TestGenerateSPDXIncludesRelationshipsAndAvoidsIDCollisions(t *testing.T) {
	result := &types.ScanResult{
		Version:     1,
		ProjectPath: "/app",
		ScannedAt:   time.Now().UTC(),
		LockFile:    "pom.xml",
		Dependencies: []types.Dependency{
			{
				Name:      "org.apache.logging.log4j:log4j-core",
				Version:   "2.14.1",
				Ecosystem: types.EcosystemMaven,
				Direct:    true,
			},
			// Two names that previously collided after naive sanitisation.
			{
				Name:      "a/b",
				Version:   "1.0.0",
				Ecosystem: types.EcosystemNPM,
				Direct:    true,
			},
			{
				Name:      "a-b",
				Version:   "1.0.0",
				Ecosystem: types.EcosystemNPM,
				Direct:    true,
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateSPDX(result, nil, &buf); err != nil {
		t.Fatalf("GenerateSPDX returned error: %v", err)
	}

	var jsonOut map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonOut); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if jsonOut["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion SPDX-2.3, got %v", jsonOut["spdxVersion"])
	}

	packages, ok := jsonOut["packages"].([]interface{})
	if !ok || len(packages) != 4 { // root application + 3 dependencies
		t.Fatalf("expected 4 packages (root + 3 deps), got %d", len(packages))
	}

	// Ensure all SPDXIDs are unique.
	seenIDs := make(map[string]bool)
	for _, raw := range packages {
		pkg := raw.(map[string]interface{})
		id := pkg["SPDXID"].(string)
		if seenIDs[id] {
			t.Errorf("duplicate SPDXID detected: %s", id)
		}
		seenIDs[id] = true
	}

	// Ensure Maven PURL is formatted properly.
	if !strings.Contains(buf.String(), "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") {
		t.Errorf("expected Maven PURL in SPDX output, got:\n%s", buf.String())
	}

	relationships, ok := jsonOut["relationships"].([]interface{})
	if !ok || len(relationships) < 4 {
		t.Fatalf("expected DESCRIBES and DEPENDS_ON relationships, got %v", jsonOut["relationships"])
	}
}
