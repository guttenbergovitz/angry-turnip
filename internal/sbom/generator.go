package sbom

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
	"github.com/guttenbergovitz/angry-turnip/internal/version"
)

// canonicalComponent represents a normalised component and its outgoing dependency keys
// used to render deterministic CycloneDX and SPDX documents.
type canonicalComponent struct {
	Key       string // "name@version"
	Name      string
	Version   string
	Ecosystem types.Ecosystem
	Direct    bool
	DependsOn []string
	PURL      string
	SPDXID    string
}

// GenerateCycloneDX generates a deterministic CycloneDX v1.5 JSON SBOM including
// component metadata and dependency graph relationships.
func GenerateCycloneDX(result *types.ScanResult, graph *types.DependencyGraph, w io.Writer) error {
	projectName := normaliseProjectName(result)
	toolVersion := currentToolVersion()
	serialUUID, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("generate CycloneDX UUID: %w", err)
	}

	components := buildCanonicalComponents(graph, result)
	rootRef := fmt.Sprintf("pkg:generic/%s@root", sanitiseRefSegment(projectName))

	cdxComponents := make([]map[string]interface{}, 0, len(components))
	for _, c := range components {
		cdxComponents = append(cdxComponents, map[string]interface{}{
			"type":    "library",
			"bom-ref": c.PURL,
			"name":    c.Name,
			"version": c.Version,
			"purl":    c.PURL,
		})
	}

	cdxDependencies := buildCycloneDXDependencies(rootRef, components)

	cycloneDX := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"version":      1,
		"serialNumber": "urn:uuid:" + serialUUID,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]interface{}{
				{
					"vendor":  "Angry Turnip",
					"name":    "atnp",
					"version": toolVersion,
				},
			},
			"component": map[string]interface{}{
				"bom-ref": rootRef,
				"name":    projectName,
				"type":    "application",
			},
		},
		"components":   cdxComponents,
		"dependencies": cdxDependencies,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cycloneDX); err != nil {
		return fmt.Errorf("encode CycloneDX JSON: %w", err)
	}

	return nil
}

// GenerateSPDX generates a deterministic SPDX v2.3 JSON SBOM including
// collision-free package SPDXIDs and DESCRIBES/DEPENDS_ON relationships.
func GenerateSPDX(result *types.ScanResult, graph *types.DependencyGraph, w io.Writer) error {
	projectName := normaliseProjectName(result)
	toolVersion := currentToolVersion()
	nsUUID, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("generate SPDX namespace UUID: %w", err)
	}

	components := buildCanonicalComponents(graph, result)
	rootSPDXID := "SPDXRef-Application-" + sanitiseSPDXSegment(projectName)

	spdxPackages := make([]map[string]interface{}, 0, len(components)+1)
	spdxPackages = append(spdxPackages, map[string]interface{}{
		"name":             projectName,
		"SPDXID":           rootSPDXID,
		"downloadLocation": "NOASSERTION",
		"filesAnalyzed":    false,
	})

	for _, c := range components {
		spdxPackages = append(spdxPackages, map[string]interface{}{
			"name":             c.Name,
			"SPDXID":           c.SPDXID,
			"versionInfo":      c.Version,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"externalRefs": []map[string]interface{}{
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType":     "purl",
					"referenceLocator":  c.PURL,
				},
			},
		})
	}

	relationships := buildSPDXRelationships(rootSPDXID, components)

	spdx := map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              projectName,
		"documentNamespace": fmt.Sprintf("https://spdx.org/spdxdocs/angry-turnip-%s-%s", sanitiseSPDXSegment(projectName), nsUUID),
		"creationInfo": map[string]interface{}{
			"created": time.Now().UTC().Format(time.RFC3339),
			"creators": []string{
				"Tool: atnp-" + toolVersion,
			},
		},
		"packages":      spdxPackages,
		"relationships": relationships,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(spdx); err != nil {
		return fmt.Errorf("encode SPDX JSON: %w", err)
	}

	return nil
}

func buildCanonicalComponents(graph *types.DependencyGraph, result *types.ScanResult) []canonicalComponent {
	lockFile := ""
	if result != nil {
		lockFile = result.LockFile
	}

	byKey := make(map[string]canonicalComponent)

	if graph != nil && len(graph.Nodes) > 0 {
		for key, node := range graph.Nodes {
			eco := node.Ecosystem
			if eco == "" {
				eco = graph.Ecosystem
			}
			children := append([]string(nil), node.Children...)
			sort.Strings(children)
			byKey[key] = canonicalComponent{
				Key:       key,
				Name:      node.Name,
				Version:   node.Version,
				Ecosystem: eco,
				Direct:    node.Direct,
				DependsOn: dedupeSorted(children),
				PURL:      buildPurl(node.Name, node.Version, eco, lockFile),
				SPDXID:    buildSPDXID(eco, node.Name, node.Version),
			}
		}
	} else if result != nil {
		for _, dep := range result.Dependencies {
			key := dep.Name + "@" + dep.Version
			children := append([]string(nil), dep.DependsOn...)
			sort.Strings(children)
			byKey[key] = canonicalComponent{
				Key:       key,
				Name:      dep.Name,
				Version:   dep.Version,
				Ecosystem: dep.Ecosystem,
				Direct:    dep.Direct,
				DependsOn: dedupeSorted(children),
				PURL:      buildPurl(dep.Name, dep.Version, dep.Ecosystem, lockFile),
				SPDXID:    buildSPDXID(dep.Ecosystem, dep.Name, dep.Version),
			}
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	components := make([]canonicalComponent, 0, len(keys))
	for _, k := range keys {
		components = append(components, byKey[k])
	}
	return components
}

func buildCycloneDXDependencies(rootRef string, components []canonicalComponent) []map[string]interface{} {
	purlByKey := make(map[string]string, len(components))
	directRefs := make([]string, 0)
	for _, c := range components {
		purlByKey[c.Key] = c.PURL
		if c.Direct {
			directRefs = append(directRefs, c.PURL)
		}
	}
	sort.Strings(directRefs)

	deps := make([]map[string]interface{}, 0, len(components)+1)
	deps = append(deps, map[string]interface{}{
		"ref":       rootRef,
		"dependsOn": directRefs,
	})

	for _, c := range components {
		childRefs := make([]string, 0, len(c.DependsOn))
		for _, childKey := range c.DependsOn {
			if childPURL, ok := purlByKey[childKey]; ok {
				childRefs = append(childRefs, childPURL)
			}
		}
		sort.Strings(childRefs)
		deps = append(deps, map[string]interface{}{
			"ref":       c.PURL,
			"dependsOn": childRefs,
		})
	}

	return deps
}

func buildSPDXRelationships(rootSPDXID string, components []canonicalComponent) []map[string]interface{} {
	idByKey := make(map[string]string, len(components))
	for _, c := range components {
		idByKey[c.Key] = c.SPDXID
	}

	relationships := make([]map[string]interface{}, 0, len(components)+1)
	relationships = append(relationships, map[string]interface{}{
		"spdxElementId":      "SPDXRef-DOCUMENT",
		"relationshipType":   "DESCRIBES",
		"relatedSpdxElement": rootSPDXID,
	})

	for _, c := range components {
		if c.Direct {
			relationships = append(relationships, map[string]interface{}{
				"spdxElementId":      rootSPDXID,
				"relationshipType":   "DEPENDS_ON",
				"relatedSpdxElement": c.SPDXID,
			})
		}
	}

	for _, c := range components {
		for _, childKey := range c.DependsOn {
			if childID, ok := idByKey[childKey]; ok {
				relationships = append(relationships, map[string]interface{}{
					"spdxElementId":      c.SPDXID,
					"relationshipType":   "DEPENDS_ON",
					"relatedSpdxElement": childID,
				})
			}
		}
	}

	return relationships
}

func buildPurl(pkg, ver string, eco types.Ecosystem, lockFile string) string {
	if eco == "" && lockFile != "" {
		lf := strings.ToLower(lockFile)
		switch {
		case strings.Contains(lf, "uv.lock"), strings.Contains(lf, "poetry.lock"), strings.Contains(lf, "pipfile.lock"), strings.Contains(lf, "requirements.txt"):
			eco = types.EcosystemPyPI
		case strings.Contains(lf, "cargo.lock"):
			eco = types.EcosystemCargo
		case strings.Contains(lf, "composer.lock"):
			eco = types.EcosystemPackagist
		case strings.Contains(lf, "go.mod"):
			eco = types.EcosystemGo
		case strings.Contains(lf, "pom.xml"), strings.Contains(lf, "gradle.lockfile"):
			eco = types.EcosystemMaven
		default:
			eco = types.EcosystemNPM
		}
	}

	switch eco {
	case types.EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", pkg, ver)
	case types.EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", pkg, ver)
	case types.EcosystemCargo:
		return fmt.Sprintf("pkg:cargo/%s@%s", pkg, ver)
	case types.EcosystemPackagist:
		return fmt.Sprintf("pkg:composer/%s@%s", pkg, ver)
	case types.EcosystemMaven:
		// Maven coordinates are stored as "groupId:artifactId"; PURL uses "pkg:maven/groupId/artifactId@version".
		if groupID, artifactID, ok := strings.Cut(pkg, ":"); ok {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, ver)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", pkg, ver)
	default:
		cleanPkg := pkg
		if strings.HasPrefix(pkg, "@") {
			cleanPkg = strings.ReplaceAll(pkg, "@", "%40")
		}
		return fmt.Sprintf("pkg:npm/%s@%s", cleanPkg, ver)
	}
}

// buildSPDXID produces a deterministic, collision-resistant SPDXRef identifier
// containing only valid SPDX characters ([a-zA-Z0-9.-]).
func buildSPDXID(eco types.Ecosystem, name, ver string) string {
	sum := sha256.Sum256([]byte(string(eco) + "/" + name + "@" + ver))
	shortHash := hex.EncodeToString(sum[:4])
	return fmt.Sprintf("SPDXRef-Package-%s-%s-%s", sanitiseSPDXSegment(name), sanitiseSPDXSegment(ver), shortHash)
}

func sanitiseSPDXSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return "pkg"
	}
	return res
}

func sanitiseRefSegment(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "-")
}

func normaliseProjectName(result *types.ScanResult) string {
	if result == nil || result.ProjectPath == "" {
		return "root-project"
	}
	name := filepath.Base(result.ProjectPath)
	if name == "." || name == "/" || name == "" {
		return "root-project"
	}
	return name
}

func currentToolVersion() string {
	v := strings.TrimSpace(version.Version)
	if v == "" || v == "dev" {
		return version.Get()
	}
	return strings.TrimPrefix(v, "v")
}

// newUUIDv4 generates a random RFC 4122 version 4 UUID string.
func newUUIDv4() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}

func dedupeSorted(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if len(out) == 0 || out[len(out)-1] != item {
			out = append(out, item)
		}
	}
	return out
}
