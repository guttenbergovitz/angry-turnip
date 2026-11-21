package lockfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Dependencies holds parsed production and development dependencies.
type Dependencies struct {
	Production  map[string]string
	Development map[string]string
}

// ParseNPMLock parses npm package-lock.json format.
func ParseNPMLock(r io.Reader) (*Dependencies, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse npm lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for pkgPath, pkg := range lock.Packages {
		// Skip root package
		if pkgPath == "" || pkg.Version == "" {
			continue
		}

		// Extract package name from path
		// For scoped packages: "node_modules/@scope/name" -> "@scope/name"
		// For regular packages: "node_modules/name" -> "name"
		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
			// Remove any nested node_modules subdirectories (transitive deps)
			// e.g., "node_modules/foo/node_modules/bar" -> "bar"
			if subIdx := strings.Index(name, "/node_modules/"); subIdx >= 0 {
				name = name[subIdx+len("/node_modules/"):]
			}
		}

		if pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// ParseNPMLockGraph parses npm package-lock.json and returns full dependency graph.
func ParseNPMLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	var lock struct {
		Packages map[string]struct {
			Version         string            `json:"version"`
			Dev             bool              `json:"dev"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		} `json:"packages"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse npm lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	pkgPathToNodeKey := make(map[string]string)

	// Extract package name from node_modules path
	extractName := func(pkgPath string) string {
		if pkgPath == "" {
			return ""
		}

		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
			// Remove nested node_modules subdirs
			if subIdx := strings.Index(name, "/node_modules/"); subIdx >= 0 {
				name = name[subIdx+len("/node_modules/"):]
			}
		}
		return name
	}

	// First pass: add all nodes
	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" || pkg.Version == "" {
			continue
		}

		name := extractName(pkgPath)
		if name == "" {
			continue
		}

		typ := types.Production
		if pkg.Dev {
			typ = types.Development
		}

		node := graph.AddNode(name, pkg.Version, typ, false)
		pkgPathToNodeKey[pkgPath] = node.Name + "@" + node.Version
	}

	// Helper to resolve child package key using node_modules hierarchy
	findChildKey := func(parentPath, childName string) string {
		curr := parentPath
		for {
			candidatePath := "node_modules/" + childName
			if curr != "" {
				candidatePath = curr + "/node_modules/" + childName
			}
			if key, ok := pkgPathToNodeKey[candidatePath]; ok {
				return key
			}
			if curr == "" {
				break
			}
			idx := strings.LastIndex(curr, "/node_modules/")
			if idx >= 0 {
				curr = curr[:idx]
			} else {
				curr = ""
			}
		}
		// Fallback: search by package name in graph
		for key, node := range graph.Nodes {
			if node.Name == childName {
				return key
			}
		}
		return ""
	}

	// Second pass: add edges from dependencies field
	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" {
			continue
		}

		parentKey, ok := pkgPathToNodeKey[pkgPath]
		if !ok {
			continue
		}

		for childName := range pkg.Dependencies {
			childKey := findChildKey(pkgPath, childName)
			if childKey != "" {
				graph.AddEdge(parentKey, childKey)
			}
		}
	}

	// Third pass: identify roots from root package (packages[""])
	if rootPkg, ok := lock.Packages[""]; ok {
		for childName := range rootPkg.Dependencies {
			childKey := findChildKey("", childName)
			if childKey != "" {
				if node, exists := graph.Nodes[childKey]; exists {
					node.Direct = true
					graph.Root = append(graph.Root, childKey)
				}
			}
		}
		for childName := range rootPkg.DevDependencies {
			childKey := findChildKey("", childName)
			if childKey != "" {
				if node, exists := graph.Nodes[childKey]; exists {
					node.Direct = true
					node.Type = types.Development
					graph.Root = append(graph.Root, childKey)
				}
			}
		}
	}

	// Fallback for roots if none detected
	if len(graph.Root) == 0 {
		childNodes := make(map[string]bool)
		for _, node := range graph.Nodes {
			for _, child := range node.Children {
				childNodes[child] = true
			}
		}

		for key, node := range graph.Nodes {
			if !childNodes[key] && !node.Direct {
				node.Direct = true
				graph.Root = append(graph.Root, key)
			}
		}
	}

	graph.CalculateDepths()

	return graph, nil
}

// LockFileType represents the type of lock file.
type LockFileType string

const (
	NPMLock         LockFileType = "npm"
	YarnLock        LockFileType = "yarn"
	PnpmLock        LockFileType = "pnpm"
	UVLock          LockFileType = "uv"
	PoetryLock      LockFileType = "poetry"
	PipfileLock     LockFileType = "pipfile"
	RequirementsTxt LockFileType = "requirements"
	CargoLock       LockFileType = "cargo"
	ComposerLock    LockFileType = "composer"
	GoModLock       LockFileType = "gomod"
	PomXml          LockFileType = "pomxml"
	GradleLock      LockFileType = "gradlelock"
)

// Ecosystem maps a lock file type to its target package ecosystem.
func (t LockFileType) Ecosystem() types.Ecosystem {
	switch t {
	case UVLock, PoetryLock, PipfileLock, RequirementsTxt:
		return types.EcosystemPyPI
	case CargoLock:
		return types.EcosystemCargo
	case ComposerLock:
		return types.EcosystemPackagist
	case GoModLock:
		return types.EcosystemGo
	case PomXml, GradleLock:
		return types.EcosystemMaven
	default:
		return types.EcosystemNPM
	}
}

// FindLockFile searches for supported lock files in the given directory in priority order.
// Returns the filename and type of the first found lock file, or error if none found.
func FindLockFile(dir string) (string, LockFileType, error) {
	candidates := []struct {
		name string
		typ  LockFileType
	}{
		{"pom.xml", PomXml},
		{"gradle.lockfile", GradleLock},
		{"uv.lock", UVLock},
		{"poetry.lock", PoetryLock},
		{"Pipfile.lock", PipfileLock},
		{"requirements.txt", RequirementsTxt},
		{"package-lock.json", NPMLock},
		{"yarn.lock", YarnLock},
		{"pnpm-lock.yaml", PnpmLock},
		{"Cargo.lock", CargoLock},
		{"composer.lock", ComposerLock},
		{"go.mod", GoModLock},
	}

	for _, candidate := range candidates {
		path := filepath.Join(dir, candidate.name)
		if _, err := os.Stat(path); err == nil {
			return candidate.name, candidate.typ, nil
		}
	}

	return "", "", errors.New("no supported lock file found (pom.xml, gradle.lockfile, uv.lock, poetry.lock, Pipfile.lock, requirements.txt, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, composer.lock, go.mod)")
}

// ParseLockFile dispatches to the correct parser based on lock file type.
func ParseLockFile(r io.Reader, typ LockFileType) (*Dependencies, error) {
	switch typ {
	case NPMLock:
		return ParseNPMLock(r)
	case PnpmLock:
		return ParsePnpmLock(r)
	case YarnLock:
		return ParseYarnLock(r)
	case UVLock:
		return ParseUVLock(r)
	case PoetryLock:
		return ParsePoetryLock(r)
	case PipfileLock:
		return ParsePipfileLock(r)
	case RequirementsTxt:
		return ParseRequirementsTxt(r)
	case CargoLock:
		return ParseCargoLock(r)
	case ComposerLock:
		return ParseComposerLock(r)
	case GoModLock:
		return ParseGoMod(r)
	case PomXml:
		return ParsePomXml(r)
	case GradleLock:
		return ParseGradleLockfile(r)
	default:
		return nil, fmt.Errorf("unknown or unsupported lock file type: %s", typ)
	}
}

// ParsePackageJSON extracts name and version from package.json.
func ParsePackageJSON(r io.Reader) (map[string]interface{}, error) {
	var pkg map[string]interface{}

	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	return pkg, nil
}
