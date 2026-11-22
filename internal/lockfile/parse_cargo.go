package lockfile

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type cargoDep struct {
	Name    string
	Version string
}

type cargoPackage struct {
	Name    string
	Version string
	Deps    []cargoDep
}

// ParseCargoLock parses Rust Cargo.lock TOML format into Dependencies.
func ParseCargoLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseCargoLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		if pkg.Name != "" && pkg.Version != "" {
			deps.Production[strings.ToLower(pkg.Name)] = pkg.Version
		}
	}

	return deps, nil
}

// ParseCargoLockGraph parses Rust Cargo.lock and builds a DependencyGraph with Cargo ecosystem
// metadata, resolving version-qualified edges deterministically when multiple crate versions exist.
func ParseCargoLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseCargoLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemCargo

	nodesByName := make(map[string][]string)

	for _, pkg := range pkgs {
		name := strings.ToLower(strings.TrimSpace(pkg.Name))
		if name == "" {
			continue
		}
		node := graph.AddNode(name, pkg.Version, types.Production, false)
		key := node.Name + "@" + node.Version
		nodesByName[name] = append(nodesByName[name], key)
	}
	for name := range nodesByName {
		sort.Strings(nodesByName[name])
	}

	for _, pkg := range pkgs {
		parentKey := strings.ToLower(strings.TrimSpace(pkg.Name)) + "@" + pkg.Version
		for _, dep := range pkg.Deps {
			depNameLower := strings.ToLower(strings.TrimSpace(dep.Name))
			if depNameLower == "" {
				continue
			}
			if dep.Version != "" {
				exactKey := depNameLower + "@" + dep.Version
				if _, ok := graph.Nodes[exactKey]; ok {
					graph.AddEdge(parentKey, exactKey)
					continue
				}
			}
			for _, childKey := range nodesByName[depNameLower] {
				graph.AddEdge(parentKey, childKey)
			}
		}
	}

	childKeys := make(map[string]bool)
	for _, node := range graph.Nodes {
		for _, child := range node.Children {
			childKeys[child] = true
		}
	}

	for key, node := range graph.Nodes {
		if !childKeys[key] {
			node.Direct = true
			graph.Root = append(graph.Root, key)
		}
	}
	sort.Strings(graph.Root)

	graph.CalculateDepths()
	return graph, nil
}

type cargoLockTOML struct {
	Packages []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"package"`
}

// parseCargoLockPackages parses Cargo.lock using a full TOML parser (github.com/BurntSushi/toml).
func parseCargoLockPackages(r io.Reader) ([]cargoPackage, error) {
	var doc cargoLockTOML
	if _, err := toml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode Cargo.lock TOML: %w", err)
	}

	pkgs := make([]cargoPackage, 0, len(doc.Packages))
	for _, rawPkg := range doc.Packages {
		name := strings.TrimSpace(rawPkg.Name)
		if name == "" {
			continue
		}
		deps := make([]cargoDep, 0, len(rawPkg.Dependencies))
		for _, depStr := range rawPkg.Dependencies {
			parts := strings.Fields(strings.TrimSpace(depStr))
			if len(parts) == 0 {
				continue
			}
			ver := ""
			if len(parts) >= 2 && !strings.HasPrefix(parts[1], "(") {
				ver = parts[1]
			}
			deps = append(deps, cargoDep{
				Name:    parts[0],
				Version: ver,
			})
		}
		pkgs = append(pkgs, cargoPackage{
			Name:    name,
			Version: strings.TrimSpace(rawPkg.Version),
			Deps:    deps,
		})
	}
	return pkgs, nil
}
