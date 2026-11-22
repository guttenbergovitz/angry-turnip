package lockfile

import (
	"fmt"
	"io"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

type goPackage struct {
	Name           string
	Version        string
	IsIndirect     bool
	IsLocalReplace bool
}

// ParseGoMod parses a Go go.mod file into Dependencies using golang.org/x/mod/modfile.
//
// In Go modules, "// indirect" denotes a transitive module requirement rather than a
// development-only dependency. All resolved requirements are therefore classified as
// production dependencies so that --skip-devdeps never silently excludes runtime modules.
func ParseGoMod(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseGoModPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		if pkg.IsLocalReplace {
			deps.Unresolved = append(deps.Unresolved, pkg.Name)
			continue
		}
		deps.Production[pkg.Name] = pkg.Version
	}

	return deps, nil
}

// ParseGoModGraph parses a Go go.mod file and builds a DependencyGraph with Go ecosystem metadata.
// Direct and indirect requirements are distinguished via DependencyNode.Direct while keeping
// DependencyNode.Type as Production, because go.mod does not separate build/dev scopes.
// Modules replaced by a local filesystem directory (no upstream version) are marked StatusUnsupported.
func ParseGoModGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseGoModPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemGo

	for _, pkg := range pkgs {
		direct := !pkg.IsIndirect
		ver := pkg.Version
		if pkg.IsLocalReplace {
			ver = ""
		}
		node := graph.AddNode(pkg.Name, ver, types.Production, direct)
		if pkg.IsLocalReplace {
			node.ScanStatus = types.StatusUnsupported
			node.ScanError = "local filesystem replace directive (no upstream module version)"
		}
		if direct {
			graph.Root = append(graph.Root, node.Name+"@"+node.Version)
		}
	}

	graph.CalculateDepths()

	// Indirect modules in go.mod lack explicit parent edges without `go mod graph`,
	// so assign depth 1 rather than leaving them at -1 (which indicates orphaned nodes).
	for _, node := range graph.Nodes {
		if !node.Direct && node.Depth == -1 {
			node.Depth = 1
		}
	}

	return graph, nil
}

// parseGoModPackages parses go.mod using the official golang.org/x/mod/modfile parser,
// applying exclude and replace directives.
func parseGoModPackages(r io.Reader) ([]goPackage, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse modfile: %w", err)
	}

	excluded := make(map[module.Version]bool, len(file.Exclude))
	for _, ex := range file.Exclude {
		excluded[ex.Mod] = true
	}

	// Index replace directives: exact version matches take precedence over path-only matches.
	replaceExact := make(map[module.Version]module.Version)
	replacePath := make(map[string]module.Version)
	for _, rep := range file.Replace {
		if rep.Old.Version != "" {
			replaceExact[rep.Old] = rep.New
		} else {
			replacePath[rep.Old.Path] = rep.New
		}
	}

	pkgs := make([]goPackage, 0, len(file.Require))
	seen := make(map[string]bool, len(file.Require))

	for _, req := range file.Require {
		mod := req.Mod
		if excluded[mod] {
			continue
		}

		// Apply replace directives when the target is a versioned module; mark local filesystem
		// replacements (where rep.Version == "") so they are reported as unsupported rather than
		// queried under a placeholder version.
		localReplace := false
		if rep, ok := replaceExact[mod]; ok {
			if rep.Version != "" {
				mod = rep
			} else {
				localReplace = true
			}
		} else if rep, ok := replacePath[mod.Path]; ok {
			if rep.Version != "" {
				mod = rep
			} else {
				localReplace = true
			}
		}

		key := mod.Path + "@" + mod.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		pkgs = append(pkgs, goPackage{
			Name:           mod.Path,
			Version:        mod.Version,
			IsIndirect:     req.Indirect,
			IsLocalReplace: localReplace,
		})
	}

	return pkgs, nil
}
