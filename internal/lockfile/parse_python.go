package lockfile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

// pythonDep represents a dependency reference with an optional exact version pin,
// version constraint specification, or environment marker.
type pythonDep struct {
	Name       string
	Version    string
	Constraint string
	Marker     string
	Optional   bool
}

// pythonPackage holds metadata parsed from Python TOML/JSON lock files.
type pythonPackage struct {
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Category string      `json:"category"`
	Dev      bool        `json:"dev"`
	Deps     []pythonDep `json:"deps"`
}

// ParseUVLock parses uv.lock TOML format into Dependencies.
func ParseUVLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseUVLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse uv.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		if pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// ParseUVLockGraph parses uv.lock and builds a DependencyGraph with PyPI ecosystem metadata.
func ParseUVLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseUVLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse uv.lock graph: %w", err)
	}
	return buildPythonGraph(pkgs), nil
}

// ParsePoetryLockGraph parses poetry.lock and builds a DependencyGraph preserving transitive
// [package.dependencies] edges and dev/main category or group classification.
func ParsePoetryLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parsePoetryLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse poetry.lock graph: %w", err)
	}
	return buildPythonGraph(pkgs), nil
}

func buildPythonGraph(pkgs []pythonPackage) *types.DependencyGraph {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemPyPI

	// Index all resolved node keys per package name in sorted order so edge resolution
	// is 100% deterministic even when multiple versions of the same package exist.
	nodesByName := make(map[string][]string)

	for _, pkg := range pkgs {
		name := strings.ToLower(strings.TrimSpace(pkg.Name))
		if name == "" {
			continue
		}
		depType := types.Production
		if pkg.Dev || pkg.Category == "dev" {
			depType = types.Development
		}
		node := graph.AddNode(name, pkg.Version, depType, false)
		key := node.Name + "@" + node.Version
		nodesByName[name] = append(nodesByName[name], key)
	}
	for name := range nodesByName {
		sort.Strings(nodesByName[name])
	}

	// Second pass: resolve dependency edges by exact (name, version) or version constraint.
	// Distinguishes three distinct data defects without fabricating edges:
	// 1. missing_exact_dependency: exact version pin does not exist in lockfile -> graph.Unresolved
	// 2. constraint_unsatisfied: zero versions in lockfile satisfy constraint -> graph.Unresolved
	// 3. ambiguous_candidates / unsupported_version_constraint: >1 candidates or unevaluable spec -> graph.Ambiguous
	ambiguousChildren := make(map[string]bool)
	for _, pkg := range pkgs {
		parentKey := strings.ToLower(strings.TrimSpace(pkg.Name)) + "@" + pkg.Version
		for _, dep := range pkg.Deps {
			depNameLower := strings.ToLower(strings.TrimSpace(dep.Name))
			if depNameLower == "" {
				continue
			}

			// 1. Exact version pin on dependency edge.
			if dep.Version != "" {
				exactKey := depNameLower + "@" + dep.Version
				if _, ok := graph.Nodes[exactKey]; ok {
					graph.AddEdge(parentKey, exactKey)
				} else {
					graph.Unresolved = append(graph.Unresolved, types.UnresolvedDependency{
						Package: fmt.Sprintf("%s@%s (required by %s)", depNameLower, dep.Version, parentKey),
						Reason:  "missing_exact_dependency: pinned dependency version is not present in lockfile",
					})
				}
				continue
			}

			candidates := nodesByName[depNameLower]
			if len(candidates) == 0 {
				if !dep.Optional {
					graph.Unresolved = append(graph.Unresolved, types.UnresolvedDependency{
						Package: fmt.Sprintf("%s (required by %s)", depNameLower, parentKey),
						Reason:  "missing_exact_dependency: required package is not present in lockfile",
					})
				}
				continue
			}

			// 2. Evaluate version constraint against all candidates (even when len(candidates) == 1)
			// so a single incompatible version in the lockfile is never falsely linked.
			if dep.Constraint != "" && dep.Constraint != "*" {
				var matched []string
				unsupportedSpec := false
				for _, candKey := range candidates {
					node := graph.Nodes[candKey]
					if node == nil {
						continue
					}
					ok, supported := matchesPythonVersionSpec(node.Version, dep.Constraint)
					if !supported {
						unsupportedSpec = true
						break
					}
					if ok {
						matched = append(matched, candKey)
					}
				}

				if unsupportedSpec {
					graph.Ambiguous = append(graph.Ambiguous, types.AmbiguousDependency{
						Parent:     parentKey,
						Dependency: depNameLower,
						Candidates: append([]string(nil), candidates...),
						Reason:     fmt.Sprintf("unsupported_version_constraint: constraint %q cannot be statically evaluated", dep.Constraint),
					})
					for _, candKey := range candidates {
						ambiguousChildren[candKey] = true
						if node := graph.Nodes[candKey]; node != nil {
							node.Ambiguous = true
						}
					}
					continue
				}

				if len(matched) == 0 {
					if !dep.Optional {
						graph.Unresolved = append(graph.Unresolved, types.UnresolvedDependency{
							Package: fmt.Sprintf("%s (%s, required by %s)", depNameLower, dep.Constraint, parentKey),
							Reason:  fmt.Sprintf("constraint_unsatisfied: zero versions in lockfile satisfy %q (available: %s)", dep.Constraint, strings.Join(candidates, ", ")),
						})
					}
					continue
				}

				if len(matched) == 1 {
					graph.AddEdge(parentKey, matched[0])
					continue
				}

				graph.Ambiguous = append(graph.Ambiguous, types.AmbiguousDependency{
					Parent:     parentKey,
					Dependency: depNameLower,
					Candidates: matched,
					Reason:     fmt.Sprintf("ambiguous_candidates: constraint %q matched %d candidate versions", dep.Constraint, len(matched)),
				})
				for _, candKey := range matched {
					ambiguousChildren[candKey] = true
					if node := graph.Nodes[candKey]; node != nil {
						node.Ambiguous = true
					}
				}
				continue
			}

			// 3. No version pin and no narrowing constraint.
			if len(candidates) == 1 {
				graph.AddEdge(parentKey, candidates[0])
				continue
			}

			reason := "ambiguous_candidates: multiple package versions present in lockfile without unique version pin"
			if dep.Marker != "" {
				reason = fmt.Sprintf("ambiguous_candidates: multiple package versions gated by environment marker (%s)", dep.Marker)
			}
			graph.Ambiguous = append(graph.Ambiguous, types.AmbiguousDependency{
				Parent:     parentKey,
				Dependency: depNameLower,
				Candidates: append([]string(nil), candidates...),
				Reason:     reason,
			})
			for _, candKey := range candidates {
				ambiguousChildren[candKey] = true
				if node := graph.Nodes[candKey]; node != nil {
					node.Ambiguous = true
				}
			}
		}
	}

	// Identify root nodes (nodes without parents and not only ambiguously referenced).
	childKeys := make(map[string]bool)
	for _, node := range graph.Nodes {
		for _, child := range node.Children {
			childKeys[child] = true
		}
	}

	for key, node := range graph.Nodes {
		if !childKeys[key] && !ambiguousChildren[key] {
			node.Direct = true
			graph.Root = append(graph.Root, key)
		}
	}
	sort.Strings(graph.Root)

	graph.CalculateDepths()
	for _, node := range graph.Nodes {
		if node.Ambiguous && node.Depth == -1 {
			node.Depth = 1
		}
	}
	return graph
}

type uvLockTOML struct {
	Packages []struct {
		Name            string           `toml:"name"`
		Version         string           `toml:"version"`
		Dev             bool             `toml:"dev"`
		Dependencies    []any            `toml:"dependencies"`
		DevDependencies map[string][]any `toml:"dev-dependencies"`
	} `toml:"package"`
}

// parseUVLockPackages parses uv.lock using a full TOML parser (github.com/BurntSushi/toml).
func parseUVLockPackages(r io.Reader) ([]pythonPackage, error) {
	var doc uvLockTOML
	if _, err := toml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode uv.lock TOML: %w", err)
	}

	devReferenced := make(map[string]bool)
	prodReferenced := make(map[string]bool)

	pkgs := make([]pythonPackage, 0, len(doc.Packages))
	for _, rawPkg := range doc.Packages {
		deps := parseTOMLDepArray(rawPkg.Dependencies)
		for _, d := range deps {
			prodReferenced[strings.ToLower(d.Name)] = true
		}
		for _, groupDeps := range rawPkg.DevDependencies {
			parsedDev := parseTOMLDepArray(groupDeps)
			for _, d := range parsedDev {
				devReferenced[strings.ToLower(d.Name)] = true
			}
			deps = append(deps, parsedDev...)
		}
		pkgs = append(pkgs, pythonPackage{
			Name:    strings.TrimSpace(rawPkg.Name),
			Version: strings.TrimSpace(rawPkg.Version),
			Dev:     rawPkg.Dev,
			Deps:    deps,
		})
	}

	for i := range pkgs {
		lower := strings.ToLower(pkgs[i].Name)
		if !pkgs[i].Dev && devReferenced[lower] && !prodReferenced[lower] {
			pkgs[i].Dev = true
		}
	}

	return pkgs, nil
}

func parseTOMLDepArray(items []any) []pythonDep {
	if len(items) == 0 {
		return nil
	}
	out := make([]pythonDep, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case map[string]any:
			name, _ := v["name"].(string)
			ver, _ := v["version"].(string)
			marker, _ := v["marker"].(string)
			if strings.TrimSpace(name) != "" {
				out = append(out, pythonDep{
					Name:    strings.TrimSpace(name),
					Version: strings.TrimSpace(ver),
					Marker:  strings.TrimSpace(marker),
				})
			}
		case string:
			parts := strings.Fields(strings.TrimSpace(v))
			if len(parts) == 1 {
				out = append(out, pythonDep{Name: parts[0]})
			} else if len(parts) >= 2 {
				out = append(out, pythonDep{Name: parts[0], Version: parts[1]})
			}
		}
	}
	return out
}

// ParsePoetryLock parses poetry.lock TOML format into Dependencies.
func ParsePoetryLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parsePoetryLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		if pkg.Category == "dev" || pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

type poetryLockTOML struct {
	Packages []struct {
		Name         string         `toml:"name"`
		Version      string         `toml:"version"`
		Category     string         `toml:"category"`
		Groups       []string       `toml:"groups"`
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"package"`
}

// parsePoetryLockPackages parses poetry.lock using a full TOML parser (github.com/BurntSushi/toml).
func parsePoetryLockPackages(r io.Reader) ([]pythonPackage, error) {
	var doc poetryLockTOML
	if _, err := toml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode poetry.lock TOML: %w", err)
	}

	pkgs := make([]pythonPackage, 0, len(doc.Packages))
	for _, rawPkg := range doc.Packages {
		isDev := strings.EqualFold(rawPkg.Category, "dev")
		if !isDev && len(rawPkg.Groups) > 0 {
			hasMain := false
			hasDevOrTest := false
			for _, g := range rawPkg.Groups {
				if strings.EqualFold(g, "main") {
					hasMain = true
				}
				if strings.EqualFold(g, "dev") || strings.EqualFold(g, "test") {
					hasDevOrTest = true
				}
			}
			if !hasMain && hasDevOrTest {
				isDev = true
			}
		}

		depKeys := make([]string, 0, len(rawPkg.Dependencies))
		for k := range rawPkg.Dependencies {
			depKeys = append(depKeys, k)
		}
		sort.Strings(depKeys)

		deps := make([]pythonDep, 0, len(depKeys))
		for _, k := range depKeys {
			constraint, marker, optional := extractPoetryDepSpec(rawPkg.Dependencies[k])
			deps = append(deps, pythonDep{
				Name:       strings.TrimSpace(k),
				Constraint: constraint,
				Marker:     marker,
				Optional:   optional,
			})
		}

		pkgs = append(pkgs, pythonPackage{
			Name:     strings.TrimSpace(rawPkg.Name),
			Version:  strings.TrimSpace(rawPkg.Version),
			Category: strings.TrimSpace(rawPkg.Category),
			Dev:      isDev,
			Deps:     deps,
		})
	}

	return pkgs, nil
}

func extractPoetryDepSpec(raw any) (constraint, marker string, optional bool) {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v), "", false
	case map[string]any:
		ver, _ := v["version"].(string)
		m, _ := v["markers"].(string)
		opt, _ := v["optional"].(bool)
		return strings.TrimSpace(ver), strings.TrimSpace(m), opt
	case []any:
		// Array of environment-specific dependency tables in poetry.lock: cannot be reduced
		// to a single static constraint without target environment evaluation.
		var markers []string
		for _, elem := range v {
			if m, ok := elem.(map[string]any); ok {
				if mk, ok := m["markers"].(string); ok && strings.TrimSpace(mk) != "" {
					markers = append(markers, strings.TrimSpace(mk))
				}
			}
		}
		return "", strings.Join(markers, " | "), false
	default:
		return "", "", false
	}
}

// matchesPythonVersionSpec evaluates supported numeric PEP 440 / Poetry version constraints
// (==, !=, >=, <=, >, <, ~=, ^) against a concrete numeric version string.
// Returns (matched, supported). If the version or specifier uses unsupported pre-release,
// post-release, local, or union syntax, supported=false is returned so the caller records
// the edge as ambiguous rather than guessing.
func matchesPythonVersionSpec(version, spec string) (bool, bool) {
	version = strings.TrimSpace(version)
	spec = strings.TrimSpace(spec)
	if version == "" || spec == "" || spec == "*" {
		return true, true
	}
	vParts, vOK := parseStrictNumericVersion(version)
	if !vOK {
		return false, false
	}
	if strings.Contains(spec, "||") || strings.Contains(spec, "|") || strings.Contains(spec, "@") || strings.Contains(spec, "===") {
		return false, false
	}

	// Handle Poetry Caret (^1.2.3 -> >=1.2.3, <2.0.0; ^0.2.3 -> >=0.2.3, <0.3.0; ^0.0.3 -> >=0.0.3, <0.0.4)
	if strings.HasPrefix(spec, "^") {
		base := strings.TrimSpace(strings.TrimPrefix(spec, "^"))
		bParts, ok := parseStrictNumericVersion(base)
		if !ok {
			return false, false
		}
		if compareVersionSlices(vParts, bParts) < 0 {
			return false, true
		}
		upper := []int{bParts[0] + 1, 0, 0}
		if bParts[0] == 0 {
			if len(bParts) > 1 && bParts[1] > 0 {
				upper = []int{0, bParts[1] + 1, 0}
			} else if len(bParts) > 2 {
				upper = []int{0, 0, bParts[2] + 1}
			}
		}
		return compareVersionSlices(vParts, upper) < 0, true
	}

	// Handle comma-separated PEP 440 clauses (e.g. ">=1.26,<2.0" or "~=1.4.5")
	for _, clause := range strings.Split(spec, ",") {
		c := strings.TrimSpace(clause)
		if c == "" {
			continue
		}
		switch {
		case strings.HasPrefix(c, "~="):
			// PEP 440 compatible release: ~= V.N requires >= V.N and < (V+1).0;
			// ~= V.N.M requires >= V.N.M and < V.(N+1).0 (pads/Drops last segment and increments second-to-last).
			base := strings.TrimSpace(strings.TrimPrefix(c, "~="))
			bParts, ok := parseStrictNumericVersion(base)
			if !ok || len(bParts) < 2 {
				return false, false
			}
			if compareVersionSlices(vParts, bParts) < 0 {
				return false, true
			}
			upper := make([]int, len(bParts)-1)
			copy(upper, bParts[:len(bParts)-1])
			upper[len(upper)-1]++
			if compareVersionSlices(vParts, upper) >= 0 {
				return false, true
			}
		case strings.HasPrefix(c, "=="):
			target := strings.TrimSpace(strings.TrimPrefix(c, "=="))
			if strings.HasSuffix(target, ".*") {
				prefixStr := strings.TrimSuffix(target, ".*")
				pParts, ok := parseStrictNumericVersion(prefixStr)
				if !ok {
					return false, false
				}
				for i, pv := range pParts {
					vv := 0
					if i < len(vParts) {
						vv = vParts[i]
					}
					if vv != pv {
						return false, true
					}
				}
			} else {
				tParts, ok := parseStrictNumericVersion(target)
				if !ok {
					return false, false
				}
				if compareVersionSlices(vParts, tParts) != 0 {
					return false, true
				}
			}
		case strings.HasPrefix(c, "!="):
			target := strings.TrimSpace(strings.TrimPrefix(c, "!="))
			if strings.HasSuffix(target, ".*") {
				return false, false
			}
			tParts, ok := parseStrictNumericVersion(target)
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) == 0 {
				return false, true
			}
		case strings.HasPrefix(c, ">="):
			tParts, ok := parseStrictNumericVersion(strings.TrimSpace(strings.TrimPrefix(c, ">=")))
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) < 0 {
				return false, true
			}
		case strings.HasPrefix(c, "<="):
			tParts, ok := parseStrictNumericVersion(strings.TrimSpace(strings.TrimPrefix(c, "<=")))
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) > 0 {
				return false, true
			}
		case strings.HasPrefix(c, ">"):
			tParts, ok := parseStrictNumericVersion(strings.TrimSpace(strings.TrimPrefix(c, ">")))
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) <= 0 {
				return false, true
			}
		case strings.HasPrefix(c, "<"):
			tParts, ok := parseStrictNumericVersion(strings.TrimSpace(strings.TrimPrefix(c, "<")))
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) >= 0 {
				return false, true
			}
		default:
			tParts, ok := parseStrictNumericVersion(c)
			if !ok {
				return false, false
			}
			if compareVersionSlices(vParts, tParts) != 0 {
				return false, true
			}
		}
	}
	return true, true
}

// parseStrictNumericVersion parses dotted non-negative integers (e.g. "1.26.4").
// Returns ok=false if any segment contains pre-release, post-release, local, or wildcard tokens.
func parseStrictNumericVersion(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	segments := strings.Split(v, ".")
	out := make([]int, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			return nil, false
		}
		num := 0
		for _, r := range seg {
			if r < '0' || r > '9' {
				return nil, false
			}
			num = num*10 + int(r-'0')
		}
		out = append(out, num)
	}
	return out, true
}

func compareVersionSlices(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(a) {
			va = a[i]
		}
		if i < len(b) {
			vb = b[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

// ParsePipfileLock parses Pipfile.lock JSON format into Dependencies.
func ParsePipfileLock(r io.Reader) (*Dependencies, error) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	cleanVersion := func(v string) string {
		v = strings.TrimPrefix(v, "==")
		v = strings.TrimPrefix(v, "=")
		return strings.TrimSpace(v)
	}

	for pkgName, pkg := range lock.Default {
		deps.Production[strings.ToLower(pkgName)] = cleanVersion(pkg.Version)
	}
	for pkgName, pkg := range lock.Develop {
		deps.Development[strings.ToLower(pkgName)] = cleanVersion(pkg.Version)
	}

	return deps, nil
}

var (
	reqPinnedRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)(?:\[[a-zA-Z0-9_\-\.,\s]+\])?\s*===?\s*([a-zA-Z0-9_\-\.\+]+)$`)
	reqNameRegex   = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)`)
)

// ParseRequirementsTxt parses requirements.txt format into Dependencies.
// Only exact pinned versions (== or ===) are recorded in Production; unpinned or
// range-constrained entries (>=, ~=, >, <, !=, or bare package names) are recorded in
// Unresolved so scan coverage accurately flags non-deterministic requirements.
func ParseRequirementsTxt(r io.Reader) (*Dependencies, error) {
	scanner := bufio.NewScanner(r)
	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}
	unresolvedSet := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments or environment markers / hashes
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, " --"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if matches := reqPinnedRegex.FindStringSubmatch(line); len(matches) == 3 {
			pkgName := strings.ToLower(matches[1])
			pkgVer := strings.TrimSpace(matches[2])
			if pkgName != "" && pkgVer != "" {
				deps.Production[pkgName] = pkgVer
				delete(unresolvedSet, pkgName)
			}
			continue
		}

		if matches := reqNameRegex.FindStringSubmatch(line); len(matches) >= 2 {
			pkgName := strings.ToLower(matches[1])
			if pkgName != "" {
				if _, ok := deps.Production[pkgName]; !ok {
					unresolvedSet[pkgName] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse requirements.txt: %w", err)
	}

	if len(unresolvedSet) > 0 {
		deps.Unresolved = make([]string, 0, len(unresolvedSet))
		for pkg := range unresolvedSet {
			deps.Unresolved = append(deps.Unresolved, pkg)
		}
		sort.Strings(deps.Unresolved)
	}

	return deps, nil
}
