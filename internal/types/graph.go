package types

import "time"

// DependencyNode represents a single package in the dependency tree.
type DependencyNode struct {
	Name            string
	Version         string
	Ecosystem       Ecosystem         // Package ecosystem (npm, PyPI, Go, Cargo, etc.)
	Type            DependencyType    // Production or development classification
	Direct          bool              // Whether direct dependency or transitive
	Ambiguous       bool              // True when incoming parent edge was ambiguous across versions
	Depth           int               // 0 = direct, 1 = dependency of direct, etc.
	Parents         []string          // Slice of "name@version" keys that depend on this package
	Children        []string          // Slice of "name@version" keys that this package depends on
	ReleasedAt      *time.Time        // Package release date (informational metadata only)
	ScanStatus      PackageScanStatus // Explicit scan outcome for this node
	ScanError       string            // Error message when ScanStatus is StatusFailed
	Vulnerabilities []Vulnerability   // Advisories matched for this package
}

// DependencyGraph represents a full dependency tree.
type DependencyGraph struct {
	Ecosystem Ecosystem                  // Overall ecosystem of graph
	Nodes     map[string]*DependencyNode // Keyed by "name@version"
	Root      []string                   // Direct dependencies: []"name@version"
	Ambiguous []AmbiguousDependency      // Dependency edges that matched >1 candidate version
}

// NewDependencyGraph creates a new empty graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Ecosystem: EcosystemNPM,
		Nodes:     make(map[string]*DependencyNode),
		Root:      make([]string, 0),
	}
}

// AddNode adds a node to the graph if it does not already exist.
func (g *DependencyGraph) AddNode(name, version string, typ DependencyType, direct bool) *DependencyNode {
	key := name + "@" + version
	if node, exists := g.Nodes[key]; exists {
		return node
	}

	node := &DependencyNode{
		Name:      name,
		Version:   version,
		Ecosystem: g.Ecosystem,
		Type:      typ,
		Direct:    direct,
		Depth:     -1,
		Parents:   make([]string, 0),
		Children:  make([]string, 0),
	}

	g.Nodes[key] = node
	return node
}

// AddEdge records a parent -> child dependency relationship.
func (g *DependencyGraph) AddEdge(parentKey, childKey string) {
	if parent, exists := g.Nodes[parentKey]; exists {
		parent.Children = append(parent.Children, childKey)
	}
	if child, exists := g.Nodes[childKey]; exists {
		child.Parents = append(child.Parents, parentKey)
	}
}

// CalculateDepths computes the minimum depth of each node from the roots using BFS.
func (g *DependencyGraph) CalculateDepths() {
	for _, node := range g.Nodes {
		node.Depth = -1
	}

	queue := make([]string, len(g.Root))
	copy(queue, g.Root)

	for _, key := range queue {
		if node, exists := g.Nodes[key]; exists {
			node.Depth = 0
		}
	}

	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]

		if node, exists := g.Nodes[key]; exists {
			for _, childKey := range node.Children {
				if child, childExists := g.Nodes[childKey]; childExists {
					if child.Depth < 0 || child.Depth > node.Depth+1 {
						child.Depth = node.Depth + 1
						queue = append(queue, childKey)
					}
				}
			}
		}
	}
}

// GetVulnerablePath returns a dependency path from a root node to the target node.
func (g *DependencyGraph) GetVulnerablePath(nodeKey string) []string {
	path := []string{nodeKey}
	node, exists := g.Nodes[nodeKey]
	if !exists {
		return path
	}

	current := nodeKey
	visited := make(map[string]bool)

	for len(node.Parents) > 0 && !visited[current] {
		visited[current] = true
		parentKey := node.Parents[0]
		path = append([]string{parentKey}, path...)

		if parent, exists := g.Nodes[parentKey]; exists {
			node = parent
			current = parentKey
		} else {
			break
		}
	}

	return path
}
