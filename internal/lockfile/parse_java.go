package lockfile

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var propertyRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomParent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type pomDocument struct {
	GroupID             string          `xml:"groupId"`
	ArtifactID          string          `xml:"artifactId"`
	Version             string          `xml:"version"`
	Parent              *pomParent      `xml:"parent"`
	Dependencies        []pomDependency `xml:"dependencies>dependency"`
	ManagedDependencies []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

// ParsePomXmlFile parses a Maven pom.xml file from disk and resolves inherited <properties>
// and <dependencyManagement> from local multi-module parent POMs (via <parent><relativePath>
// or default ../pom.xml) up to 5 ancestor levels.
func ParsePomXmlFile(pomPath string) (*Dependencies, error) {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, fmt.Errorf("read pom.xml: %w", err)
	}
	return parsePomXmlWithAncestors(data, filepath.Dir(pomPath))
}

// ParsePomXml parses a Maven pom.xml manifest from an io.Reader.
//
// Scope: reads direct <dependencies>, resolves local <properties>, <parent>, and
// <dependencyManagement> version declarations. Dependencies whose version is inherited
// from an external parent POM or BOM are recorded in Dependencies.Unresolved rather than
// silently discarded, so scan coverage accurately reflects unresolved entries.
func ParsePomXml(r io.Reader) (*Dependencies, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read pom.xml: %w", err)
	}
	return parsePomXmlWithAncestors(data, "")
}

func parsePomXmlWithAncestors(data []byte, baseDir string) (*Dependencies, error) {
	var p pomDocument
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal pom.xml: %w", err)
	}

	// Collect ancestor chain from root parent down to immediate parent when baseDir is known.
	type ancestorLayer struct {
		doc   pomDocument
		props map[string]string
	}
	var ancestors []ancestorLayer

	if baseDir != "" && p.Parent != nil {
		currDir := baseDir
		currParent := p.Parent
		visited := make(map[string]bool)
		for depth := 0; depth < 5 && currParent != nil; depth++ {
			relPath := strings.TrimSpace(currParent.RelativePath)
			if relPath == "" {
				relPath = filepath.Join("..", "pom.xml")
			}
			candidate := filepath.Join(currDir, relPath)
			if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
				candidate = filepath.Join(candidate, "pom.xml")
			}
			absCand, absErr := filepath.Abs(candidate)
			if absErr != nil || visited[absCand] {
				break
			}
			visited[absCand] = true

			parentBytes, readErr := os.ReadFile(absCand)
			if readErr != nil {
				break
			}
			var parentDoc pomDocument
			if xml.Unmarshal(parentBytes, &parentDoc) != nil {
				break
			}
			parentGroup := strings.TrimSpace(parentDoc.GroupID)
			if parentGroup == "" && parentDoc.Parent != nil {
				parentGroup = strings.TrimSpace(parentDoc.Parent.GroupID)
			}
			if strings.TrimSpace(currParent.ArtifactID) != "" && strings.TrimSpace(parentDoc.ArtifactID) != strings.TrimSpace(currParent.ArtifactID) {
				break
			}
			if strings.TrimSpace(currParent.GroupID) != "" && parentGroup != "" && parentGroup != strings.TrimSpace(currParent.GroupID) {
				break
			}

			ancestors = append(ancestors, ancestorLayer{
				doc:   parentDoc,
				props: extractPomProperties(parentBytes),
			})
			currDir = filepath.Dir(absCand)
			currParent = parentDoc.Parent
		}
	}

	// Merge properties from oldest ancestor down to child POM (child overrides parent).
	props := make(map[string]string)
	for i := len(ancestors) - 1; i >= 0; i-- {
		for k, v := range ancestors[i].props {
			props[k] = v
		}
	}
	for k, v := range extractPomProperties(data) {
		props[k] = v
	}

	// Populate built-in Maven project/parent properties.
	projectGroup := strings.TrimSpace(p.GroupID)
	projectVersion := strings.TrimSpace(p.Version)
	if p.Parent != nil {
		if projectGroup == "" {
			projectGroup = strings.TrimSpace(p.Parent.GroupID)
		}
		if projectVersion == "" {
			projectVersion = strings.TrimSpace(p.Parent.Version)
		}
		if strings.TrimSpace(p.Parent.Version) != "" {
			props["project.parent.version"] = strings.TrimSpace(p.Parent.Version)
		}
	}
	if projectGroup != "" {
		props["project.groupId"] = projectGroup
	}
	if projectVersion != "" {
		props["project.version"] = projectVersion
	}

	// Index versions declared in ancestor and local <dependencyManagement> (child overrides parent).
	managedVersions := make(map[string]string)
	for i := len(ancestors) - 1; i >= 0; i-- {
		for _, dep := range ancestors[i].doc.ManagedDependencies {
			groupID := resolvePomProperty(strings.TrimSpace(dep.GroupID), props)
			artifactID := resolvePomProperty(strings.TrimSpace(dep.ArtifactID), props)
			ver := resolvePomProperty(strings.TrimSpace(dep.Version), props)
			if groupID != "" && artifactID != "" && ver != "" && !propertyRegex.MatchString(ver) {
				managedVersions[groupID+":"+artifactID] = ver
			}
		}
	}
	for _, dep := range p.ManagedDependencies {
		groupID := resolvePomProperty(strings.TrimSpace(dep.GroupID), props)
		artifactID := resolvePomProperty(strings.TrimSpace(dep.ArtifactID), props)
		ver := resolvePomProperty(strings.TrimSpace(dep.Version), props)
		if groupID != "" && artifactID != "" && ver != "" && !propertyRegex.MatchString(ver) {
			managedVersions[groupID+":"+artifactID] = ver
		}
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	unresolvedSet := make(map[string]bool)

	for _, dep := range p.Dependencies {
		groupID := resolvePomProperty(strings.TrimSpace(dep.GroupID), props)
		artifactID := resolvePomProperty(strings.TrimSpace(dep.ArtifactID), props)
		version := strings.TrimSpace(dep.Version)
		scope := strings.TrimSpace(strings.ToLower(dep.Scope))

		if groupID == "" || artifactID == "" {
			continue
		}

		pkgName := groupID + ":" + artifactID

		if version == "" {
			version = managedVersions[pkgName]
		} else {
			version = resolvePomProperty(version, props)
		}

		// Record dependencies whose version could not be resolved locally (e.g. external BOM/parent).
		if version == "" || propertyRegex.MatchString(version) {
			unresolvedSet[pkgName] = true
			continue
		}

		if scope == "test" {
			deps.Development[pkgName] = version
		} else {
			deps.Production[pkgName] = version
		}
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

// ParseGradleLockfile parses Gradle gradle.lockfile format.
func ParseGradleLockfile(r io.Reader) (*Dependencies, error) {
	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 1 {
			continue
		}

		gav := strings.TrimSpace(parts[0])
		classpaths := ""
		if len(parts) == 2 {
			classpaths = strings.ToLower(parts[1])
		}

		gavParts := strings.Split(gav, ":")
		if len(gavParts) < 3 {
			continue
		}

		groupID := gavParts[0]
		artifactID := gavParts[1]
		version := gavParts[2]

		pkgName := groupID + ":" + artifactID

		isDev := false
		if classpaths != "" {
			isDev = true
			for _, cp := range strings.Split(classpaths, ",") {
				cp = strings.TrimSpace(cp)
				if !strings.HasPrefix(cp, "test") {
					isDev = false
					break
				}
			}
		}

		if isDev {
			deps.Development[pkgName] = version
		} else {
			deps.Production[pkgName] = version
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read gradle.lockfile: %w", err)
	}

	return deps, nil
}

func extractPomProperties(data []byte) map[string]string {
	props := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	inProperties := false
	var currentPropName string

	for {
		token, err := decoder.Token()
		if err != nil || token == nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "properties" {
				inProperties = true
			} else if inProperties {
				currentPropName = t.Name.Local
			}
		case xml.EndElement:
			if t.Name.Local == "properties" {
				inProperties = false
			} else if inProperties {
				currentPropName = ""
			}
		case xml.CharData:
			if inProperties && currentPropName != "" {
				val := strings.TrimSpace(string(t))
				if val != "" {
					props[currentPropName] = val
				}
			}
		}
	}

	return props
}

func resolvePomProperty(val string, props map[string]string) string {
	matches := propertyRegex.FindAllStringSubmatch(val, -1)
	resolved := val
	for _, match := range matches {
		if len(match) == 2 {
			propKey := match[1]
			if propVal, ok := props[propKey]; ok {
				resolved = strings.ReplaceAll(resolved, match[0], propVal)
			}
		}
	}
	return resolved
}
