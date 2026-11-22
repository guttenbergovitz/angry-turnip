package lockfile

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var propertyRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// ParsePomXml parses a Maven pom.xml manifest.
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

	props := extractPomProperties(data)

	type dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}

	type parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}

	type pom struct {
		GroupID              string       `xml:"groupId"`
		ArtifactID           string       `xml:"artifactId"`
		Version              string       `xml:"version"`
		Parent               *parent      `xml:"parent"`
		Dependencies         []dependency `xml:"dependencies>dependency"`
		ManagedDependencies  []dependency `xml:"dependencyManagement>dependencies>dependency"`
	}

	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal pom.xml: %w", err)
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

	// Index versions declared in local <dependencyManagement>.
	managedVersions := make(map[string]string, len(p.ManagedDependencies))
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
