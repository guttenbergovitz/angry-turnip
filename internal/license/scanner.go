package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

// LicenseCategory classifies open-source licenses by legal risk profile.
type LicenseCategory string

const (
	Permissive LicenseCategory = "Permissive"
	Copyleft   LicenseCategory = "Copyleft"
	Unknown    LicenseCategory = "Unknown"
)

// LicenseFinding represents the identified license of a package.
type LicenseFinding struct {
	PackageName string          `json:"package_name"`
	Version     string          `json:"version"`
	License     string          `json:"license"`
	Category    LicenseCategory `json:"category"`
}

// ClassifyLicense categorizes an SPDX license string into Permissive or Copyleft.
func ClassifyLicense(lic string) LicenseCategory {
	clean := strings.TrimSpace(strings.ToUpper(lic))
	if clean == "" {
		return Unknown
	}

	// Permissive license keywords
	if strings.Contains(clean, "MIT") ||
		strings.Contains(clean, "APACHE") ||
		strings.Contains(clean, "BSD") ||
		strings.Contains(clean, "ISC") ||
		strings.Contains(clean, "UNLICENSE") ||
		strings.Contains(clean, "CC0") ||
		strings.Contains(clean, "WTFPL") {
		return Permissive
	}

	// Copyleft / Restrictive license keywords
	if strings.Contains(clean, "GPL") ||
		strings.Contains(clean, "AGPL") ||
		strings.Contains(clean, "LGPL") ||
		strings.Contains(clean, "MPL") ||
		strings.Contains(clean, "EUPL") ||
		strings.Contains(clean, "CDDL") ||
		strings.Contains(clean, "EPL") {
		return Copyleft
	}

	return Unknown
}

// AnalyzeGraphLicenses iterates over dependency graph nodes and categorizes their licenses.
func AnalyzeGraphLicenses(graph *types.DependencyGraph, licenseMap map[string]string) []LicenseFinding {
	var findings []LicenseFinding

	if graph == nil {
		return findings
	}

	for _, node := range graph.Nodes {
		key := node.Name + "@" + node.Version
		lic := "Unknown"
		if val, ok := licenseMap[key]; ok && val != "" {
			lic = val
		}

		cat := ClassifyLicense(lic)
		findings = append(findings, LicenseFinding{
			PackageName: node.Name,
			Version:     node.Version,
			License:     lic,
			Category:    cat,
		})
	}

	return findings
}

// AnalyzeResultLicenses categorises licenses for all resolved dependencies in a ScanResult.
func AnalyzeResultLicenses(result *types.ScanResult, licenseMap map[string]string) []LicenseFinding {
	if result == nil || len(result.Dependencies) == 0 {
		return nil
	}
	findings := make([]LicenseFinding, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		if strings.TrimSpace(dep.Name) == "" {
			continue
		}
		key := dep.Name + "@" + dep.Version
		lic := "Unknown"
		if val, ok := licenseMap[key]; ok && val != "" {
			lic = val
		}
		findings = append(findings, LicenseFinding{
			PackageName: dep.Name,
			Version:     dep.Version,
			License:     lic,
			Category:    ClassifyLicense(lic),
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].PackageName != findings[j].PackageName {
			return findings[i].PackageName < findings[j].PackageName
		}
		return findings[i].Version < findings[j].Version
	})
	return findings
}

// ExtractLockfileLicenses extracts declared package license strings from lockfiles that
// embed license metadata (such as npm package-lock.json and PHP composer.lock).
// Returns a map keyed by "name@version" -> SPDX license expression.
func ExtractLockfileLicenses(lockFilePath string) map[string]string {
	if strings.TrimSpace(lockFilePath) == "" {
		return nil
	}
	data, err := os.ReadFile(lockFilePath)
	if err != nil {
		return nil
	}
	base := filepath.Base(lockFilePath)
	out := make(map[string]string)

	switch base {
	case "package-lock.json":
		var npmLock struct {
			Packages map[string]struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				License any    `json:"license"`
			} `json:"packages"`
		}
		if json.Unmarshal(data, &npmLock) == nil {
			for key, pkg := range npmLock.Packages {
				if key == "" || pkg.Version == "" {
					continue
				}
				name := pkg.Name
				if name == "" {
					if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
						name = key[idx+len("node_modules/"):]
					}
				}
				lic := normaliseLicenseField(pkg.License)
				if name != "" && lic != "" {
					out[name+"@"+pkg.Version] = lic
				}
			}
		}
	case "composer.lock":
		var compLock struct {
			Packages []struct {
				Name    string   `json:"name"`
				Version string   `json:"version"`
				License []string `json:"license"`
			} `json:"packages"`
			PackagesDev []struct {
				Name    string   `json:"name"`
				Version string   `json:"version"`
				License []string `json:"license"`
			} `json:"packages-dev"`
		}
		if json.Unmarshal(data, &compLock) == nil {
			for _, pkg := range append(compLock.Packages, compLock.PackagesDev...) {
				ver := strings.TrimPrefix(pkg.Version, "v")
				if pkg.Name != "" && ver != "" && len(pkg.License) > 0 {
					out[pkg.Name+"@"+ver] = strings.Join(pkg.License, " OR ")
				}
			}
		}
	}

	return out
}

func normaliseLicenseField(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.Join(parts, " OR ")
	case map[string]any:
		if t, ok := v["type"].(string); ok {
			return strings.TrimSpace(t)
		}
	}
	return ""
}
