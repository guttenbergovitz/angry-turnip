package export

import (
	"io"

	"github.com/guttenbergovitz/angry-turnip/internal/sbom"
	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

// CycloneDX exports scan results in CycloneDX v1.5 JSON SBOM format.
func CycloneDX(result *types.ScanResult, w io.Writer) error {
	return sbom.GenerateCycloneDX(result, nil, w)
}

// SPDX exports scan results in SPDX v2.3 JSON SBOM format.
func SPDX(result *types.ScanResult, w io.Writer) error {
	return sbom.GenerateSPDX(result, nil, w)
}
