package lockfile

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/guttenbergovitz/angry-turnip/internal/types"
)

const (
	// DefaultCacheFileName is the canonical scan cache file written by Angry Turnip (`atnp`).
	DefaultCacheFileName = ".atnp.cache"
	// LegacyCacheFileName is the legacy Vigil CLI cache file supported as a read fallback.
	LegacyCacheFileName = ".vigil.cache"
)

// ResolveCachePath returns the path to the scan cache file in dir, preferring the canonical
// .atnp.cache file and falling back to a pre-existing .vigil.cache file when .atnp.cache does
// not yet exist on disk.
func ResolveCachePath(dir string) string {
	primary := filepath.Join(dir, DefaultCacheFileName)
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	legacy := filepath.Join(dir, LegacyCacheFileName)
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return primary
}

// SaveCache atomically writes scan results to the cache file (.atnp.cache) using a
// temporary file in the same directory followed by os.Rename so an interrupted process
// never leaves a partially written or corrupted snapshot.
func SaveCache(path string, result *types.ScanResult) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".atnp.cache.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("encode cache: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync cache file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit cache file: %w", err)
	}

	cleanup = false
	return nil
}

// LoadCache reads scan results from cache file.
func LoadCache(path string) (*types.ScanResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file: %w", err)
	}
	defer file.Close()

	var result types.ScanResult
	if err := json.NewDecoder(file).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode cache: %w", err)
	}

	return &result, nil
}

// IsCacheValid checks whether the cached hash matches the current lock file hash.
func IsCacheValid(cachedHash, currentHash string) bool {
	return cachedHash != "" && cachedHash == currentHash
}

// HashFile computes the SHA-256 hex digest of a file.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
