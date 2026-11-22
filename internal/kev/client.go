package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultEndpoint is the public, keyless CISA Known Exploited Vulnerabilities JSON feed.
	DefaultEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	maxResponseBytes = 20 << 20 // 20 MiB upper bound for the KEV catalogue
)

// Client queries the CISA Known Exploited Vulnerabilities (KEV) catalogue.
// The catalogue is fetched at most once per Client instance and cached in memory.
type Client struct {
	endpoint   string
	httpClient *http.Client

	mu      sync.Mutex
	loaded  bool
	catalog map[string]struct{}
}

// New creates a KEV client targeting the given endpoint with the specified timeout in seconds.
func New(endpoint string, timeoutSec int) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	return &Client{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
	}
}

type kevFeed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// LookupKEV checks which of the supplied CVE identifiers appear in the CISA KEV catalogue.
// Returns a map containing only matched uppercase CVE IDs mapped to true.
func (c *Client) LookupKEV(ctx context.Context, cveIDs []string) (map[string]bool, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	catalog, err := c.loadCatalog(ctx)
	if err != nil {
		return nil, err
	}

	matches := make(map[string]bool)
	for _, raw := range cveIDs {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if _, ok := catalog[id]; ok {
			matches[id] = true
		}
	}
	return matches, nil
}

func (c *Client) loadCatalog(ctx context.Context) (map[string]struct{}, error) {
	c.mu.Lock()
	if c.loaded {
		cat := c.catalog
		c.mu.Unlock()
		return cat, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create KEV request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV catalogue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV catalogue returned HTTP %d", resp.StatusCode)
	}

	var feed kevFeed
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(limited).Decode(&feed); err != nil {
		return nil, fmt.Errorf("decode KEV catalogue: %w", err)
	}

	cat := make(map[string]struct{}, len(feed.Vulnerabilities))
	for _, entry := range feed.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if id != "" {
			cat[id] = struct{}{}
		}
	}

	c.mu.Lock()
	c.catalog = cat
	c.loaded = true
	c.mu.Unlock()

	return cat, nil
}
