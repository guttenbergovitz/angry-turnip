package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultEndpoint is the public, keyless FIRST EPSS API endpoint.
	DefaultEndpoint = "https://api.first.org/data/v1/epss"

	batchSize        = 50
	maxResponseBytes = 4 << 20 // 4 MiB upper bound per batch response
)

// Score holds the FIRST EPSS exploitation probability and percentile rank for a CVE.
type Score struct {
	EPSS       float64
	Percentile float64
}

// Client queries the public FIRST EPSS API for CVE exploitation probabilities.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// New creates an EPSS client targeting endpoint with the given timeout in seconds.
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

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// LookupEPSS queries FIRST EPSS in batches for the supplied CVE identifiers.
// Returns a map of uppercase CVE IDs to parsed EPSS scores.
func (c *Client) LookupEPSS(ctx context.Context, cveIDs []string) (map[string]Score, error) {
	unique := normaliseCVEIDs(cveIDs)
	if len(unique) == 0 {
		return nil, nil
	}

	results := make(map[string]Score, len(unique))
	for start := 0; start < len(unique); start += batchSize {
		end := start + batchSize
		if end > len(unique) {
			end = len(unique)
		}
		if err := c.fetchBatch(ctx, unique[start:end], results); err != nil {
			return results, err
		}
	}

	return results, nil
}

func (c *Client) fetchBatch(ctx context.Context, batch []string, out map[string]Score) error {
	parsedURL, err := url.Parse(c.endpoint)
	if err != nil {
		return fmt.Errorf("parse EPSS endpoint: %w", err)
	}
	q := parsedURL.Query()
	q.Set("cve", strings.Join(batch, ","))
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create EPSS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch EPSS scores: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EPSS API returned HTTP %d", resp.StatusCode)
	}

	var payload epssResponse
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(limited).Decode(&payload); err != nil {
		return fmt.Errorf("decode EPSS response: %w", err)
	}

	for _, entry := range payload.Data {
		id := strings.ToUpper(strings.TrimSpace(entry.CVE))
		if id == "" {
			continue
		}
		prob, err := strconv.ParseFloat(strings.TrimSpace(entry.EPSS), 64)
		if err != nil || prob < 0 || prob > 1 {
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSpace(entry.Percentile), 64)
		if err != nil || pct < 0 || pct > 1 {
			pct = 0
		}
		out[id] = Score{
			EPSS:       prob,
			Percentile: pct,
		}
	}
	return nil
}

func normaliseCVEIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
