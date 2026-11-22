package kev

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestLookupKEVMatchesAndCachesCatalogue(t *testing.T) {
	var hits atomic.Int32
	client := New("https://kev.example.test/feed.json", 5)
	client.httpClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		hits.Add(1)
		body := `{
			"catalogVersion": "2026.01.01",
			"vulnerabilities": [
				{"cveID": "CVE-2021-44228"},
				{"cveID": "CVE-2023-38545"}
			]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})

	got, err := client.LookupKEV(context.Background(), []string{"cve-2021-44228", "CVE-2099-0001"})
	if err != nil {
		t.Fatalf("LookupKEV returned error: %v", err)
	}
	if !got["CVE-2021-44228"] {
		t.Errorf("expected CVE-2021-44228 to match KEV")
	}
	if got["CVE-2099-0001"] {
		t.Errorf("did not expect CVE-2099-0001 to match KEV")
	}

	// Second lookup must reuse cached catalogue without issuing another HTTP request.
	got2, err := client.LookupKEV(context.Background(), []string{"CVE-2023-38545"})
	if err != nil {
		t.Fatalf("second LookupKEV returned error: %v", err)
	}
	if !got2["CVE-2023-38545"] {
		t.Errorf("expected CVE-2023-38545 to match cached KEV")
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 HTTP fetch due to in-memory caching, got %d", hits.Load())
	}
}

func TestLookupKEVEmptyInputSkipsNetwork(t *testing.T) {
	var hits atomic.Int32
	client := New("https://kev.example.test/feed.json", 5)
	client.httpClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})

	got, err := client.LookupKEV(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 || hits.Load() != 0 {
		t.Errorf("expected no matches and 0 HTTP calls, got %v (%d calls)", got, hits.Load())
	}
}
