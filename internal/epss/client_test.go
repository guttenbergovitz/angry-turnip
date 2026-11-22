package epss

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

func TestLookupEPSSParsesBatchResponse(t *testing.T) {
	var seenQuery string
	client := New("https://epss.example.test/data/v1/epss", 5)
	client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seenQuery = r.URL.Query().Get("cve")
		body := `{
			"status": "OK",
			"data": [
				{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99991"},
				{"cve": "CVE-2023-38545", "epss": "0.42100", "percentile": "0.97210"}
			]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})

	got, err := client.LookupEPSS(context.Background(), []string{
		"cve-2023-38545",
		"CVE-2021-44228",
		"CVE-2021-44228", // duplicate should be deduplicated
		"GHSA-xxxx-yyyy", // non-CVE should be ignored
	})
	if err != nil {
		t.Fatalf("LookupEPSS returned error: %v", err)
	}

	if seenQuery != "CVE-2021-44228,CVE-2023-38545" {
		t.Errorf("unexpected query parameter %q", seenQuery)
	}

	s1, ok := got["CVE-2021-44228"]
	if !ok || s1.EPSS != 0.97565 || s1.Percentile != 0.99991 {
		t.Errorf("unexpected score for CVE-2021-44228: %+v (ok=%v)", s1, ok)
	}
	s2, ok := got["CVE-2023-38545"]
	if !ok || s2.EPSS != 0.421 || s2.Percentile != 0.9721 {
		t.Errorf("unexpected score for CVE-2023-38545: %+v (ok=%v)", s2, ok)
	}
}

func TestLookupEPSSSkipsNonCVEInput(t *testing.T) {
	var hits atomic.Int32
	client := New("https://epss.example.test/data/v1/epss", 5)
	client.httpClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})

	got, err := client.LookupEPSS(context.Background(), []string{"GHSA-1234-5678-9012"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 || hits.Load() != 0 {
		t.Errorf("expected 0 results and 0 HTTP calls, got %v (%d calls)", got, hits.Load())
	}
}

func TestLookupEPSSRejectsOutOfRangeValues(t *testing.T) {
	client := New("https://epss.example.test/data/v1/epss", 5)
	client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.RawQuery, "CVE-2024-0001") {
			t.Errorf("missing expected CVE in query: %s", r.URL.RawQuery)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"data":[{"cve":"CVE-2024-0001","epss":"1.5","percentile":"0.5"}]}`)),
		}, nil
	})

	got, err := client.LookupEPSS(context.Background(), []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected out-of-range EPSS value to be ignored, got %+v", got)
	}
}
