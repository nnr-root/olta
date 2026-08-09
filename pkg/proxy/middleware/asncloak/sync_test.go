package asncloak

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestAtomicProviderSwap(t *testing.T) {
	first, err := NewLocalProvider([]Entry{{CIDR: "192.0.2.0/24", Organization: "first"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLocalProvider([]Entry{{CIDR: "198.51.100.0/24", Organization: "second"}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewAtomicProvider(first)
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 500; j++ {
				_, _ = provider.Lookup(netip.MustParseAddr("192.0.2.10"))
				_, _ = provider.Lookup(netip.MustParseAddr("198.51.100.10"))
			}
		}()
	}
	if err := provider.Swap(second); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if _, ok := provider.Lookup(netip.MustParseAddr("192.0.2.10")); ok {
		t.Fatal("old prefix still matched after swap")
	}
	match, ok := provider.Lookup(netip.MustParseAddr("198.51.100.10"))
	if !ok || match.Organization != "second" {
		t.Fatalf("new prefix match = %+v/%v", match, ok)
	}
}

func TestSyncIngestsMockHTTPFeeds(t *testing.T) {
	responses := map[string]string{
		"/aws":   `{"prefixes":[{"ip_prefix":"192.0.2.0/24"}],"ipv6_prefixes":[{"ipv6_prefix":"2001:db8:1::/48"}]}`,
		"/gcp":   `{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"2001:db8:2::/48"}]}`,
		"/azure": `{"values":[{"properties":{"addressPrefixes":["203.0.113.0/24","2001:db8:3::/48"]}}]}`,
		"/palo":  `<html><body>Scanner ranges: 100.64.0.0/24 and 2001:db8:4::/48</body></html>`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := responses[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		_, _ = fmt.Fprint(writer, body)
	}))
	defer server.Close()

	initial, err := NewLocalProvider([]Entry{{CIDR: "10.0.0.0/8", Organization: "bootstrap"}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewAtomicProvider(initial)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSyncService(SyncConfig{
		Provider: provider, Client: server.Client(), Interval: time.Minute,
		BaseEntries: []Entry{{CIDR: "10.0.0.0/8", Organization: "bootstrap"}},
		Feeds: []Feed{
			{Name: "aws", URL: server.URL + "/aws", Kind: FeedAWS, Organization: "AWS", Category: CategoryCloud},
			{Name: "gcp", URL: server.URL + "/gcp", Kind: FeedGCP, Organization: "GCP", Category: CategoryCloud},
			{Name: "azure", URL: server.URL + "/azure", Kind: FeedAzure, Organization: "Azure", Category: CategoryCloud},
			{Name: "palo", URL: server.URL + "/palo", Kind: FeedCIDRText, Organization: "Palo Alto", Category: CategorySecurityCrawler},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.SuccessfulFeeds != 4 || result.FailedFeeds != 0 || result.Entries != 9 {
		t.Fatalf("Sync() result = %+v, want 4 feeds and 9 entries", result)
	}

	checks := map[string]string{
		"10.1.2.3": "bootstrap", "192.0.2.20": "AWS", "2001:db8:2::1": "GCP",
		"203.0.113.9": "Azure", "100.64.0.7": "Palo Alto",
	}
	for address, organization := range checks {
		match, ok := provider.Lookup(netip.MustParseAddr(address))
		if !ok || match.Organization != organization {
			t.Errorf("Lookup(%s) = %+v/%v, want %s", address, match, ok, organization)
		}
	}
}

func TestSyncFailureRetainsCurrentTrie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	initial, _ := NewLocalProvider([]Entry{{CIDR: "192.0.2.0/24", Organization: "stable"}})
	provider, _ := NewAtomicProvider(initial)
	service, err := NewSyncService(SyncConfig{
		Provider: provider, Client: server.Client(), Interval: time.Minute,
		BaseEntries: nil,
		Feeds:       []Feed{{Name: "failed", URL: server.URL, Kind: FeedAWS}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Sync(context.Background()); err == nil {
		t.Fatal("Sync() error = nil, want feed failure")
	}
	match, ok := provider.Lookup(netip.MustParseAddr("192.0.2.10"))
	if !ok || match.Organization != "stable" {
		t.Fatalf("current trie changed after failed sync: %+v/%v", match, ok)
	}
}
