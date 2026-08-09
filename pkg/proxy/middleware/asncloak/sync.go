package asncloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	AWSIPRangesURL    = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	GCPIPRangesURL    = "https://www.gstatic.com/ipranges/cloud.json"
	AzureIPRangesURL  = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
	PaloAltoRangesURL = "https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity"

	defaultSyncInterval = 12 * time.Hour
	maxFeedSize         = 64 << 20
)

// FeedKind identifies the provider-specific response parser.
type FeedKind string

const (
	FeedAWS            FeedKind = "aws"
	FeedGCP            FeedKind = "gcp"
	FeedAzure          FeedKind = "azure"
	FeedAzureDiscovery FeedKind = "azure-discovery"
	FeedCIDRText       FeedKind = "cidr-text"
)

// Feed configures one official or test range source.
type Feed struct {
	Name          string
	URL           string
	Kind          FeedKind
	ASN           uint32
	Organization  string
	Category      Category
	FallbackCIDRs []string
}

// DefaultFeeds returns the official public sources used by the updater.
func DefaultFeeds() []Feed {
	return []Feed{
		{Name: "aws", URL: AWSIPRangesURL, Kind: FeedAWS, ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
		{Name: "gcp", URL: GCPIPRangesURL, Kind: FeedGCP, ASN: 396982, Organization: "Google Cloud", Category: CategoryCloud},
		{Name: "azure", URL: AzureIPRangesURL, Kind: FeedAzureDiscovery, ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
		{
			Name: "palo-alto", URL: PaloAltoRangesURL, Kind: FeedCIDRText,
			Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler,
			// Palo Alto currently redirects its published scanning-activity URL
			// to a JavaScript documentation shell. Keep the last official list as
			// a continuity fallback while still attempting the official URL first.
			FallbackCIDRs: []string{
				"35.203.210.0/23", "144.86.173.0/24", "147.185.132.0/23",
				"162.216.149.0/24", "162.216.150.0/24", "172.105.147.0/24",
				"198.235.24.0/24", "205.210.31.0/24", "216.25.88.0/21",
				"2604:a940:300:5b6::/64", "2604:a940:301:225::/64", "2604:a940:302:118::/64",
			},
		},
	}
}

// AtomicProvider performs lock-free lookups against an atomically replaceable
// immutable radix trie.
type AtomicProvider struct {
	current atomic.Pointer[RadixTrie]
}

// NewAtomicProvider wraps initial for atomic updates.
func NewAtomicProvider(initial *RadixTrie) (*AtomicProvider, error) {
	if initial == nil {
		return nil, errors.New("initial radix trie is required")
	}
	provider := &AtomicProvider{}
	provider.current.Store(initial)
	return provider, nil
}

// Lookup loads the current trie once and performs an immutable lookup.
func (provider *AtomicProvider) Lookup(address netip.Addr) (Network, bool) {
	if provider == nil {
		return Network{}, false
	}
	trie := provider.current.Load()
	if trie == nil {
		return Network{}, false
	}
	return trie.Lookup(address)
}

// Swap atomically publishes next to all new lookups.
func (provider *AtomicProvider) Swap(next *RadixTrie) error {
	if provider == nil || next == nil {
		return errors.New("replacement radix trie is required")
	}
	provider.current.Store(next)
	return nil
}

// SyncConfig configures periodic feed ingestion.
type SyncConfig struct {
	Provider    *AtomicProvider
	Client      *http.Client
	Feeds       []Feed
	BaseEntries []Entry
	Interval    time.Duration
	OnUpdate    func(SyncResult)
	OnError     func(error)
}

// SyncResult summarizes a successful atomic refresh.
type SyncResult struct {
	Entries         int
	SuccessfulFeeds int
	FailedFeeds     int
	FallbackFeeds   int
	UpdatedAt       time.Time
}

// SyncService downloads feeds and builds replacement tries away from the
// request path.
type SyncService struct {
	provider    *AtomicProvider
	client      *http.Client
	feeds       []Feed
	baseEntries []Entry
	interval    time.Duration
	onUpdate    func(SyncResult)
	onError     func(error)
}

// NewSyncService constructs a live range updater with a bootstrap provider.
func NewSyncService(config SyncConfig) (*SyncService, error) {
	if config.Interval == 0 {
		config.Interval = defaultSyncInterval
	}
	if config.Interval < time.Minute {
		return nil, errors.New("IP sync interval must be at least one minute")
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: 45 * time.Second}
	}
	if len(config.Feeds) == 0 {
		config.Feeds = DefaultFeeds()
	}
	if config.BaseEntries == nil {
		config.BaseEntries = append([]Entry(nil), DefaultEntries...)
	}
	if config.Provider == nil {
		initial, err := NewLocalProvider(config.BaseEntries)
		if err != nil {
			return nil, err
		}
		provider, err := NewAtomicProvider(initial)
		if err != nil {
			return nil, err
		}
		config.Provider = provider
	}
	return &SyncService{
		provider: config.Provider, client: config.Client,
		feeds:       append([]Feed(nil), config.Feeds...),
		baseEntries: append([]Entry(nil), config.BaseEntries...),
		interval:    config.Interval, onUpdate: config.OnUpdate, onError: config.OnError,
	}, nil
}

// Provider returns the lock-free provider used by request evaluation.
func (service *SyncService) Provider() *AtomicProvider {
	if service == nil {
		return nil
	}
	return service.provider
}

// Run refreshes immediately and then on every configured interval until the
// context is cancelled.
func (service *SyncService) Run(ctx context.Context) {
	if service == nil {
		return
	}
	service.runOnce(ctx)
	ticker := time.NewTicker(service.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.runOnce(ctx)
		}
	}
}

func (service *SyncService) runOnce(ctx context.Context) {
	result, err := service.Sync(ctx)
	if err != nil && service.onError != nil {
		service.onError(err)
	}
	if err == nil && service.onUpdate != nil {
		service.onUpdate(result)
	}
}

type feedResult struct {
	entries  []Entry
	fallback bool
	err      error
}

// Sync ingests all feeds concurrently, builds a complete immutable trie, and
// publishes it with one atomic pointer store. Any failed feed aborts the
// publication so an incomplete download never clears active provider ranges.
func (service *SyncService) Sync(ctx context.Context) (SyncResult, error) {
	if service == nil || service.provider == nil {
		return SyncResult{}, errors.New("IP sync service is not initialized")
	}
	results := make(chan feedResult, len(service.feeds))
	var wait sync.WaitGroup
	for _, feed := range service.feeds {
		feed := feed
		wait.Add(1)
		go func() {
			defer wait.Done()
			entries, fallback, err := service.fetch(ctx, feed)
			results <- feedResult{entries: entries, fallback: fallback, err: err}
		}()
	}
	wait.Wait()
	close(results)

	entries := append([]Entry(nil), service.baseEntries...)
	var failures []error
	successful := 0
	fallbacks := 0
	for result := range results {
		if result.err != nil {
			failures = append(failures, result.err)
			continue
		}
		successful++
		if result.fallback {
			fallbacks++
		}
		entries = append(entries, result.entries...)
	}
	if successful == 0 {
		return SyncResult{FailedFeeds: len(failures)}, fmt.Errorf("all IP range feeds failed: %w", errors.Join(failures...))
	}
	if len(failures) > 0 {
		return SyncResult{SuccessfulFeeds: successful, FailedFeeds: len(failures)}, fmt.Errorf("one or more IP range feeds failed: %w", errors.Join(failures...))
	}
	entries = deduplicateEntries(entries)
	next, err := NewLocalProvider(entries)
	if err != nil {
		return SyncResult{}, fmt.Errorf("build synchronized radix trie: %w", err)
	}
	if err := service.provider.Swap(next); err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{
		Entries: len(entries), SuccessfulFeeds: successful,
		FailedFeeds: len(failures), FallbackFeeds: fallbacks, UpdatedAt: time.Now().UTC(),
	}
	return result, nil
}

func (service *SyncService) fetch(ctx context.Context, feed Feed) ([]Entry, bool, error) {
	body, err := service.download(ctx, feed.URL)
	if err != nil {
		return fallbackEntries(feed, fmt.Errorf("fetch %s feed: %w", feed.Name, err))
	}
	if feed.Kind == FeedAzureDiscovery {
		downloadURL, err := discoverAzureDownloadURL(body)
		if err != nil {
			return fallbackEntries(feed, fmt.Errorf("discover Azure range file: %w", err))
		}
		body, err = service.download(ctx, downloadURL)
		if err != nil {
			return fallbackEntries(feed, fmt.Errorf("fetch Azure range file: %w", err))
		}
		feed.Kind = FeedAzure
	}
	prefixes, err := parseFeed(feed.Kind, body)
	if err != nil {
		return fallbackEntries(feed, fmt.Errorf("parse %s feed: %w", feed.Name, err))
	}
	return entriesFromPrefixes(feed, prefixes), false, nil
}

func fallbackEntries(feed Feed, cause error) ([]Entry, bool, error) {
	if len(feed.FallbackCIDRs) == 0 {
		return nil, false, cause
	}
	prefixes, err := parseFeed(FeedCIDRText, []byte(strings.Join(feed.FallbackCIDRs, "\n")))
	if err != nil {
		return nil, false, fmt.Errorf("%w; fallback is invalid: %v", cause, err)
	}
	return entriesFromPrefixes(feed, prefixes), true, nil
}

func entriesFromPrefixes(feed Feed, prefixes []netip.Prefix) []Entry {
	entries := make([]Entry, 0, len(prefixes))
	for _, prefix := range prefixes {
		entries = append(entries, Entry{
			CIDR: prefix.String(), ASN: feed.ASN,
			Organization: feed.Organization, Category: feed.Category,
		})
	}
	return entries
}

func (service *SyncService) download(ctx context.Context, rawURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Olta-IP-Sync/1.0")
	response, err := service.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP status %s", response.Status)
	}
	limited := io.LimitReader(response.Body, maxFeedSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxFeedSize {
		return nil, errors.New("feed exceeds maximum size")
	}
	return body, nil
}

func parseFeed(kind FeedKind, body []byte) ([]netip.Prefix, error) {
	var values []string
	switch kind {
	case FeedAWS:
		var document struct {
			Prefixes []struct {
				IPPrefix string `json:"ip_prefix"`
			} `json:"prefixes"`
			IPv6Prefixes []struct {
				IPv6Prefix string `json:"ipv6_prefix"`
			} `json:"ipv6_prefixes"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			return nil, err
		}
		for _, item := range document.Prefixes {
			values = append(values, item.IPPrefix)
		}
		for _, item := range document.IPv6Prefixes {
			values = append(values, item.IPv6Prefix)
		}
	case FeedGCP:
		var document struct {
			Prefixes []struct {
				IPv4 string `json:"ipv4Prefix"`
				IPv6 string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			return nil, err
		}
		for _, item := range document.Prefixes {
			values = append(values, item.IPv4, item.IPv6)
		}
	case FeedAzure:
		var document struct {
			Values []struct {
				Properties struct {
					AddressPrefixes []string `json:"addressPrefixes"`
				} `json:"properties"`
			} `json:"values"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			return nil, err
		}
		for _, item := range document.Values {
			values = append(values, item.Properties.AddressPrefixes...)
		}
	case FeedCIDRText:
		values = cidrPattern.FindAllString(html.UnescapeString(string(body)), -1)
	default:
		return nil, fmt.Errorf("unsupported feed kind %q", kind)
	}

	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", value)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("feed contains no CIDR prefixes")
	}
	return prefixes, nil
}

var (
	cidrPattern          = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f:]+/[0-9]{1,3}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}`)
	azureDownloadPattern = regexp.MustCompile(`https://download\.microsoft\.com/[^"'<>[:space:]]+\.json`)
)

func discoverAzureDownloadURL(body []byte) (string, error) {
	decoded := html.UnescapeString(string(bytes.ReplaceAll(body, []byte(`\/`), []byte(`/`))))
	match := azureDownloadPattern.FindString(decoded)
	if match == "" {
		return "", errors.New("current JSON download URL not found")
	}
	return match, nil
}

func deduplicateEntries(entries []Entry) []Entry {
	result := make([]Entry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key := entry.CIDR + "\x00" + entry.Organization + "\x00" + string(entry.Category)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, entry)
	}
	return result
}
