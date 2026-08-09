// Package asncloak provides a low-latency, local request classifier for
// identifying traffic from cloud networks and automated security crawlers.
package asncloak

import (
	"fmt"
	"net/netip"
)

// Category describes why a network is included in the local table.
type Category string

const (
	CategoryCloud           Category = "cloud"
	CategorySecurityCrawler Category = "security-crawler"
)

// Entry maps a CIDR prefix to its owner and, when known, its origin ASN.
type Entry struct {
	CIDR         string
	ASN          uint32
	Organization string
	Category     Category
}

// Network is the parsed form of an Entry returned by a lookup.
type Network struct {
	Prefix       netip.Prefix
	ASN          uint32
	Organization string
	Category     Category
}

// Provider resolves an IP address against a local or external network source.
type Provider interface {
	Lookup(netip.Addr) (Network, bool)
}

type trieNode struct {
	children [2]*trieNode
	network  *Network
}

// RadixTrie performs immutable longest-prefix matching with an in-memory
// binary trie. A lookup examines at most 32 nodes for IPv4 and 128 for IPv6.
type RadixTrie struct {
	v4 trieNode
	v6 trieNode
}

// LocalProvider is retained as a compatibility alias for RadixTrie.
type LocalProvider = RadixTrie

// NewLocalProvider builds a provider from CIDR entries. Once constructed, it
// is safe for concurrent use without locks.
func NewLocalProvider(entries []Entry) (*LocalProvider, error) {
	provider := &LocalProvider{}
	for index, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR entry %d (%q): %w", index, entry.CIDR, err)
		}
		if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return nil, fmt.Errorf("parse CIDR entry %d (%q): invalid IPv4-mapped prefix length", index, entry.CIDR)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
		prefix = prefix.Masked()
		network := Network{
			Prefix:       prefix,
			ASN:          entry.ASN,
			Organization: entry.Organization,
			Category:     entry.Category,
		}
		provider.insert(network)
	}
	return provider, nil
}

func (provider *RadixTrie) insert(network Network) {
	address := network.Prefix.Addr().Unmap()
	node := &provider.v6
	if address.Is4() {
		node = &provider.v4
	}

	for bit := 0; bit < network.Prefix.Bits(); bit++ {
		direction := addressBit(address, bit)
		if node.children[direction] == nil {
			node.children[direction] = &trieNode{}
		}
		node = node.children[direction]
	}
	value := network
	node.network = &value
}

// Lookup returns the most-specific matching network for address.
func (provider *RadixTrie) Lookup(address netip.Addr) (Network, bool) {
	if provider == nil || !address.IsValid() {
		return Network{}, false
	}
	address = address.Unmap()
	node := &provider.v6
	bits := 128
	if address.Is4() {
		node = &provider.v4
		bits = 32
	}

	var match *Network
	if node.network != nil {
		match = node.network
	}
	for bit := 0; bit < bits; bit++ {
		node = node.children[addressBit(address, bit)]
		if node == nil {
			break
		}
		if node.network != nil {
			match = node.network
		}
	}
	if match == nil {
		return Network{}, false
	}
	return *match, true
}

func addressBit(address netip.Addr, bit int) byte {
	if address.Is4() {
		bytes := address.As4()
		return (bytes[bit/8] >> (7 - uint(bit%8))) & 1
	}
	bytes := address.As16()
	return (bytes[bit/8] >> (7 - uint(bit%8))) & 1
}

// DefaultEntries is a conservative bootstrap table of provider-owned address
// space. Deployments can supply a refreshed or organization-specific table to
// NewLocalProvider without changing the lookup path.
var DefaultEntries = []Entry{
	{CIDR: "13.64.0.0/11", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
	{CIDR: "20.0.0.0/8", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
	{CIDR: "40.64.0.0/10", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
	{CIDR: "51.103.0.0/16", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
	{CIDR: "52.224.0.0/11", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},
	{CIDR: "2603:1000::/23", ASN: 8075, Organization: "Microsoft Azure", Category: CategoryCloud},

	{CIDR: "3.0.0.0/9", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
	{CIDR: "13.32.0.0/15", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
	{CIDR: "18.0.0.0/8", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
	{CIDR: "52.0.0.0/8", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
	{CIDR: "54.0.0.0/8", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},
	{CIDR: "2600:1f00::/24", ASN: 16509, Organization: "Amazon Web Services", Category: CategoryCloud},

	{CIDR: "34.0.0.0/8", ASN: 396982, Organization: "Google Cloud", Category: CategoryCloud},
	{CIDR: "35.0.0.0/8", ASN: 396982, Organization: "Google Cloud", Category: CategoryCloud},
	{CIDR: "130.211.0.0/16", ASN: 15169, Organization: "Google Cloud", Category: CategoryCloud},
	{CIDR: "2600:1900::/28", ASN: 396982, Organization: "Google Cloud", Category: CategoryCloud},

	{CIDR: "104.131.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "138.68.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "139.59.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "159.65.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "165.22.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "167.71.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "178.62.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "188.166.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "206.189.0.0/16", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},
	{CIDR: "2400:6180::/32", ASN: 14061, Organization: "DigitalOcean", Category: CategoryCloud},

	{CIDR: "67.231.144.0/24", ASN: 26211, Organization: "Proofpoint", Category: CategorySecurityCrawler},
	{CIDR: "67.231.152.0/24", ASN: 26211, Organization: "Proofpoint", Category: CategorySecurityCrawler},
	{CIDR: "148.163.128.0/19", ASN: 26211, Organization: "Proofpoint", Category: CategorySecurityCrawler},

	{CIDR: "205.210.31.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "198.235.24.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "172.105.147.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "144.86.173.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "147.185.132.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "147.185.133.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "35.203.210.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "35.203.211.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "162.216.149.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
	{CIDR: "162.216.150.0/24", Organization: "Palo Alto Networks Cortex Xpanse", Category: CategorySecurityCrawler},
}

// NewDefaultProvider constructs a provider using DefaultEntries.
func NewDefaultProvider() (*LocalProvider, error) {
	return NewLocalProvider(DefaultEntries)
}
