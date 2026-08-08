package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/log"
)

type BlockIP struct {
	ipv4 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	mu      sync.RWMutex
	ips     map[string]*BlockIP
	masks   []*BlockIP
	store   *database.Database
	verbose bool
}

func NewBlacklist(path string, store *database.Database) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:     make(map[string]*BlockIP),
		store:   store,
		verbose: true,
	}
	if store != nil {
		persisted, err := store.ListBlockedIPs()
		if err != nil {
			return nil, err
		}
		for _, ip := range persisted {
			parsed := net.ParseIP(ip)
			if parsed != nil {
				bl.ips[parsed.String()] = &BlockIP{ipv4: parsed}
			}
		}
	}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
					if store != nil {
						if err := store.BlockIP(ipv4.String()); err != nil {
							return nil, err
						}
					}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}
	if err := fs.Err(); err != nil {
		return nil, err
	}

	log.Info("blacklist: loaded %d ip addresses and %d ip masks", len(bl.ips), len(bl.masks))
	return bl, nil
}

func (bl *Blacklist) GetStats() (int, int) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.ips), len(bl.masks)
}

func (bl *Blacklist) AddIP(ip string) error {
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4 := net.ParseIP(ip)
	if ipv4 != nil {
		bl.mu.Lock()
		bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
		bl.mu.Unlock()
	} else {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	if bl.store != nil {
		return bl.store.BlockIP(ipv4.String())
	}
	return nil
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()
	if _, ok := bl.ips[ipv4.String()]; ok {
		return true
	}
	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) SetVerbose(verbose bool) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.verbose = verbose
}

func (bl *Blacklist) IsVerbose() bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return bl.verbose
}

func (bl *Blacklist) IsWhitelisted(ip string) bool {
	if ip == "127.0.0.1" {
		return true
	}
	return false
}
