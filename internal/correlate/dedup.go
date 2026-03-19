package correlate

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// DedupCache suppresses duplicate alerts within a configurable time window.
// An alert is considered duplicate if the same rule fires for the same
// group-by key values within the window. Thread-safe for concurrent use.
type DedupCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	window  time.Duration
}

// NewDedupCache creates a dedup cache with the given suppression window.
// A zero or negative window disables dedup (all alerts pass through).
func NewDedupCache(window time.Duration) *DedupCache {
	return &DedupCache{
		entries: make(map[string]time.Time),
		window:  window,
	}
}

// IsDuplicate checks whether an alert is a duplicate of a recently seen alert.
// Returns true if the alert should be suppressed. If not a duplicate, records
// the alert and returns false.
func (d *DedupCache) IsDuplicate(alert Alert) bool {
	if d.window <= 0 {
		return false
	}

	key := dedupKey(alert)

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Evict expired entries lazily (only the checked key).
	if lastSeen, exists := d.entries[key]; exists {
		if now.Sub(lastSeen) < d.window {
			return true // still within window — suppress
		}
	}

	d.entries[key] = now
	return false
}

// Len returns the number of entries currently in the cache (for testing).
func (d *DedupCache) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Purge removes all expired entries from the cache.
// Can be called periodically in a background goroutine.
func (d *DedupCache) Purge() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, lastSeen := range d.entries {
		if now.Sub(lastSeen) >= d.window {
			delete(d.entries, key)
			removed++
		}
	}
	return removed
}

// dedupKey computes a hash key for an alert based on rule ID and
// identifying event fields (host, user, process, source/dest IPs).
func dedupKey(alert Alert) string {
	h := sha256.New()
	fmt.Fprintf(h, "rule:%s\n", alert.RuleID)

	// Include key identifying fields from the event.
	if alert.Event != nil {
		writeEventKeys(h, alert.Event)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// writeEventKeys writes identifying event fields to a hash writer.
// Fields are sorted for deterministic key generation.
func writeEventKeys(h interface{ Write([]byte) (int, error) }, event *common.ECSEvent) {
	var parts []string

	if event.Host != nil && event.Host.Name != "" {
		parts = append(parts, "host.name:"+event.Host.Name)
	}
	if event.Host != nil && len(event.Host.IP) > 0 {
		parts = append(parts, "host.ip:"+event.Host.IP[0])
	}
	if event.User != nil && event.User.Name != "" {
		parts = append(parts, "user.name:"+event.User.Name)
	}
	if event.Process != nil && event.Process.Name != "" {
		parts = append(parts, "process.name:"+event.Process.Name)
	}
	if event.Source != nil && event.Source.IP != "" {
		parts = append(parts, "source.ip:"+event.Source.IP)
	}
	if event.Destination != nil && event.Destination.IP != "" {
		parts = append(parts, "destination.ip:"+event.Destination.IP)
	}

	sort.Strings(parts)
	fmt.Fprintf(h, "%s\n", strings.Join(parts, "|"))
}
