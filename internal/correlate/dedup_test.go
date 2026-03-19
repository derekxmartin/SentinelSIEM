package correlate

import (
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

func TestDedupCacheBasic(t *testing.T) {
	cache := NewDedupCache(1 * time.Second)

	alert := Alert{
		RuleID: "rule-001",
		Title:  "Test Rule",
		Event: &common.ECSEvent{
			Host: &common.HostFields{Name: "host-a"},
			Process: &common.ProcessFields{Name: "malware.exe"},
		},
	}

	// First occurrence — not duplicate.
	if cache.IsDuplicate(alert) {
		t.Error("first alert should not be duplicate")
	}

	// Immediate repeat — duplicate.
	if !cache.IsDuplicate(alert) {
		t.Error("immediate repeat should be duplicate")
	}
}

func TestDedupCacheDifferentRuleIDs(t *testing.T) {
	cache := NewDedupCache(1 * time.Second)

	alert1 := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}
	alert2 := Alert{
		RuleID: "rule-002",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}

	if cache.IsDuplicate(alert1) {
		t.Error("first alert should not be duplicate")
	}
	// Different rule ID → not duplicate.
	if cache.IsDuplicate(alert2) {
		t.Error("different rule ID should not be duplicate")
	}
}

func TestDedupCacheDifferentHosts(t *testing.T) {
	cache := NewDedupCache(1 * time.Second)

	alert1 := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}
	alert2 := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-b"}},
	}

	if cache.IsDuplicate(alert1) {
		t.Error("first alert should not be duplicate")
	}
	// Same rule but different host → not duplicate.
	if cache.IsDuplicate(alert2) {
		t.Error("different host should not be duplicate")
	}
}

func TestDedupCacheExpiry(t *testing.T) {
	// Use a very short window for testing.
	cache := NewDedupCache(50 * time.Millisecond)

	alert := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}

	if cache.IsDuplicate(alert) {
		t.Error("first alert should not be duplicate")
	}
	if !cache.IsDuplicate(alert) {
		t.Error("immediate repeat should be duplicate")
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	// Should no longer be duplicate.
	if cache.IsDuplicate(alert) {
		t.Error("alert after window expiry should not be duplicate")
	}
}

func TestDedupCacheDisabled(t *testing.T) {
	// Zero window disables dedup.
	cache := NewDedupCache(0)

	alert := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}

	// Should never be duplicate with zero window.
	if cache.IsDuplicate(alert) {
		t.Error("zero window should never report duplicate")
	}
	if cache.IsDuplicate(alert) {
		t.Error("zero window should never report duplicate (repeat)")
	}
}

func TestDedupCacheNegativeWindow(t *testing.T) {
	cache := NewDedupCache(-1 * time.Second)

	alert := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{},
	}

	if cache.IsDuplicate(alert) {
		t.Error("negative window should never report duplicate")
	}
}

func TestDedupCacheNilEvent(t *testing.T) {
	cache := NewDedupCache(1 * time.Second)

	alert := Alert{RuleID: "rule-001"}

	// Should not panic with nil event.
	if cache.IsDuplicate(alert) {
		t.Error("first alert should not be duplicate")
	}
	if !cache.IsDuplicate(alert) {
		t.Error("repeat nil-event alert should be duplicate")
	}
}

func TestDedupCachePurge(t *testing.T) {
	cache := NewDedupCache(50 * time.Millisecond)

	for i := 0; i < 10; i++ {
		alert := Alert{
			RuleID: "rule-001",
			Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
			// All same key, so only 1 entry.
		}
		cache.IsDuplicate(alert)
	}

	// Add different keys.
	for i := 0; i < 5; i++ {
		alert := Alert{
			RuleID: "rule-001",
			Event: &common.ECSEvent{
				Host: &common.HostFields{Name: "host-unique-" + string(rune('a'+i))},
			},
		}
		cache.IsDuplicate(alert)
	}

	if cache.Len() != 6 {
		t.Errorf("cache length = %d, want 6", cache.Len())
	}

	// Wait for expiry.
	time.Sleep(60 * time.Millisecond)

	removed := cache.Purge()
	if removed != 6 {
		t.Errorf("purged = %d, want 6", removed)
	}
	if cache.Len() != 0 {
		t.Errorf("cache length after purge = %d, want 0", cache.Len())
	}
}

func TestDedupCacheConcurrent(t *testing.T) {
	cache := NewDedupCache(1 * time.Second)
	alert := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			cache.IsDuplicate(alert)
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	// Should have exactly 1 entry regardless of concurrency.
	if cache.Len() != 1 {
		t.Errorf("cache length = %d, want 1", cache.Len())
	}
}

func TestDedupKeyDeterministic(t *testing.T) {
	alert := Alert{
		RuleID: "rule-001",
		Event: &common.ECSEvent{
			Host:    &common.HostFields{Name: "host-a", IP: []string{"10.0.0.1"}},
			User:    &common.UserFields{Name: "admin"},
			Process: &common.ProcessFields{Name: "cmd.exe"},
		},
	}

	key1 := dedupKey(alert)
	key2 := dedupKey(alert)

	if key1 != key2 {
		t.Errorf("dedup key not deterministic: %q != %q", key1, key2)
	}
}

func TestDedupKeyIncludesAllFields(t *testing.T) {
	base := Alert{
		RuleID: "rule-001",
		Event:  &common.ECSEvent{Host: &common.HostFields{Name: "host-a"}},
	}
	withUser := Alert{
		RuleID: "rule-001",
		Event: &common.ECSEvent{
			Host: &common.HostFields{Name: "host-a"},
			User: &common.UserFields{Name: "admin"},
		},
	}

	key1 := dedupKey(base)
	key2 := dedupKey(withUser)

	if key1 == key2 {
		t.Error("different user fields should produce different keys")
	}
}

func TestDedupKeySourceDestIP(t *testing.T) {
	alert1 := Alert{
		RuleID: "rule-001",
		Event: &common.ECSEvent{
			Source:      &common.EndpointFields{IP: "10.0.0.1"},
			Destination: &common.EndpointFields{IP: "10.0.0.2"},
		},
	}
	alert2 := Alert{
		RuleID: "rule-001",
		Event: &common.ECSEvent{
			Source:      &common.EndpointFields{IP: "10.0.0.1"},
			Destination: &common.EndpointFields{IP: "10.0.0.3"},
		},
	}

	if dedupKey(alert1) == dedupKey(alert2) {
		t.Error("different destination IPs should produce different keys")
	}
}
