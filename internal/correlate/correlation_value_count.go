package correlate

import (
	"fmt"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// ValueCountEvaluator implements value_count correlation rules.
// It tracks per-group-by-key distinct values of a specified field within
// sliding time windows. When the count of distinct values meets the
// threshold, a correlation alert is fired.
//
// Thread-safe: all methods are safe for concurrent use.
type ValueCountEvaluator struct {
	mu    sync.Mutex
	rules []*valueCountEntry
}

// valueCountEntry is a single value_count correlation rule with its state.
type valueCountEntry struct {
	rule    *CorrelationRule
	ruleSet map[string]bool // set of referenced single-event rule IDs

	// buckets maps group-by key → value count bucket.
	buckets map[string]*valueCountBucket
}

// valueCountBucket tracks timestamped distinct values for a single group-by key.
type valueCountBucket struct {
	entries   []valueEntry
	lastAlert time.Time // prevents re-alerting within the same window
}

// valueEntry pairs a field value with the timestamp it was observed.
type valueEntry struct {
	value     string
	timestamp time.Time
}

// NewValueCountEvaluator creates an evaluator for a set of value_count
// correlation rules. Rules that are not value_count type are silently skipped.
func NewValueCountEvaluator(rules []*CorrelationRule) *ValueCountEvaluator {
	var entries []*valueCountEntry

	for _, r := range rules {
		if r.Type != CorrelationValueCount {
			continue
		}

		ruleSet := make(map[string]bool, len(r.Rules))
		for _, id := range r.Rules {
			ruleSet[id] = true
		}

		entries = append(entries, &valueCountEntry{
			rule:    r,
			ruleSet: ruleSet,
			buckets: make(map[string]*valueCountBucket),
		})
	}

	return &ValueCountEvaluator{rules: entries}
}

// Process takes a single-event alert and the original event. If the alert's
// rule ID is referenced by any value_count correlation rule, the value field
// is extracted and tracked. Returns any correlation alerts that fire.
func (e *ValueCountEvaluator) Process(alert Alert, event *common.ECSEvent) []Alert {
	if event == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []Alert

	for _, entry := range e.rules {
		if !entry.ruleSet[alert.RuleID] {
			continue
		}

		// Extract the value field from the event.
		val, ok := getEventFieldValue(event, entry.rule.ValueField)
		if !ok {
			continue
		}
		valStr := fmt.Sprintf("%v", val)

		// Build group-by key from event fields.
		key := buildGroupByKey(entry.rule.GroupBy, event)

		// Get or create bucket for this key.
		bucket, ok := entry.buckets[key]
		if !ok {
			bucket = &valueCountBucket{}
			entry.buckets[key] = bucket
		}

		now := event.Timestamp
		if now.IsZero() {
			now = time.Now()
		}

		// Add this value entry.
		bucket.entries = append(bucket.entries, valueEntry{
			value:     valStr,
			timestamp: now,
		})

		// Evict entries outside the window.
		cutoff := now.Add(-entry.rule.Timespan)
		bucket.entries = evictValuesBefore(bucket.entries, cutoff)

		// Count distinct values in the window.
		distinct := countDistinct(bucket.entries)

		if meetsThreshold(distinct, entry.rule.Condition, entry.rule.Threshold) {
			// Don't re-alert if we already fired within this window.
			if !bucket.lastAlert.IsZero() && bucket.lastAlert.After(cutoff) {
				continue
			}

			bucket.lastAlert = now

			alerts = append(alerts, Alert{
				RuleID:      entry.rule.ID,
				Title:       entry.rule.Title,
				Level:       entry.rule.Level,
				Tags:        entry.rule.Tags,
				Description: entry.rule.Description,
				Author:      entry.rule.Author,
				Ruleset:     "sigma_correlation",
				Event:       event,
			})
		}
	}

	return alerts
}

// Stats returns the number of active buckets across all value_count rules.
func (e *ValueCountEvaluator) Stats() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()

	stats := make(map[string]int, len(e.rules))
	for _, entry := range e.rules {
		stats[entry.rule.ID] = len(entry.buckets)
	}
	return stats
}

// ExpireState removes buckets whose newest entry is older than the
// rule's timespan. Called periodically by the state manager (P5-T5).
func (e *ValueCountEvaluator) ExpireState(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	expired := 0
	for _, entry := range e.rules {
		cutoff := now.Add(-entry.rule.Timespan)
		for key, bucket := range entry.buckets {
			bucket.entries = evictValuesBefore(bucket.entries, cutoff)
			if len(bucket.entries) == 0 {
				delete(entry.buckets, key)
				expired++
			}
		}
	}
	return expired
}

// evictValuesBefore removes value entries with timestamps strictly before the cutoff.
// Assumes entries are roughly ordered (appended chronologically).
func evictValuesBefore(entries []valueEntry, cutoff time.Time) []valueEntry {
	i := 0
	for i < len(entries) && entries[i].timestamp.Before(cutoff) {
		i++
	}
	if i == 0 {
		return entries
	}
	remaining := make([]valueEntry, len(entries)-i)
	copy(remaining, entries[i:])
	return remaining
}

// countDistinct returns the number of distinct values in the entries.
func countDistinct(entries []valueEntry) int {
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		seen[e.value] = struct{}{}
	}
	return len(seen)
}

