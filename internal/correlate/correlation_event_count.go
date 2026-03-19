package correlate

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// EventCountEvaluator implements event_count correlation rules.
// It tracks per-group-by-key event counts within sliding time windows.
// When the count of matching single-event rule hits meets the threshold,
// a correlation alert is fired.
//
// Thread-safe: all methods are safe for concurrent use.
type EventCountEvaluator struct {
	mu    sync.Mutex
	rules []*eventCountEntry
}

// eventCountEntry is a single event_count correlation rule with its state.
type eventCountEntry struct {
	rule    *CorrelationRule
	ruleSet map[string]bool // set of referenced single-event rule IDs

	// buckets maps group-by key → list of event timestamps within the window.
	buckets map[string]*eventCountBucket
}

// eventCountBucket tracks event timestamps for a single group-by key.
type eventCountBucket struct {
	timestamps []time.Time
	lastAlert  time.Time // prevents re-alerting within the same window
}

// NewEventCountEvaluator creates an evaluator for a set of event_count
// correlation rules. Rules that are not event_count type are silently skipped.
func NewEventCountEvaluator(rules []*CorrelationRule) *EventCountEvaluator {
	var entries []*eventCountEntry

	for _, r := range rules {
		if r.Type != CorrelationEventCount {
			continue
		}

		ruleSet := make(map[string]bool, len(r.Rules))
		for _, id := range r.Rules {
			ruleSet[id] = true
		}

		entries = append(entries, &eventCountEntry{
			rule:    r,
			ruleSet: ruleSet,
			buckets: make(map[string]*eventCountBucket),
		})
	}

	return &EventCountEvaluator{rules: entries}
}

// Process takes a single-event alert (from the rule engine) and the original
// event. If the alert's rule ID is referenced by any event_count correlation
// rule, the event is counted. Returns any correlation alerts that fire.
func (e *EventCountEvaluator) Process(alert Alert, event *common.ECSEvent) []Alert {
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

		// Build group-by key from event fields.
		key := buildGroupByKey(entry.rule.GroupBy, event)

		// Get or create bucket for this key.
		bucket, ok := entry.buckets[key]
		if !ok {
			bucket = &eventCountBucket{}
			entry.buckets[key] = bucket
		}

		now := event.Timestamp
		if now.IsZero() {
			now = time.Now()
		}

		// Add this event's timestamp.
		bucket.timestamps = append(bucket.timestamps, now)

		// Evict timestamps outside the window.
		cutoff := now.Add(-entry.rule.Timespan)
		bucket.timestamps = evictBefore(bucket.timestamps, cutoff)

		// Check threshold.
		count := len(bucket.timestamps)
		if meetsThreshold(count, entry.rule.Condition, entry.rule.Threshold) {
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

// Stats returns the number of active buckets across all event_count rules.
func (e *EventCountEvaluator) Stats() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()

	stats := make(map[string]int, len(e.rules))
	for _, entry := range e.rules {
		stats[entry.rule.ID] = len(entry.buckets)
	}
	return stats
}

// ExpireState removes buckets whose newest timestamp is older than the
// rule's timespan. Called periodically by the state manager (P5-T5).
func (e *EventCountEvaluator) ExpireState(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	expired := 0
	for _, entry := range e.rules {
		cutoff := now.Add(-entry.rule.Timespan)
		for key, bucket := range entry.buckets {
			bucket.timestamps = evictBefore(bucket.timestamps, cutoff)
			if len(bucket.timestamps) == 0 {
				delete(entry.buckets, key)
				expired++
			}
		}
	}
	return expired
}

// buildGroupByKey constructs a string key from the group-by field values.
// Example: group-by ["user.name", "host.name"] → "admin|HOST-A"
func buildGroupByKey(groupBy []string, event *common.ECSEvent) string {
	if len(groupBy) == 0 {
		return "_global_"
	}

	parts := make([]string, len(groupBy))
	for i, field := range groupBy {
		val, ok := getEventFieldValue(event, field)
		if ok {
			parts[i] = fmt.Sprintf("%v", val)
		} else {
			parts[i] = ""
		}
	}
	return strings.Join(parts, "|")
}

// evictBefore removes timestamps strictly before the cutoff.
// Assumes timestamps are roughly ordered (appended chronologically).
func evictBefore(timestamps []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(timestamps) && timestamps[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return timestamps
	}
	// Compact the slice to avoid unbounded growth.
	remaining := make([]time.Time, len(timestamps)-i)
	copy(remaining, timestamps[i:])
	return remaining
}

// meetsThreshold checks if a count satisfies the condition operator.
func meetsThreshold(count int, op ConditionOp, threshold int) bool {
	switch op {
	case OpGTE:
		return count >= threshold
	case OpGT:
		return count > threshold
	case OpLTE:
		return count <= threshold
	case OpLT:
		return count < threshold
	case OpEQ:
		return count == threshold
	default:
		return false
	}
}
