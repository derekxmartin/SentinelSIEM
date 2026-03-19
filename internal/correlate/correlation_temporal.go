package correlate

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// TemporalEvaluator implements temporal (ordered sequence) correlation rules.
// It maintains a state machine per group-by key that advances through an
// ordered list of referenced single-event rule IDs. When all steps are
// matched in order within the timespan, a correlation alert fires.
//
// Thread-safe: all methods are safe for concurrent use.
type TemporalEvaluator struct {
	mu    sync.Mutex
	rules []*temporalEntry
}

// temporalEntry is a single temporal correlation rule with its state.
type temporalEntry struct {
	rule *CorrelationRule

	// ruleIndex maps a single-event rule ID → its position(s) in the
	// ordered sequence. A rule ID may appear at multiple positions.
	ruleIndex map[string][]int

	// chains maps group-by key → active sequence chains.
	chains map[string]*temporalChain
}

// temporalChain tracks sequence progress for a single group-by key.
// Multiple partial chains may exist if earlier steps re-fire, but we
// keep it simple: one active chain advancing forward.
type temporalChain struct {
	// nextStep is the index into the rule's Rules slice that we expect next.
	nextStep int

	// startTime is when the first step was matched.
	startTime time.Time

	// matchedEvents stores the triggering event for each completed step.
	matchedEvents []*common.ECSEvent

	// lastAlert prevents re-alerting for the same completed chain.
	lastAlert time.Time
}

// NewTemporalEvaluator creates an evaluator for a set of temporal
// correlation rules. Rules that are not temporal type are silently skipped.
func NewTemporalEvaluator(rules []*CorrelationRule) *TemporalEvaluator {
	var entries []*temporalEntry

	for _, r := range rules {
		if r.Type != CorrelationTemporal {
			continue
		}

		// Build index: rule ID → positions in the sequence.
		idx := make(map[string][]int)
		for i, ruleID := range r.Rules {
			idx[ruleID] = append(idx[ruleID], i)
		}

		entries = append(entries, &temporalEntry{
			rule:      r,
			ruleIndex: idx,
			chains:    make(map[string]*temporalChain),
		})
	}

	return &TemporalEvaluator{rules: entries}
}

// Process takes a single-event alert and the original event. If the alert's
// rule ID matches a step in any temporal correlation rule's sequence, the
// state machine for the corresponding group-by key advances. Returns any
// correlation alerts that fire (when all steps complete in order within the
// timespan).
func (te *TemporalEvaluator) Process(alert Alert, event *common.ECSEvent) []Alert {
	if event == nil {
		return nil
	}

	te.mu.Lock()
	defer te.mu.Unlock()

	var alerts []Alert

	for _, entry := range te.rules {
		positions, referenced := entry.ruleIndex[alert.RuleID]
		if !referenced {
			continue
		}

		key := buildGroupByKey(entry.rule.GroupBy, event)

		now := event.Timestamp
		if now.IsZero() {
			now = time.Now()
		}

		chain, exists := entry.chains[key]

		for _, pos := range positions {
			if pos == 0 {
				// This rule ID can start a new chain.
				if !exists || chain.nextStep == 0 {
					// Start a new chain (or restart if already at step 0).
					entry.chains[key] = &temporalChain{
						nextStep:      1,
						startTime:     now,
						matchedEvents: []*common.ECSEvent{event},
					}
					chain = entry.chains[key]
					exists = true
				} else {
					// Chain already in progress at a later step.
					// Restart if the current chain is stale (outside window).
					cutoff := now.Add(-entry.rule.Timespan)
					if chain.startTime.Before(cutoff) {
						entry.chains[key] = &temporalChain{
							nextStep:      1,
							startTime:     now,
							matchedEvents: []*common.ECSEvent{event},
						}
						chain = entry.chains[key]
					}
					// Otherwise, keep the existing chain progressing.
				}
			} else if exists && pos == chain.nextStep {
				// This is the expected next step — advance the chain.
				cutoff := now.Add(-entry.rule.Timespan)

				// Check if chain has expired.
				if chain.startTime.Before(cutoff) {
					// Chain timed out. Delete it.
					delete(entry.chains, key)
					exists = false
					continue
				}

				chain.matchedEvents = append(chain.matchedEvents, event)
				chain.nextStep++

				// Check if the sequence is complete.
				if chain.nextStep >= len(entry.rule.Rules) {
					// Suppress re-alert within the same window.
					if !chain.lastAlert.IsZero() && chain.lastAlert.After(cutoff) {
						continue
					}

					chain.lastAlert = now

					// Build a summary description with matched events.
					desc := buildTemporalDescription(entry.rule, chain)

					alerts = append(alerts, Alert{
						RuleID:      entry.rule.ID,
						Title:       entry.rule.Title,
						Level:       entry.rule.Level,
						Tags:        entry.rule.Tags,
						Description: desc,
						Author:      entry.rule.Author,
						Ruleset:     "sigma_correlation",
						Event:       event, // last event in the sequence
					})

					// Reset chain so a new sequence can start.
					delete(entry.chains, key)
					exists = false
				}
			}
			// If pos doesn't match step 0 or the expected next step, ignore it.
		}
	}

	return alerts
}

// Stats returns the number of active chains across all temporal rules.
func (te *TemporalEvaluator) Stats() map[string]int {
	te.mu.Lock()
	defer te.mu.Unlock()

	stats := make(map[string]int, len(te.rules))
	for _, entry := range te.rules {
		stats[entry.rule.ID] = len(entry.chains)
	}
	return stats
}

// ExpireState removes chains whose start time is older than the rule's
// timespan. Called periodically by the state manager (P5-T5).
func (te *TemporalEvaluator) ExpireState(now time.Time) int {
	te.mu.Lock()
	defer te.mu.Unlock()

	expired := 0
	for _, entry := range te.rules {
		cutoff := now.Add(-entry.rule.Timespan)
		for key, chain := range entry.chains {
			if chain.startTime.Before(cutoff) {
				delete(entry.chains, key)
				expired++
			}
		}
	}
	return expired
}

// buildTemporalDescription creates a human-readable summary of the matched
// temporal sequence for the alert description.
func buildTemporalDescription(rule *CorrelationRule, chain *temporalChain) string {
	if rule.Description != "" {
		return rule.Description
	}

	var parts []string
	for i, ruleID := range rule.Rules {
		ts := ""
		if i < len(chain.matchedEvents) && chain.matchedEvents[i] != nil {
			ts = chain.matchedEvents[i].Timestamp.Format(time.RFC3339)
		}
		parts = append(parts, fmt.Sprintf("step %d: %s @ %s", i+1, ruleID, ts))
	}

	elapsed := ""
	if len(chain.matchedEvents) >= 2 {
		first := chain.matchedEvents[0].Timestamp
		last := chain.matchedEvents[len(chain.matchedEvents)-1].Timestamp
		elapsed = fmt.Sprintf(" (elapsed: %s)", last.Sub(first).Round(time.Second))
	}

	return fmt.Sprintf("Temporal sequence completed: %s%s",
		strings.Join(parts, " → "), elapsed)
}
