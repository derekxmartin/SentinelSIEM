package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/correlate"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

// Pipeline wires together the ingestion components:
// HTTPListener → normalize.Engine → store.Indexer (Elasticsearch).
// Optionally evaluates events against a RuleEngine and indexes alerts.
// NDR host_score events are additionally upserted to a dedicated index.
type Pipeline struct {
	engine         *normalize.Engine
	indexer        store.Indexer
	hostScoreIndex store.HostScoreIndexer
	ruleEngine     *correlate.RuleEngine
	dedupCache     *correlate.DedupCache
	prefix         string
}

// NewPipeline creates an ingestion pipeline.
// hostScoreIndex, ruleEngine, and dedupCache may be nil if not needed.
func NewPipeline(engine *normalize.Engine, indexer store.Indexer, prefix string, hostScoreIndex store.HostScoreIndexer, ruleEngine *correlate.RuleEngine, dedupCache *correlate.DedupCache) *Pipeline {
	if prefix == "" {
		prefix = "sentinel"
	}
	return &Pipeline{
		engine:         engine,
		indexer:        indexer,
		hostScoreIndex: hostScoreIndex,
		ruleEngine:     ruleEngine,
		dedupCache:     dedupCache,
		prefix:         prefix,
	}
}

// Handle is the EventHandler callback for HTTPListener. It normalizes a batch
// of raw events, indexes them into Elasticsearch, evaluates Sigma rules, and
// indexes any resulting alerts.
func (p *Pipeline) Handle(rawEvents []json.RawMessage) {
	if len(rawEvents) == 0 {
		return
	}

	// Normalize.
	events, errs := p.engine.NormalizeBatch(rawEvents)
	for _, err := range errs {
		log.Printf("[pipeline] normalization error: %v", err)
	}

	if len(events) == 0 {
		return
	}

	// Group events by target index.
	groups := p.groupByIndex(events)

	// Bulk index each group.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for index, batch := range groups {
		if err := p.indexer.BulkIndex(ctx, index, batch); err != nil {
			log.Printf("[pipeline] indexing error for %s: %v", index, err)
		}
	}

	// Upsert NDR host score events to the dedicated index.
	if p.hostScoreIndex != nil {
		for _, event := range events {
			if isHostScoreEvent(event) {
				if err := p.hostScoreIndex.UpsertHostScore(ctx, event); err != nil {
					log.Printf("[pipeline] host score upsert error: %v", err)
				}
			}
		}
	}

	// Evaluate Sigma rules and index alerts.
	if p.ruleEngine != nil {
		p.evaluateAndIndexAlerts(ctx, events)
	}
}

// evaluateAndIndexAlerts runs each event through the rule engine and bulk-indexes
// any resulting alerts to a time-partitioned alerts index.
func (p *Pipeline) evaluateAndIndexAlerts(ctx context.Context, events []*common.ECSEvent) {
	var alertDocs []common.ECSEvent

	for _, event := range events {
		alerts := p.ruleEngine.Evaluate(event)
		for _, alert := range alerts {
			// Skip duplicate alerts within the dedup window.
			if p.dedupCache != nil && p.dedupCache.IsDuplicate(alert) {
				continue
			}
			// Wrap alert as an ECSEvent-shaped doc for BulkIndex compatibility.
			doc := alertToDocument(alert)
			alertDocs = append(alertDocs, doc)
		}
	}

	if len(alertDocs) == 0 {
		return
	}

	// Group alerts by date-partitioned index.
	alertGroups := make(map[string][]common.ECSEvent)
	for _, doc := range alertDocs {
		date := doc.Timestamp.UTC().Format("2006.01.02")
		index := fmt.Sprintf("%s-alerts-%s", p.prefix, date)
		alertGroups[index] = append(alertGroups[index], doc)
	}

	for index, batch := range alertGroups {
		if err := p.indexer.BulkIndex(ctx, index, batch); err != nil {
			log.Printf("[pipeline] alert indexing error for %s: %v", index, err)
		} else {
			log.Printf("[pipeline] indexed %d alert(s) to %s", len(batch), index)
		}
	}
}

// alertToDocument converts a correlate.Alert into an ECSEvent that can be
// bulk-indexed. Rule metadata is stored in the ECS rule.* fields, and the
// original event data (process, host, network, etc.) is preserved.
func alertToDocument(alert correlate.Alert) common.ECSEvent {
	// Start with a copy of the triggering event.
	doc := *alert.Event

	// Set alert-specific event fields.
	doc.Event = &common.EventFields{
		Kind:     "alert",
		Category: []string{"intrusion_detection"},
		Type:     []string{"indicator"},
		Action:   "sigma_match",
		Severity: levelToSeverity(alert.Level),
	}

	// Preserve rule tags as MITRE ATT&CK technique references.
	if len(alert.Tags) > 0 {
		techniques := make([]common.ThreatTechnique, len(alert.Tags))
		for i, tag := range alert.Tags {
			techniques[i] = common.ThreatTechnique{Name: tag}
		}
		doc.Threat = &common.ThreatFields{
			Technique: techniques,
		}
	}

	// Use "sigma_alert" as the source type for index routing.
	doc.SourceType = "sigma_alert"

	// Store rule metadata in the ECS rule.* field set.
	doc.Rule = &common.RuleFields{
		ID:          alert.RuleID,
		Name:        alert.Title,
		Severity:    alert.Level,
		Tags:        alert.Tags,
		Description: alert.Description,
		Author:      alert.Author,
		Category:    "sigma",
		Ruleset:     alert.Ruleset,
	}

	// Observer identifies the detection system.
	doc.Observer = &common.ObserverFields{
		Type: "sigma",
	}

	return doc
}

// levelToSeverity converts Sigma severity levels to numeric ECS severity.
func levelToSeverity(level string) int {
	switch level {
	case "informational":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return 0
	}
}

// isHostScoreEvent returns true if the event is an NDR host_score event.
func isHostScoreEvent(event *common.ECSEvent) bool {
	return event != nil &&
		event.Event != nil &&
		event.Event.Action == "host_score_update" &&
		event.NDR != nil &&
		event.NDR.HostScore != nil
}

// groupByIndex partitions events into per-index batches.
// Index pattern: {prefix}-events-{source_type}-{YYYY.MM.dd}
func (p *Pipeline) groupByIndex(events []*common.ECSEvent) map[string][]common.ECSEvent {
	groups := make(map[string][]common.ECSEvent)

	for _, event := range events {
		index := p.indexName(event)
		groups[index] = append(groups[index], *event)
	}

	return groups
}

// indexName computes the target ES index for an event.
func (p *Pipeline) indexName(event *common.ECSEvent) string {
	sourceType := event.SourceType
	if sourceType == "" {
		sourceType = "unknown"
	}

	date := event.Timestamp.UTC().Format("2006.01.02")

	return fmt.Sprintf("%s-events-%s-%s", p.prefix, sourceType, date)
}
