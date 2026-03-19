package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/alert"
	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
	"github.com/derekxmartin/akeso-siem/internal/metrics"
	"github.com/derekxmartin/akeso-siem/internal/normalize"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// Pipeline wires together the ingestion components:
// HTTPListener → normalize.Engine → store.Indexer (Elasticsearch).
// Optionally evaluates events against a RuleEvaluator and indexes alerts.
// NDR host_score events are additionally upserted to a dedicated index.
// Failed events are routed to the dead letter queue (DLQ), and failed
// alert batches are retried via the alert retry queue.
type Pipeline struct {
	engine         *normalize.Engine
	indexer        store.Indexer
	hostScoreIndex store.HostScoreIndexer
	ruleEvaluator  correlate.RuleEvaluator
	dedupCache     *correlate.DedupCache
	dlq            *DeadLetterQueue
	alertRetryQ    *alert.RetryQueue
	prefix         string

	// In-flight tracking for graceful shutdown.
	inflight sync.WaitGroup
	// Total events processed (monotonic counter).
	processed atomic.Int64
}

// NewPipeline creates an ingestion pipeline.
// hostScoreIndex, ruleEvaluator, dedupCache, dlq, and alertRetryQ may be nil if not needed.
func NewPipeline(engine *normalize.Engine, indexer store.Indexer, prefix string, hostScoreIndex store.HostScoreIndexer, ruleEvaluator correlate.RuleEvaluator, dedupCache *correlate.DedupCache) *Pipeline {
	if prefix == "" {
		prefix = "akeso"
	}
	return &Pipeline{
		engine:         engine,
		indexer:        indexer,
		hostScoreIndex: hostScoreIndex,
		ruleEvaluator:  ruleEvaluator,
		dedupCache:     dedupCache,
		prefix:         prefix,
	}
}

// SetDLQ attaches a dead letter queue to the pipeline. Failed events
// will be routed to the DLQ instead of being silently dropped.
func (p *Pipeline) SetDLQ(dlq *DeadLetterQueue) {
	p.dlq = dlq
}

// SetAlertRetryQueue attaches an alert retry queue to the pipeline. Failed
// alert indexing operations will be retried instead of being silently dropped.
func (p *Pipeline) SetAlertRetryQueue(rq *alert.RetryQueue) {
	p.alertRetryQ = rq
}

// Drain waits for all in-flight event batches to finish processing.
// It should be called during graceful shutdown after new event acceptance
// has been stopped (HTTP server shutdown / syslog listener close).
func (p *Pipeline) Drain() {
	p.inflight.Wait()
}

// Processed returns the total number of events processed since startup.
func (p *Pipeline) Processed() int64 {
	return p.processed.Load()
}

// Handle is the EventHandler callback for HTTPListener. It normalizes a batch
// of raw events, indexes them into Elasticsearch, evaluates Sigma rules, and
// indexes any resulting alerts.
func (p *Pipeline) Handle(rawEvents []json.RawMessage) {
	if len(rawEvents) == 0 {
		return
	}

	p.inflight.Add(1)
	defer p.inflight.Done()

	metrics.InflightBatches.Inc()
	defer metrics.InflightBatches.Dec()

	pipelineStart := time.Now()
	metrics.BatchSize.Observe(float64(len(rawEvents)))

	// Normalize each event individually so we can route failures to the DLQ
	// with the correct raw payload.
	var events []*common.ECSEvent
	for _, raw := range rawEvents {
		event, err := p.engine.Normalize(raw)
		if err != nil {
			log.Printf("[pipeline] normalization error: %v", err)
			metrics.EventsDropped.WithLabelValues("normalization").Inc()
			if p.dlq != nil {
				p.dlq.SendRaw(raw, err)
			}
			continue
		}
		events = append(events, event)
	}

	if len(events) == 0 {
		return
	}

	// Count ingested events by source type.
	for _, event := range events {
		st := event.SourceType
		if st == "" {
			st = "unknown"
		}
		metrics.EventsIngested.WithLabelValues(st, "http").Inc()
	}

	// Group events by target index.
	groups := p.groupByIndex(events)

	// Bulk index each group.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for index, batch := range groups {
		indexStart := time.Now()
		if err := p.indexer.BulkIndex(ctx, index, batch); err != nil {
			log.Printf("[pipeline] indexing error for %s: %v", index, err)
			metrics.EventsDropped.WithLabelValues("indexing").Add(float64(len(batch)))
			// Route failed events to the dead letter queue.
			if p.dlq != nil {
				for _, event := range batch {
					data, marshalErr := json.Marshal(event)
					if marshalErr != nil {
						continue
					}
					p.dlq.Send(DLQReasonIndexFailure, event.SourceType, data, err, 0, index)
				}
			}
		} else {
			p.processed.Add(int64(len(batch)))
			metrics.EventsIndexed.WithLabelValues(index).Add(float64(len(batch)))
		}
		metrics.IndexLatency.WithLabelValues(index).Observe(time.Since(indexStart).Seconds())
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
	if p.ruleEvaluator != nil {
		p.evaluateAndIndexAlerts(ctx, events)
	}

	metrics.PipelineLatency.Observe(time.Since(pipelineStart).Seconds())
}

// evaluateAndIndexAlerts runs each event through the rule engine and bulk-indexes
// any resulting alerts to a time-partitioned alerts index.
func (p *Pipeline) evaluateAndIndexAlerts(ctx context.Context, events []*common.ECSEvent) {
	var alertDocs []common.ECSEvent

	for _, event := range events {
		evalStart := time.Now()
		alerts := p.ruleEvaluator.Evaluate(event)
		metrics.RuleEvalDuration.Observe(time.Since(evalStart).Seconds())

		for _, alert := range alerts {
			// Skip duplicate alerts within the dedup window.
			if p.dedupCache != nil && p.dedupCache.IsDuplicate(alert) {
				metrics.AlertsDeduplicated.Inc()
				continue
			}
			metrics.AlertsGenerated.WithLabelValues(alert.Level).Inc()
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
			// Route failed alert batch to the retry queue.
			if p.alertRetryQ != nil {
				p.alertRetryQ.Enqueue(index, batch, err)
			}
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
