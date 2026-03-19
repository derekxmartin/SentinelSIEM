// Package ingest provides the event ingestion pipeline.
//
// dead_letter.go implements a dead letter queue (DLQ) for events that fail
// normalization or indexing. Failed events are captured with error metadata
// and indexed to a dedicated DLQ index for later investigation and replay.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/metrics"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// RawIndexer is an optional interface that indexers can implement to support
// indexing arbitrary JSON documents (not just ECSEvent). Used by the DLQ
// to write entries that don't conform to the ECS schema.
type RawIndexer interface {
	BulkIndexRaw(ctx context.Context, index string, docs []json.RawMessage) error
}

// DLQReason categorizes why an event was sent to the dead letter queue.
type DLQReason string

const (
	// DLQReasonMalformed indicates the event could not be parsed or normalized.
	DLQReasonMalformed DLQReason = "malformed"
	// DLQReasonIndexFailure indicates the event failed to index after retries.
	DLQReasonIndexFailure DLQReason = "index_failure"
	// DLQReasonAlertFailure indicates an alert failed to index after retries.
	DLQReasonAlertFailure DLQReason = "alert_failure"
)

// DLQEntry represents a single dead letter queue item. It captures the
// original event payload along with metadata about the failure.
type DLQEntry struct {
	Timestamp    time.Time       `json:"@timestamp"`
	Reason       DLQReason       `json:"dlq_reason"`
	Error        string          `json:"dlq_error"`
	SourceType   string          `json:"source_type,omitempty"`
	OriginalData json.RawMessage `json:"original_data"`
	RetryCount   int             `json:"retry_count,omitempty"`
	TargetIndex  string          `json:"target_index,omitempty"`
}

// DeadLetterQueue buffers failed events and periodically flushes them
// to a dedicated Elasticsearch index. It is safe for concurrent use.
type DeadLetterQueue struct {
	indexer store.Indexer
	prefix  string

	mu      sync.Mutex
	buffer  []DLQEntry
	maxSize int // max buffer size before forced flush

	flushInterval time.Duration
	stopCh        chan struct{}
	done          chan struct{}
}

// DLQOption configures a DeadLetterQueue.
type DLQOption func(*DeadLetterQueue)

// WithDLQFlushInterval sets the flush interval (default: 10s).
func WithDLQFlushInterval(d time.Duration) DLQOption {
	return func(dlq *DeadLetterQueue) {
		dlq.flushInterval = d
	}
}

// WithDLQMaxBufferSize sets the maximum buffer size before a forced flush (default: 1000).
func WithDLQMaxBufferSize(size int) DLQOption {
	return func(dlq *DeadLetterQueue) {
		dlq.maxSize = size
	}
}

// NewDeadLetterQueue creates a dead letter queue that writes failed events
// to the indexer. The prefix is used to construct the DLQ index name
// (e.g., "akeso-dlq-2026.03.17").
func NewDeadLetterQueue(indexer store.Indexer, prefix string, opts ...DLQOption) *DeadLetterQueue {
	if prefix == "" {
		prefix = "akeso"
	}

	dlq := &DeadLetterQueue{
		indexer:       indexer,
		prefix:        prefix,
		buffer:        make([]DLQEntry, 0, 100),
		maxSize:       1000,
		flushInterval: 10 * time.Second,
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(dlq)
	}

	go dlq.flushLoop()
	return dlq
}

// Send adds a failed event to the dead letter queue.
func (dlq *DeadLetterQueue) Send(reason DLQReason, sourceType string, rawData json.RawMessage, err error, retryCount int, targetIndex string) {
	entry := DLQEntry{
		Timestamp:    time.Now().UTC(),
		Reason:       reason,
		Error:        err.Error(),
		SourceType:   sourceType,
		OriginalData: rawData,
		RetryCount:   retryCount,
		TargetIndex:  targetIndex,
	}

	metrics.DLQEventsTotal.WithLabelValues(string(reason)).Inc()

	dlq.mu.Lock()
	dlq.buffer = append(dlq.buffer, entry)
	shouldFlush := len(dlq.buffer) >= dlq.maxSize
	dlq.mu.Unlock()

	if shouldFlush {
		dlq.flush()
	}
}

// SendRaw is a convenience method for sending a malformed event that couldn't
// be parsed at all. It takes the raw bytes directly.
func (dlq *DeadLetterQueue) SendRaw(rawData json.RawMessage, err error) {
	dlq.Send(DLQReasonMalformed, "", rawData, err, 0, "")
}

// SendAlert sends a failed alert to the DLQ. This method satisfies the
// alert.DLQSender interface so the DLQ can be used by the retry queue.
func (dlq *DeadLetterQueue) SendAlert(index string, data json.RawMessage, err error, retryCount int) {
	dlq.Send(DLQReasonAlertFailure, "sigma_alert", data, err, retryCount, index)
}

// Stop flushes remaining entries and stops the background flush loop.
func (dlq *DeadLetterQueue) Stop() {
	close(dlq.stopCh)
	<-dlq.done
}

// Len returns the current number of buffered entries.
func (dlq *DeadLetterQueue) Len() int {
	dlq.mu.Lock()
	defer dlq.mu.Unlock()
	return len(dlq.buffer)
}

// flushLoop periodically flushes buffered DLQ entries to Elasticsearch.
func (dlq *DeadLetterQueue) flushLoop() {
	defer close(dlq.done)
	ticker := time.NewTicker(dlq.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dlq.stopCh:
			dlq.flush() // Final flush on shutdown.
			return
		case <-ticker.C:
			dlq.flush()
		}
	}
}

// flush writes all buffered entries to the DLQ index.
func (dlq *DeadLetterQueue) flush() {
	dlq.mu.Lock()
	if len(dlq.buffer) == 0 {
		dlq.mu.Unlock()
		return
	}
	entries := dlq.buffer
	dlq.buffer = make([]DLQEntry, 0, 100)
	dlq.mu.Unlock()

	// Group entries by date for time-partitioned indices.
	groups := make(map[string][]DLQEntry)
	for _, entry := range entries {
		date := entry.Timestamp.Format("2006.01.02")
		index := fmt.Sprintf("%s-dlq-%s", dlq.prefix, date)
		groups[index] = append(groups[index], entry)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for index, batch := range groups {
		if err := dlq.indexBatch(ctx, index, batch); err != nil {
			// If we can't write to the DLQ itself, log the error. We don't
			// re-queue to avoid infinite loops.
			log.Printf("[dlq] failed to index %d entries to %s: %v", len(batch), index, err)
			metrics.DLQFlushErrors.Inc()
		} else {
			log.Printf("[dlq] flushed %d entries to %s", len(batch), index)
		}
	}
}

// indexBatch converts DLQ entries to ECSEvent-shaped documents and bulk-indexes them.
// We use the store.Indexer interface which expects []common.ECSEvent, so we
// marshal the DLQ entries and use json.RawMessage wrapping.
func (dlq *DeadLetterQueue) indexBatch(ctx context.Context, index string, entries []DLQEntry) error {
	// We serialize DLQ entries as raw JSON and use the indexer's BulkIndex
	// via a temporary conversion. Since DLQ entries don't fit the ECSEvent
	// schema perfectly, we use a lightweight wrapper approach.
	docs := make([]json.RawMessage, len(entries))
	for i, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			log.Printf("[dlq] failed to marshal entry: %v", err)
			continue
		}
		docs[i] = data
	}

	return dlq.bulkIndexRaw(ctx, index, docs)
}

// bulkIndexRaw indexes raw JSON documents via the store.Indexer. Since the
// Indexer interface expects []common.ECSEvent, we use a DLQIndexer adapter
// if available, or fall back to wrapping in ECSEvent.Raw.
func (dlq *DeadLetterQueue) bulkIndexRaw(ctx context.Context, index string, docs []json.RawMessage) error {
	// Use the RawIndexer interface if the indexer supports it.
	if ri, ok := dlq.indexer.(RawIndexer); ok {
		return ri.BulkIndexRaw(ctx, index, docs)
	}

	// Fallback: wrap each doc in a minimal ECSEvent with the raw data.
	events := make([]common.ECSEvent, len(docs))
	for i, doc := range docs {
		events[i] = common.ECSEvent{
			Timestamp: time.Now().UTC(),
			Raw:       doc,
		}
	}
	return dlq.indexer.BulkIndex(ctx, index, events)
}
