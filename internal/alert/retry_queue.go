// Package alert provides alert pipeline components including a retry queue
// for alert indexing failures.
//
// The RetryQueue accepts failed alert batches and retries indexing with
// exponential backoff. After MaxRetries failures, alerts are forwarded to
// the dead letter queue for manual investigation.
package alert

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/metrics"
	"github.com/derekxmartin/akeso-siem/internal/store"
)

// DLQSender is the interface for sending failed alerts to the dead letter queue.
// This avoids a direct dependency on the ingest package.
type DLQSender interface {
	// SendAlert sends a failed alert to the DLQ with the given error and retry count.
	SendAlert(index string, data json.RawMessage, err error, retryCount int)
}

// retryItem tracks a failed alert batch and its retry state.
type retryItem struct {
	Index      string
	Events     []common.ECSEvent
	Attempts   int
	NextRetry  time.Time
	LastError  error
}

// RetryQueue manages retry logic for failed alert indexing operations.
// It uses exponential backoff with a configurable maximum number of retries.
type RetryQueue struct {
	indexer    store.Indexer
	dlqSender DLQSender
	maxRetries int

	// Backoff configuration.
	baseDelay time.Duration
	maxDelay  time.Duration

	mu     sync.Mutex
	queue  []*retryItem
	stopCh chan struct{}
	done   chan struct{}

	// retryInterval controls how often the queue checks for items ready to retry.
	retryInterval time.Duration
}

// RetryQueueOption configures a RetryQueue.
type RetryQueueOption func(*RetryQueue)

// WithMaxRetries sets the maximum number of retry attempts (default: 3).
func WithMaxRetries(n int) RetryQueueOption {
	return func(rq *RetryQueue) {
		rq.maxRetries = n
	}
}

// WithBaseDelay sets the base delay for exponential backoff (default: 5s).
func WithBaseDelay(d time.Duration) RetryQueueOption {
	return func(rq *RetryQueue) {
		rq.baseDelay = d
	}
}

// WithMaxDelay sets the maximum delay between retries (default: 60s).
func WithMaxDelay(d time.Duration) RetryQueueOption {
	return func(rq *RetryQueue) {
		rq.maxDelay = d
	}
}

// WithRetryInterval sets how often the queue checks for retryable items (default: 2s).
func WithRetryInterval(d time.Duration) RetryQueueOption {
	return func(rq *RetryQueue) {
		rq.retryInterval = d
	}
}

// NewRetryQueue creates a retry queue for alert indexing failures.
// dlqSender may be nil, in which case exhausted alerts are only logged.
func NewRetryQueue(indexer store.Indexer, dlqSender DLQSender, opts ...RetryQueueOption) *RetryQueue {
	rq := &RetryQueue{
		indexer:       indexer,
		dlqSender:     dlqSender,
		maxRetries:    3,
		baseDelay:     5 * time.Second,
		maxDelay:      60 * time.Second,
		retryInterval: 2 * time.Second,
		queue:         make([]*retryItem, 0),
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(rq)
	}

	go rq.processLoop()
	return rq
}

// Enqueue adds a failed alert batch to the retry queue.
func (rq *RetryQueue) Enqueue(index string, events []common.ECSEvent, err error) {
	item := &retryItem{
		Index:     index,
		Events:    events,
		Attempts:  1, // First attempt already failed.
		NextRetry: time.Now().Add(rq.baseDelay),
		LastError: err,
	}

	rq.mu.Lock()
	rq.queue = append(rq.queue, item)
	queueLen := len(rq.queue)
	rq.mu.Unlock()

	metrics.AlertRetryQueueSize.Set(float64(queueLen))
	log.Printf("[alert-retry] enqueued %d alerts for %s (attempt 1 failed: %v)", len(events), index, err)
}

// Len returns the current number of items in the retry queue.
func (rq *RetryQueue) Len() int {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	return len(rq.queue)
}

// Stop gracefully shuts down the retry queue. Any remaining items are
// flushed to the DLQ.
func (rq *RetryQueue) Stop() {
	close(rq.stopCh)
	<-rq.done
}

// processLoop periodically checks for items ready to retry.
func (rq *RetryQueue) processLoop() {
	defer close(rq.done)
	ticker := time.NewTicker(rq.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rq.stopCh:
			rq.drainToDLQ()
			return
		case <-ticker.C:
			rq.processReady()
		}
	}
}

// processReady retries all items whose next retry time has passed.
func (rq *RetryQueue) processReady() {
	now := time.Now()

	rq.mu.Lock()
	var ready []*retryItem
	var remaining []*retryItem

	for _, item := range rq.queue {
		if now.After(item.NextRetry) {
			ready = append(ready, item)
		} else {
			remaining = append(remaining, item)
		}
	}

	if len(ready) == 0 {
		rq.mu.Unlock()
		return
	}

	rq.queue = remaining
	rq.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var requeue []*retryItem

	for _, item := range ready {
		metrics.AlertRetryTotal.Inc()
		item.Attempts++

		err := rq.indexer.BulkIndex(ctx, item.Index, item.Events)
		if err == nil {
			log.Printf("[alert-retry] successfully indexed %d alerts to %s on attempt %d", len(item.Events), item.Index, item.Attempts)
			continue
		}

		item.LastError = err

		if item.Attempts >= rq.maxRetries {
			// Exhausted all retries — send to DLQ.
			log.Printf("[alert-retry] exhausted %d retries for %d alerts to %s: %v", rq.maxRetries, len(item.Events), item.Index, err)
			metrics.AlertRetryExhausted.Inc()
			rq.sendToDLQ(item)
		} else {
			// Schedule next retry with exponential backoff.
			delay := rq.backoffDelay(item.Attempts)
			item.NextRetry = time.Now().Add(delay)
			requeue = append(requeue, item)
			log.Printf("[alert-retry] retry %d/%d failed for %s, next attempt in %v: %v", item.Attempts, rq.maxRetries, item.Index, delay, err)
		}
	}

	if len(requeue) > 0 {
		rq.mu.Lock()
		rq.queue = append(rq.queue, requeue...)
		rq.mu.Unlock()
	}

	rq.mu.Lock()
	metrics.AlertRetryQueueSize.Set(float64(len(rq.queue)))
	rq.mu.Unlock()
}

// backoffDelay calculates the delay for the nth attempt using exponential backoff.
// delay = baseDelay * 2^(attempt-1), capped at maxDelay.
func (rq *RetryQueue) backoffDelay(attempt int) time.Duration {
	delay := rq.baseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > rq.maxDelay {
			return rq.maxDelay
		}
	}
	return delay
}

// sendToDLQ forwards an exhausted retry item to the dead letter queue.
func (rq *RetryQueue) sendToDLQ(item *retryItem) {
	if rq.dlqSender == nil {
		log.Printf("[alert-retry] no DLQ configured, dropping %d alerts for %s", len(item.Events), item.Index)
		return
	}

	for _, event := range item.Events {
		data, err := json.Marshal(event)
		if err != nil {
			log.Printf("[alert-retry] failed to marshal alert for DLQ: %v", err)
			continue
		}
		rq.dlqSender.SendAlert(item.Index, data, item.LastError, item.Attempts)
	}
}

// drainToDLQ sends all remaining items to the DLQ on shutdown.
func (rq *RetryQueue) drainToDLQ() {
	rq.mu.Lock()
	items := rq.queue
	rq.queue = nil
	rq.mu.Unlock()

	if len(items) == 0 {
		return
	}

	log.Printf("[alert-retry] draining %d items to DLQ on shutdown", len(items))
	for _, item := range items {
		metrics.AlertRetryExhausted.Inc()
		rq.sendToDLQ(item)
	}
	metrics.AlertRetryQueueSize.Set(0)
}
