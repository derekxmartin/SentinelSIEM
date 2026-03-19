package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryCollectsAllMetrics(t *testing.T) {
	// Initialize all label combinations so CounterVec/GaugeVec metrics
	// appear in Gather() output (they only appear after first observation).
	EventsIngested.WithLabelValues("test", "http")
	EventsIndexed.WithLabelValues("test-index")
	EventsDropped.WithLabelValues("test")
	AlertsGenerated.WithLabelValues("high")
	SyslogConnections.WithLabelValues("tcp")
	SyslogMessages.WithLabelValues("tcp")
	AuthLoginAttempts.WithLabelValues("success")
	IndexLatency.WithLabelValues("test-index")
	DLQEventsTotal.WithLabelValues("malformed")

	// Gather all registered metrics.
	families, err := Registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Build a set of metric names.
	names := make(map[string]bool)
	for _, fam := range families {
		names[fam.GetName()] = true
	}

	// Verify all AkesoSIEM metrics are registered.
	expected := []string{
		"akeso_ingest_events_received_total",
		"akeso_ingest_events_indexed_total",
		"akeso_ingest_events_dropped_total",
		"akeso_ingest_batch_size",
		"akeso_ingest_index_duration_seconds",
		"akeso_ingest_pipeline_duration_seconds",
		"akeso_ingest_inflight_batches",
		"akeso_detect_alerts_generated_total",
		"akeso_detect_alerts_deduplicated_total",
		"akeso_detect_eval_duration_seconds",
		"akeso_detect_rules_loaded",
		"akeso_correlate_buckets_active",
		"akeso_syslog_connections_active",
		"akeso_syslog_messages_received_total",
		"akeso_query_duration_seconds",
		"akeso_query_requests_total",
		"akeso_auth_login_attempts_total",
		"akeso_auth_rate_limited_total",
		"akeso_dlq_events_total",
		"akeso_dlq_flush_errors_total",
		"akeso_dlq_buffer_size",
		"akeso_alert_retry_total",
		"akeso_alert_retry_exhausted_total",
		"akeso_alert_retry_queue_size",
	}

	for _, name := range expected {
		if !names[name] {
			t.Errorf("metric %q not registered", name)
		}
	}
}

func TestHandlerServesPrometheusFormat(t *testing.T) {
	// Increment a counter so there's output.
	EventsIngested.WithLabelValues("akeso_edr", "http").Inc()
	AlertsGenerated.WithLabelValues("high").Add(3)
	RulesLoaded.Set(81)

	// Serve the metrics handler.
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("failed to GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Verify key metrics appear in output.
	checks := []string{
		"akeso_ingest_events_received_total",
		"akeso_detect_alerts_generated_total",
		"akeso_detect_rules_loaded 81",
		"go_goroutines",
	}
	for _, check := range checks {
		if !strings.Contains(text, check) {
			t.Errorf("expected %q in metrics output", check)
		}
	}
}

func TestCounterIncrements(t *testing.T) {
	// Reset by creating fresh metrics would be complex; instead just verify
	// that incrementing works without panic.
	EventsDropped.WithLabelValues("normalization").Inc()
	EventsDropped.WithLabelValues("indexing").Add(5)
	AlertsDeduplicated.Inc()
	QueryTotal.Inc()
	AuthLoginAttempts.WithLabelValues("success").Inc()
	AuthLoginAttempts.WithLabelValues("failure").Inc()
	AuthRateLimited.Inc()
	SyslogMessages.WithLabelValues("tcp").Inc()
	SyslogMessages.WithLabelValues("udp").Inc()
	InflightBatches.Inc()
	InflightBatches.Dec()
	CorrelationBuckets.Set(42)
	BatchSize.Observe(100)
	IndexLatency.WithLabelValues("test-index").Observe(0.05)
	PipelineLatency.Observe(0.1)
	RuleEvalDuration.Observe(0.001)
	QueryLatency.Observe(0.5)
	SyslogConnections.WithLabelValues("tcp").Inc()
	SyslogConnections.WithLabelValues("tcp").Dec()
}
