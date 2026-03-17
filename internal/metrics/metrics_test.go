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

	// Verify all SentinelSIEM metrics are registered.
	expected := []string{
		"sentinel_ingest_events_received_total",
		"sentinel_ingest_events_indexed_total",
		"sentinel_ingest_events_dropped_total",
		"sentinel_ingest_batch_size",
		"sentinel_ingest_index_duration_seconds",
		"sentinel_ingest_pipeline_duration_seconds",
		"sentinel_ingest_inflight_batches",
		"sentinel_detect_alerts_generated_total",
		"sentinel_detect_alerts_deduplicated_total",
		"sentinel_detect_eval_duration_seconds",
		"sentinel_detect_rules_loaded",
		"sentinel_correlate_buckets_active",
		"sentinel_syslog_connections_active",
		"sentinel_syslog_messages_received_total",
		"sentinel_query_duration_seconds",
		"sentinel_query_requests_total",
		"sentinel_auth_login_attempts_total",
		"sentinel_auth_rate_limited_total",
	}

	for _, name := range expected {
		if !names[name] {
			t.Errorf("metric %q not registered", name)
		}
	}
}

func TestHandlerServesPrometheusFormat(t *testing.T) {
	// Increment a counter so there's output.
	EventsIngested.WithLabelValues("sentinel_edr", "http").Inc()
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
		"sentinel_ingest_events_received_total",
		"sentinel_detect_alerts_generated_total",
		"sentinel_detect_rules_loaded 81",
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
