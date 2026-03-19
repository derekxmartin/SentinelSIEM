package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "akeso.toml"))
	if err != nil {
		t.Fatalf("failed to load akeso.toml: %v", err)
	}

	if len(cfg.Elasticsearch.Addresses) != 1 || cfg.Elasticsearch.Addresses[0] != "http://localhost:9200" {
		t.Errorf("elasticsearch.addresses: got %v", cfg.Elasticsearch.Addresses)
	}
	if cfg.Elasticsearch.IndexPrefix != "akeso" {
		t.Errorf("elasticsearch.index_prefix: got %q", cfg.Elasticsearch.IndexPrefix)
	}
	if cfg.Ingest.HTTPPort != 8080 {
		t.Errorf("ingest.http_port: got %d", cfg.Ingest.HTTPPort)
	}
	if cfg.Ingest.RateLimit != 10000 {
		t.Errorf("ingest.rate_limit: got %d", cfg.Ingest.RateLimit)
	}
	if cfg.Ingest.Syslog.TCPPort != 1514 {
		t.Errorf("ingest.syslog.tcp_port: got %d", cfg.Ingest.Syslog.TCPPort)
	}
	if cfg.Correlate.RulesDir != "rules" {
		t.Errorf("correlate.rules_dir: got %q", cfg.Correlate.RulesDir)
	}
	if cfg.Query.Port != 8081 {
		t.Errorf("query.port: got %d", cfg.Query.Port)
	}
	if cfg.Cases.RetentionDays != 365 {
		t.Errorf("cases.retention_days: got %d", cfg.Cases.RetentionDays)
	}
	if !cfg.Cases.AutoExtract {
		t.Error("cases.auto_extract_observables: expected true")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level: got %q", cfg.Logging.Level)
	}
}

func TestDefaultsApplied(t *testing.T) {
	// Minimal config — only required field.
	content := `
[elasticsearch]
addresses = ["http://es:9200"]
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load minimal config: %v", err)
	}

	// Defaults should fill in everything else.
	if cfg.Ingest.HTTPPort != 8080 {
		t.Errorf("expected default ingest.http_port 8080, got %d", cfg.Ingest.HTTPPort)
	}
	if cfg.Correlate.ReloadInterval != 30 {
		t.Errorf("expected default reload_interval_sec 30, got %d", cfg.Correlate.ReloadInterval)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected default logging.format json, got %q", cfg.Logging.Format)
	}
}

func TestMissingAddresses(t *testing.T) {
	content := `
[elasticsearch]
addresses = []
`
	path := writeTempConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for empty addresses")
	}
	if want := "at least one address required"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestInvalidPort(t *testing.T) {
	content := `
[elasticsearch]
addresses = ["http://localhost:9200"]

[ingest]
http_port = 99999
`
	path := writeTempConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid port")
	}
	if want := "not a valid port"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestInvalidLogLevel(t *testing.T) {
	content := `
[elasticsearch]
addresses = ["http://localhost:9200"]

[logging]
level = "verbose"
`
	path := writeTempConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
	if want := "not valid"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestInvalidLogFormat(t *testing.T) {
	content := `
[elasticsearch]
addresses = ["http://localhost:9200"]

[logging]
format = "xml"
`
	path := writeTempConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log format")
	}
	if want := "not valid"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/akeso.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if want := "reading config file"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestMultipleValidationErrors(t *testing.T) {
	content := `
[elasticsearch]
addresses = []

[ingest]
http_port = -1

[logging]
level = "bad"
format = "bad"
`
	path := writeTempConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	// Should report all errors, not just the first one.
	errMsg := err.Error()
	if !contains(errMsg, "addresses") {
		t.Errorf("error should mention addresses: %q", errMsg)
	}
	if !contains(errMsg, "http_port") {
		t.Errorf("error should mention http_port: %q", errMsg)
	}
	if !contains(errMsg, "level") {
		t.Errorf("error should mention level: %q", errMsg)
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "akeso.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
