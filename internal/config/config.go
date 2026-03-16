package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the top-level SentinelSIEM configuration.
type Config struct {
	Elasticsearch ElasticsearchConfig `toml:"elasticsearch"`
	Ingest        IngestConfig        `toml:"ingest"`
	Correlate     CorrelateConfig     `toml:"correlate"`
	Query         QueryConfig         `toml:"query"`
	Auth          AuthConfig          `toml:"auth"`
	Cases         CasesConfig         `toml:"cases"`
	Logging       LoggingConfig       `toml:"logging"`
}

// ElasticsearchConfig holds Elasticsearch connection settings.
type ElasticsearchConfig struct {
	Addresses   []string `toml:"addresses"`
	Username    string   `toml:"username"`
	Password    string   `toml:"password"`
	IndexPrefix string   `toml:"index_prefix"`
	TLS         TLSConfig `toml:"tls"`
}

// TLSConfig holds TLS settings for Elasticsearch connections.
type TLSConfig struct {
	Enabled            bool   `toml:"enabled"`
	CACert             string `toml:"ca_cert"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
}

// IngestConfig holds ingestion server settings.
type IngestConfig struct {
	HTTPAddr      string       `toml:"http_addr"`
	HTTPPort      int          `toml:"http_port"`
	RateLimit     int          `toml:"rate_limit"`
	APIKeys       []string     `toml:"api_keys"`
	Syslog        SyslogConfig `toml:"syslog"`
}

// SyslogConfig holds syslog listener settings.
type SyslogConfig struct {
	TCPPort       int    `toml:"tcp_port"`
	UDPPort       int    `toml:"udp_port"`
	TLSPort       int    `toml:"tls_port"`
	TLSCert       string `toml:"tls_cert"`
	TLSKey        string `toml:"tls_key"`
	MaxConns      int    `toml:"max_connections"`
	SubParserDir  string `toml:"subparser_dir"`
	MaxMessageLen int    `toml:"max_message_len"`
}

// CorrelateConfig holds correlation engine settings.
type CorrelateConfig struct {
	RulesDir         string `toml:"rules_dir"`
	LogsourceMapPath string `toml:"logsource_map_path"`
	ReloadInterval   int    `toml:"reload_interval_sec"`
	StateExpirySec   int    `toml:"state_expiry_sec"`
	MaxBucketsPerRule int   `toml:"max_buckets_per_rule"`
	DedupWindowSec   int    `toml:"dedup_window_sec"`
}

// QueryConfig holds query API server settings.
type QueryConfig struct {
	Addr        string   `toml:"addr"`
	Port        int      `toml:"port"`
	CORSOrigins []string `toml:"cors_origins"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	JWTSecret        string `toml:"jwt_secret"`
	MFAEncryptionKey string `toml:"mfa_encryption_key"` // 64-char hex (32 bytes AES-256-GCM)
}

// CasesConfig holds case management settings.
type CasesConfig struct {
	RetentionDays    int  `toml:"retention_days"`
	AutoExtract      bool `toml:"auto_extract_observables"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() Config {
	return Config{
		Elasticsearch: ElasticsearchConfig{
			Addresses:   []string{"http://localhost:9200"},
			IndexPrefix: "sentinel",
		},
		Ingest: IngestConfig{
			HTTPAddr:  "0.0.0.0",
			HTTPPort:  8080,
			RateLimit: 10000,
			Syslog: SyslogConfig{
				TCPPort: 1514,
				UDPPort: 1514,
				TLSPort:       0,
				MaxConns:      1000,
				SubParserDir:  "parsers",
				MaxMessageLen: 65536,
			},
		},
		Correlate: CorrelateConfig{
			RulesDir:         "rules",
			LogsourceMapPath: "parsers/logsource_map.yaml",
			ReloadInterval:   30,
			StateExpirySec:    3600,
			MaxBucketsPerRule: 10000,
			DedupWindowSec:   60,
		},
		Auth: AuthConfig{
			JWTSecret: "change-me-in-production",
		},
		Query: QueryConfig{
			Addr:        "0.0.0.0",
			Port:        8081,
			CORSOrigins: []string{"http://localhost:3000"},
		},
		Cases: CasesConfig{
			RetentionDays: 365,
			AutoExtract:   true,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// Load reads a TOML config file and returns a validated Config.
// Defaults are applied first, then the file values override them.
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config file: %w", err)
	}

	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the config for required fields and valid values.
func (c *Config) Validate() error {
	var errs []string

	// Elasticsearch
	if len(c.Elasticsearch.Addresses) == 0 {
		errs = append(errs, "elasticsearch.addresses: at least one address required")
	}
	for i, addr := range c.Elasticsearch.Addresses {
		if addr == "" {
			errs = append(errs, fmt.Sprintf("elasticsearch.addresses[%d]: cannot be empty", i))
		}
	}

	// Ingest
	if c.Ingest.HTTPPort < 1 || c.Ingest.HTTPPort > 65535 {
		errs = append(errs, fmt.Sprintf("ingest.http_port: %d is not a valid port (1-65535)", c.Ingest.HTTPPort))
	}
	if c.Ingest.RateLimit < 0 {
		errs = append(errs, "ingest.rate_limit: cannot be negative")
	}
	if c.Ingest.Syslog.TCPPort < 0 || c.Ingest.Syslog.TCPPort > 65535 {
		errs = append(errs, fmt.Sprintf("ingest.syslog.tcp_port: %d is not a valid port", c.Ingest.Syslog.TCPPort))
	}
	if c.Ingest.Syslog.UDPPort < 0 || c.Ingest.Syslog.UDPPort > 65535 {
		errs = append(errs, fmt.Sprintf("ingest.syslog.udp_port: %d is not a valid port", c.Ingest.Syslog.UDPPort))
	}
	if c.Ingest.Syslog.TLSPort < 0 || c.Ingest.Syslog.TLSPort > 65535 {
		errs = append(errs, fmt.Sprintf("ingest.syslog.tls_port: %d is not a valid port", c.Ingest.Syslog.TLSPort))
	}
	if c.Ingest.Syslog.TLSPort > 0 && (c.Ingest.Syslog.TLSCert == "" || c.Ingest.Syslog.TLSKey == "") {
		errs = append(errs, "ingest.syslog: tls_cert and tls_key are required when tls_port is set")
	}

	// Query
	if c.Query.Port < 1 || c.Query.Port > 65535 {
		errs = append(errs, fmt.Sprintf("query.port: %d is not a valid port (1-65535)", c.Query.Port))
	}

	// Cases
	if c.Cases.RetentionDays < 1 {
		errs = append(errs, fmt.Sprintf("cases.retention_days: %d must be at least 1", c.Cases.RetentionDays))
	}

	// Logging
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		errs = append(errs, fmt.Sprintf("logging.level: %q is not valid (debug, info, warn, error)", c.Logging.Level))
	}
	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		errs = append(errs, fmt.Sprintf("logging.format: %q is not valid (json, text)", c.Logging.Format))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}
