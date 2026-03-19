package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
	"github.com/derekxmartin/akeso-siem/internal/config"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// DiagnoseOpts holds options for the diagnose command.
type DiagnoseOpts struct {
	ConfigPath string
	IngestURL  string
}

// RunDiagnose performs a comprehensive health check of the AkesoSIEM deployment.
func RunDiagnose(c *client.Client, opts DiagnoseOpts, jsonOut bool) {
	type checkResult struct {
		Name   string `json:"name"`
		Status string `json:"status"` // "ok", "warn", "fail"
		Detail string `json:"detail,omitempty"`
	}

	var checks []checkResult

	add := func(name, status, detail string) {
		checks = append(checks, checkResult{Name: name, Status: status, Detail: detail})
		if !jsonOut {
			icon := "✓"
			if status == "warn" {
				icon = "⚠"
			} else if status == "fail" {
				icon = "✗"
			}
			if detail != "" {
				fmt.Printf("  %s %-35s %s\n", icon, name, detail)
			} else {
				fmt.Printf("  %s %s\n", icon, name)
			}
		}
	}

	if !jsonOut {
		fmt.Println("AkesoSIEM Diagnostics")
		fmt.Println(strings.Repeat("═", 60))
		fmt.Println()
	}

	// 1. Config validation.
	if !jsonOut {
		fmt.Println("Configuration")
		fmt.Println(strings.Repeat("─", 60))
	}

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = "akeso.toml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		add("Config file ("+configPath+")", "fail", err.Error())
	} else {
		add("Config file ("+configPath+")", "ok", "valid")

		// Check for default/insecure values.
		if cfg.Auth.JWTSecret == "change-me-in-production" {
			add("JWT secret", "warn", "using default — change for production")
		} else {
			add("JWT secret", "ok", "custom value set")
		}

		if cfg.Auth.MFAEncryptionKey != "" {
			add("MFA encryption", "ok", "configured")
		} else {
			add("MFA encryption", "warn", "not configured — MFA enrollment unavailable")
		}

		if len(cfg.Ingest.APIKeys) > 0 {
			hasDefault := false
			for _, k := range cfg.Ingest.APIKeys {
				if k == "changeme" {
					hasDefault = true
				}
			}
			if hasDefault {
				add("Ingest API keys", "warn", fmt.Sprintf("%d key(s) — contains default 'changeme'", len(cfg.Ingest.APIKeys)))
			} else {
				add("Ingest API keys", "ok", fmt.Sprintf("%d key(s) configured", len(cfg.Ingest.APIKeys)))
			}
		} else {
			add("Ingest API keys", "warn", "no keys configured")
		}
	}

	if !jsonOut {
		fmt.Println()
	}

	// 2. Query server health.
	if !jsonOut {
		fmt.Println("Services")
		fmt.Println(strings.Repeat("─", 60))
	}

	queryData, queryStatus, queryErr := c.Get("/api/v1/health")
	if queryErr != nil {
		add("Query server ("+c.BaseURL+")", "fail", "unreachable")
	} else if queryStatus != 200 {
		add("Query server ("+c.BaseURL+")", "fail", fmt.Sprintf("HTTP %d", queryStatus))
	} else {
		var resp map[string]any
		json.Unmarshal(queryData, &resp)
		status, _ := resp["status"].(string)
		add("Query server ("+c.BaseURL+")", "ok", status)
	}

	// 3. Ingest server health.
	ingestURL := opts.IngestURL
	ingestReq, _ := http.NewRequest("GET", ingestURL+"/api/v1/health", nil)
	if ingestReq != nil {
		ingestResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(ingestReq)
		if err != nil {
			add("Ingest server ("+ingestURL+")", "fail", "unreachable")
		} else {
			ingestResp.Body.Close()
			if ingestResp.StatusCode == 200 {
				add("Ingest server ("+ingestURL+")", "ok", "healthy")
			} else {
				add("Ingest server ("+ingestURL+")", "fail", fmt.Sprintf("HTTP %d", ingestResp.StatusCode))
			}
		}
	}

	// 4. Elasticsearch connectivity (via query server).
	esData, esStatus, esErr := c.Post("/api/v1/query", map[string]any{
		"query": "*",
		"size":  0,
	})
	if esErr != nil || esStatus != 200 {
		add("Elasticsearch", "fail", "query failed — check ES connectivity")
	} else {
		var resp map[string]any
		json.Unmarshal(esData, &resp)
		total, _ := resp["total"].(float64)
		tookMs, _ := resp["took_ms"].(float64)
		add("Elasticsearch", "ok", fmt.Sprintf("%d events indexed, query took %dms", int(total), int(tookMs)))
	}

	if !jsonOut {
		fmt.Println()
	}

	// 5. Rules validation.
	if !jsonOut {
		fmt.Println("Rules")
		fmt.Println(strings.Repeat("─", 60))
	}

	rulesDir := "rules"
	if cfg.Correlate.RulesDir != "" {
		rulesDir = cfg.Correlate.RulesDir
	}

	rules, parseErrors := correlate.LoadRulesFromDir(rulesDir)
	if len(rules) == 0 && len(parseErrors) == 0 {
		add("Rules directory ("+rulesDir+")", "warn", "no rule files found")
	} else {
		singleEvent := 0
		correlation := 0
		for _, r := range rules {
			if r.Type == "" {
				singleEvent++
			} else {
				correlation++
			}
		}
		add("Rules loaded", "ok", fmt.Sprintf("%d valid (%d single-event, %d correlation)", len(rules), singleEvent, correlation))

		if len(parseErrors) > 0 {
			add("Rule parse errors", "warn", fmt.Sprintf("%d files had errors", len(parseErrors)))
			if !jsonOut {
				for _, pe := range parseErrors {
					fmt.Printf("      %s: %v\n", pe.File, pe.Err)
				}
			}
		}
	}

	// Check logsource map.
	lsPath := "parsers/logsource_map.yaml"
	if cfg.Correlate.LogsourceMapPath != "" {
		lsPath = cfg.Correlate.LogsourceMapPath
	}
	if _, err := os.Stat(lsPath); err != nil {
		add("Logsource map ("+lsPath+")", "fail", "file not found")
	} else {
		lsMap, err := correlate.LoadLogsourceMap(lsPath)
		if err != nil {
			add("Logsource map ("+lsPath+")", "fail", err.Error())
		} else {
			_ = lsMap
			add("Logsource map ("+lsPath+")", "ok", "valid")
		}
	}

	if !jsonOut {
		fmt.Println()

		// Summary.
		okCount, warnCount, failCount := 0, 0, 0
		for _, ch := range checks {
			switch ch.Status {
			case "ok":
				okCount++
			case "warn":
				warnCount++
			case "fail":
				failCount++
			}
		}

		fmt.Println(strings.Repeat("═", 60))
		fmt.Printf("Summary: %d passed, %d warnings, %d failures\n", okCount, warnCount, failCount)

		if failCount > 0 {
			os.Exit(1)
		}
		return
	}

	// JSON output.
	out, _ := json.MarshalIndent(map[string]any{
		"checks": checks,
	}, "", "  ")
	fmt.Println(string(out))

	for _, ch := range checks {
		if ch.Status == "fail" {
			os.Exit(1)
		}
	}
}
