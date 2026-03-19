package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// AlertsOpts holds options for the alerts command.
type AlertsOpts struct {
	Size  int
	Level string // filter by severity: low, medium, high, critical
}

// RunAlerts lists recent alerts via the query API.
func RunAlerts(c *client.Client, opts AlertsOpts, jsonOut bool) {
	q := "*"
	if opts.Level != "" {
		q = fmt.Sprintf("level:%s", opts.Level)
	}

	size := opts.Size
	if size == 0 {
		size = 25
	}

	body := map[string]any{
		"query": q,
		"index": "akeso-alerts-*",
		"size":  size,
	}

	data, status, err := c.Post("/api/v1/query", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to list alerts (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Total int               `json:"total"`
		Hits  []json.RawMessage `json:"hits"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Alerts: %d total\n", resp.Total)
	fmt.Println(strings.Repeat("─", 100))
	fmt.Printf("%-20s  %-10s  %-40s  %s\n", "TIMESTAMP", "LEVEL", "TITLE", "RULE ID")
	fmt.Println(strings.Repeat("─", 100))

	for _, hit := range resp.Hits {
		var doc map[string]any
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}

		ts, _ := doc["@timestamp"].(string)
		level, _ := doc["level"].(string)
		title, _ := doc["title"].(string)
		ruleID, _ := doc["rule_id"].(string)

		if ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ts = t.Format("2006-01-02 15:04:05")
			}
		}

		fmt.Printf("%-20s  %-10s  %-40s  %s\n", ts, level, truncate(title, 40), ruleID)
	}
}
