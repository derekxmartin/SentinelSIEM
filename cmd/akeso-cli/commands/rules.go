package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// RulesOpts holds options for the rules command.
type RulesOpts struct {
	Size int
}

// RunRules lists loaded detection rules via the query API.
func RunRules(c *client.Client, opts RulesOpts, jsonOut bool) {
	size := opts.Size
	if size == 0 {
		size = 100
	}

	body := map[string]any{
		"query": "*",
		"index": "sentinel-rules",
		"size":  size,
	}

	data, status, err := c.Post("/api/v1/query", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to list rules (HTTP %d): %s\n", status, string(data))
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

	fmt.Printf("Rules: %d total\n", resp.Total)
	fmt.Println(strings.Repeat("─", 110))
	fmt.Printf("%-36s  %-8s  %-10s  %-40s  %s\n", "ID", "ENABLED", "LEVEL", "TITLE", "TACTIC")
	fmt.Println(strings.Repeat("─", 110))

	for _, hit := range resp.Hits {
		var doc map[string]any
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}

		id, _ := doc["id"].(string)
		title, _ := doc["title"].(string)
		level, _ := doc["level"].(string)
		enabled := "yes"
		if dis, ok := doc["disabled"].(bool); ok && dis {
			enabled = "no"
		}

		tactic := ""
		if tags, ok := doc["tags"].([]any); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok && strings.HasPrefix(s, "attack.") && !strings.HasPrefix(s, "attack.t") {
					tactic = strings.TrimPrefix(s, "attack.")
					break
				}
			}
		}

		fmt.Printf("%-36s  %-8s  %-10s  %-40s  %s\n", id, enabled, level, truncate(title, 40), tactic)
	}
}
