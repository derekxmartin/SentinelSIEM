package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// QueryOpts holds options for the query command.
type QueryOpts struct {
	Query string
	Index string
	Size  int
}

// RunQuery executes an ad-hoc query against the API.
func RunQuery(c *client.Client, opts QueryOpts, jsonOut bool) {
	body := map[string]any{
		"query": opts.Query,
	}
	if opts.Index != "" {
		body["index"] = opts.Index
	}
	if opts.Size > 0 {
		body["size"] = opts.Size
	}

	data, status, err := c.Post("/api/v1/query", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Query failed (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Total  int               `json:"total"`
		Hits   []json.RawMessage `json:"hits"`
		TookMs int64             `json:"took_ms"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Results: %d (took %dms)\n", resp.Total, resp.TookMs)
	fmt.Println(strings.Repeat("─", 80))

	for i, hit := range resp.Hits {
		var doc map[string]any
		if err := json.Unmarshal(hit, &doc); err != nil {
			continue
		}

		ts, _ := doc["@timestamp"].(string)
		src, _ := doc["source_type"].(string)
		msg, _ := doc["message"].(string)
		if msg == "" {
			msg, _ = doc["event.action"].(string)
		}

		if ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ts = t.Format("2006-01-02 15:04:05")
			}
		}

		fmt.Printf("[%d] %s  %-20s  %s\n", i+1, ts, src, truncate(msg, 60))
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
