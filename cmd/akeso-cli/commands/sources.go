package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// RunSources lists configured log sources.
func RunSources(c *client.Client, jsonOut bool) {
	data, status, err := c.Get("/api/v1/sources")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to list sources (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Sources []json.RawMessage `json:"sources"`
		Total   int               `json:"total"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sources: %d total\n", resp.Total)
	fmt.Println(strings.Repeat("─", 110))
	fmt.Printf("%-36s  %-20s  %-15s  %-10s  %-20s\n", "ID", "NAME", "TYPE", "STATUS", "CREATED")
	fmt.Println(strings.Repeat("─", 110))

	for _, raw := range resp.Sources {
		var src map[string]any
		if err := json.Unmarshal(raw, &src); err != nil {
			continue
		}

		id, _ := src["id"].(string)
		name, _ := src["name"].(string)
		srcType, _ := src["source_type"].(string)
		status, _ := src["status"].(string)
		created, _ := src["created_at"].(string)

		if created != "" {
			if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
				created = t.Format("2006-01-02 15:04")
			}
		}

		fmt.Printf("%-36s  %-20s  %-15s  %-10s  %-20s\n", id, truncate(name, 20), srcType, status, created)
	}
}
