package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// RunHealth checks the API server health.
func RunHealth(c *client.Client, jsonOut bool) {
	data, status, err := c.Get("/api/v1/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Health check failed (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	svc, _ := resp["service"].(string)
	st, _ := resp["status"].(string)

	fmt.Printf("Service:  %s\n", svc)
	fmt.Printf("Status:   %s\n", st)
}
