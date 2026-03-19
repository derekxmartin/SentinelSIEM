package commands

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// IngestTestOpts holds options for the ingest test command.
type IngestTestOpts struct {
	IngestURL  string
	IngestKey  string
	SourceType string
}

// IngestReplayOpts holds options for the ingest replay command.
type IngestReplayOpts struct {
	IngestURL  string
	IngestKey  string
	File       string
	BatchSize  int
}

// RunIngestTest sends a single test event to the ingest endpoint.
func RunIngestTest(opts IngestTestOpts, jsonOut bool) {
	sourceType := opts.SourceType
	if sourceType == "" {
		sourceType = "akeso_edr"
	}

	testEvent := map[string]any{
		"source_type":    sourceType,
		"@timestamp":     time.Now().UTC().Format(time.RFC3339),
		"event.action":   "sentinel_cli_test",
		"event.category": "test",
		"event.type":     "info",
		"host.name":      "akeso-cli-test",
		"message":        "AkesoSIEM CLI test event",
		"agent.name":     "akeso-cli",
		"agent.version":  "1.0.0",
	}

	data, err := json.Marshal(testEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling test event: %v\n", err)
		os.Exit(1)
	}

	url := opts.IngestURL + "/api/v1/ingest"

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", opts.IngestKey)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if strings.Contains(err.Error(), "connection refused") {
			fmt.Fprintf(os.Stderr, "Is the ingest server running on %s?\n", opts.IngestURL)
		}
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if jsonOut {
		fmt.Println(string(body))
		return
	}

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		fmt.Fprintf(os.Stderr, "Ingest failed (HTTP %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err == nil {
		accepted, _ := result["accepted"].(float64)
		fmt.Printf("Test event sent successfully (accepted: %d)\n", int(accepted))
	} else {
		fmt.Printf("Response: %s\n", string(body))
	}

	fmt.Printf("  source_type: %s\n", sourceType)
	fmt.Printf("  timestamp:   %s\n", testEvent["@timestamp"])
	fmt.Printf("  message:     %s\n", testEvent["message"])
}

// RunIngestReplay replays an NDJSON file to the ingest endpoint.
func RunIngestReplay(opts IngestReplayOpts, jsonOut bool) {
	if opts.File == "" {
		fmt.Fprintf(os.Stderr, "Error: file argument is required\n")
		os.Exit(1)
	}

	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	f, err := os.Open(opts.File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Read all lines (NDJSON).
	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Quick validity check.
		if line[0] != '{' {
			continue
		}
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		lines = append(lines, lineCopy)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	if len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "No events found in %s\n", opts.File)
		os.Exit(1)
	}

	fmt.Printf("Replaying %d events from %s (batch size: %d)\n", len(lines), opts.File, batchSize)

	totalAccepted := 0
	totalBatches := 0
	start := time.Now()

	for i := 0; i < len(lines); i += batchSize {
		end := i + batchSize
		if end > len(lines) {
			end = len(lines)
		}

		batch := lines[i:end]

		// Build NDJSON payload.
		var buf bytes.Buffer
		for _, line := range batch {
			buf.Write(line)
			buf.WriteByte('\n')
		}

		url := opts.IngestURL + "/api/v1/ingest"
		req, err := http.NewRequest("POST", url, &buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("X-API-Key", opts.IngestKey)

		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending batch %d: %v\n", totalBatches+1, err)
			os.Exit(1)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 202 {
			fmt.Fprintf(os.Stderr, "Batch %d failed (HTTP %d): %s\n", totalBatches+1, resp.StatusCode, string(body))
			os.Exit(1)
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err == nil {
			accepted, _ := result["accepted"].(float64)
			totalAccepted += int(accepted)
		}

		totalBatches++
		fmt.Printf("  Batch %d: sent %d events (%d/%d)\n", totalBatches, len(batch), end, len(lines))
	}

	elapsed := time.Since(start)

	if jsonOut {
		out, _ := json.MarshalIndent(map[string]any{
			"file":           opts.File,
			"total_events":   len(lines),
			"total_accepted": totalAccepted,
			"batches":        totalBatches,
			"elapsed_ms":     elapsed.Milliseconds(),
			"events_per_sec": float64(totalAccepted) / elapsed.Seconds(),
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	fmt.Printf("\nReplay complete:\n")
	fmt.Printf("  Events:    %d sent, %d accepted\n", len(lines), totalAccepted)
	fmt.Printf("  Batches:   %d\n", totalBatches)
	fmt.Printf("  Elapsed:   %s\n", elapsed.Round(time.Millisecond))
	if elapsed.Seconds() > 0 {
		fmt.Printf("  Rate:      %.0f events/sec\n", float64(totalAccepted)/elapsed.Seconds())
	}
}
