package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// RulesUpdateOpts holds options for the rules update command.
type RulesUpdateOpts struct {
	RulesDir string
	Init     bool   // clone SigmaHQ rules into rules dir
	InitRepo string // custom repo URL for --init
}

const defaultSigmaRepo = "https://github.com/SigmaHQ/sigma.git"

// RunRulesUpdate validates rules on disk and triggers a hot-reload on the ingest server.
// With --init, it clones the SigmaHQ repository into the rules directory first.
func RunRulesUpdate(c *client.Client, ingestURL string, opts RulesUpdateOpts, jsonOut bool) {
	rulesDir := opts.RulesDir
	if rulesDir == "" {
		rulesDir = "rules"
	}

	// --init: clone SigmaHQ rules.
	if opts.Init {
		runRulesInit(rulesDir, opts.InitRepo)
	}

	// Step 1: Validate rules locally.
	fmt.Println("Validating rules...")
	rules, parseErrors := correlate.LoadRulesFromDir(rulesDir)

	if len(parseErrors) > 0 {
		fmt.Printf("\nParse errors (%d):\n", len(parseErrors))
		for _, pe := range parseErrors {
			fmt.Printf("  ✗ %s: %v\n", pe.File, pe.Err)
		}
	}

	if len(rules) == 0 {
		fmt.Fprintf(os.Stderr, "\nError: no valid rules found in %s\n", rulesDir)
		if opts.Init {
			fmt.Fprintf(os.Stderr, "The repository may not contain Sigma rules at the expected paths.\n")
		}
		os.Exit(1)
	}

	// Count by type.
	singleEvent := 0
	correlation := 0
	for _, r := range rules {
		if r.Type == "" {
			singleEvent++
		} else {
			correlation++
		}
	}

	fmt.Printf("\nRules validated: %d total (%d single-event, %d correlation)\n", len(rules), singleEvent, correlation)

	if len(parseErrors) > 0 {
		fmt.Printf("Parse errors: %d (rules with errors were skipped)\n", len(parseErrors))
	}

	// Step 2: Trigger hot-reload on the ingest server.
	fmt.Println("\nTriggering hot-reload on ingest server...")

	data, status, err := directPost(ingestURL+"/api/v1/rules/reload", c)

	// Handle connection failure — ingest server may not be running.
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "connect:") {
			fmt.Println("  ⚠ Ingest server not reachable — rules validated locally but hot-reload skipped.")
			fmt.Println("  Rules will be picked up automatically when the ingest server starts.")
			if jsonOut {
				result := map[string]any{
					"status":       "validated",
					"rules_total":  len(rules),
					"single_event": singleEvent,
					"correlation":  correlation,
					"parse_errors": len(parseErrors),
					"reload":       "skipped",
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))
			}
			return
		}
		fmt.Fprintf(os.Stderr, "Error contacting ingest server: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Reload failed (HTTP %d): %s\n", status, string(data))
		fmt.Println("Rolling back: rules on disk are unchanged, previous rules remain active.")
		os.Exit(1)
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err == nil {
		compiled, _ := resp["rules_compiled"].(float64)
		skipped, _ := resp["rules_skipped"].(float64)
		buckets, _ := resp["buckets"].(float64)
		errors, _ := resp["errors"].(float64)
		fmt.Printf("  Reload complete: %d compiled, %d skipped, %d buckets, %d errors\n",
			int(compiled), int(skipped), int(buckets), int(errors))
	} else {
		fmt.Printf("  Reload response: %s\n", string(data))
	}

	fmt.Println("\nRules update complete.")
}

// RunRulesValidate validates rules on disk without triggering a reload.
func RunRulesValidate(rulesDir string, jsonOut bool) {
	if rulesDir == "" {
		rulesDir = "rules"
	}

	rules, parseErrors := correlate.LoadRulesFromDir(rulesDir)

	if jsonOut {
		type ruleInfo struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Level string `json:"level"`
			Type  string `json:"type"`
			File  string `json:"file,omitempty"`
		}
		type errorInfo struct {
			File  string `json:"file"`
			Error string `json:"error"`
		}

		ruleList := make([]ruleInfo, 0, len(rules))
		for _, r := range rules {
			t := "single_event"
			if r.Type != "" {
				t = string(r.Type)
			}
			ruleList = append(ruleList, ruleInfo{
				ID:    r.ID,
				Title: r.Title,
				Level: r.Level,
				Type:  t,
			})
		}

		errList := make([]errorInfo, 0, len(parseErrors))
		for _, pe := range parseErrors {
			errList = append(errList, errorInfo{
				File:  pe.File,
				Error: pe.Err.Error(),
			})
		}

		out, _ := json.MarshalIndent(map[string]any{
			"valid_rules":  ruleList,
			"parse_errors": errList,
			"total_valid":  len(ruleList),
			"total_errors": len(errList),
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	if len(rules) == 0 && len(parseErrors) == 0 {
		fmt.Printf("No rule files found in %s\n", rulesDir)
		return
	}

	fmt.Printf("Rules directory: %s\n", rulesDir)
	fmt.Printf("Valid rules:     %d\n", len(rules))
	fmt.Printf("Parse errors:    %d\n", len(parseErrors))

	if len(parseErrors) > 0 {
		fmt.Println("\nErrors:")
		for _, pe := range parseErrors {
			fmt.Printf("  ✗ %s: %v\n", pe.File, pe.Err)
		}
	}

	if len(rules) > 0 {
		fmt.Printf("\nRules:\n")
		fmt.Printf("  %-36s  %-10s  %s\n", "ID", "LEVEL", "TITLE")
		fmt.Println("  " + strings.Repeat("─", 90))
		for _, r := range rules {
			fmt.Printf("  %-36s  %-10s  %s\n", r.ID, r.Level, truncate(r.Title, 50))
		}
	}
}

func runRulesInit(rulesDir, repoURL string) {
	if repoURL == "" {
		repoURL = defaultSigmaRepo
	}

	curatedDir := filepath.Join(rulesDir, "sigma_curated")

	// Check if already initialized.
	if info, err := os.Stat(filepath.Join(curatedDir, ".git")); err == nil && info.IsDir() {
		fmt.Println("SigmaHQ rules already cloned, pulling latest...")
		cmd := exec.Command("git", "-C", curatedDir, "pull", "--ff-only")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: git pull failed: %v\n", err)
		}
		return
	}

	// Clone the repo.
	fmt.Printf("Cloning SigmaHQ rules into %s...\n", curatedDir)
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating rules directory: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("git", "clone", "--depth", "1", repoURL, curatedDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error cloning SigmaHQ: %v\n", err)
		os.Exit(1)
	}

	// Count what we got.
	count := 0
	_ = filepath.Walk(curatedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yml" || ext == ".yaml" {
			count++
		}
		return nil
	})

	fmt.Printf("Cloned %d rule files.\n\n", count)
}

// RunRulesReload triggers an immediate hot-reload on the ingest server.
func RunRulesReload(c *client.Client, ingestURL string, jsonOut bool) {
	// The reload endpoint is on the ingest server, need direct POST.
	data, status, err := directPost(ingestURL+"/api/v1/rules/reload", c)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Reload failed (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err == nil {
		compiled, _ := resp["rules_compiled"].(float64)
		skipped, _ := resp["rules_skipped"].(float64)
		buckets, _ := resp["buckets"].(float64)
		errors, _ := resp["errors"].(float64)
		fmt.Printf("Reload complete: %d compiled, %d skipped, %d buckets, %d errors\n",
			int(compiled), int(skipped), int(buckets), int(errors))
	} else {
		fmt.Printf("Response: %s\n", string(data))
	}
}

// directPost sends a POST to the given full URL using the client's API key.
func directPost(url string, c *client.Client) ([]byte, int, error) {
	req, err := newHTTPRequest("POST", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return data, resp.StatusCode, nil
}

func newHTTPRequest(method, url string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, url, body)
}
