package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// KeyCreateOpts holds options for creating an API key.
type KeyCreateOpts struct {
	Name      string
	Scopes    string // comma-separated
	ExpiresIn int    // seconds, 0 = no expiry
}

// RunKeysList lists all API keys.
func RunKeysList(c *client.Client, jsonOut bool) {
	data, status, err := c.Get("/api/v1/admin/keys")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status == 403 {
		fmt.Fprintf(os.Stderr, "Error: insufficient permissions (admin role required)\n")
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to list keys (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Keys []struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Prefix    string    `json:"prefix"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at"`
			Revoked   bool      `json:"revoked"`
			Scopes    []string  `json:"scopes"`
		} `json:"keys"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("API Keys: %d total\n", resp.Total)
	fmt.Println(strings.Repeat("─", 110))
	fmt.Printf("%-36s  %-20s  %-14s  %-10s  %-20s  %s\n", "ID", "NAME", "PREFIX", "STATUS", "CREATED", "SCOPES")
	fmt.Println(strings.Repeat("─", 110))

	for _, k := range resp.Keys {
		status := "active"
		if k.Revoked {
			status = "revoked"
		} else if !k.ExpiresAt.IsZero() && time.Now().After(k.ExpiresAt) {
			status = "expired"
		}

		scopes := "(all)"
		if len(k.Scopes) > 0 {
			scopes = strings.Join(k.Scopes, ",")
		}

		fmt.Printf("%-36s  %-20s  %-14s  %-10s  %-20s  %s\n",
			k.ID,
			truncate(k.Name, 20),
			k.Prefix,
			status,
			k.CreatedAt.Format("2006-01-02 15:04"),
			scopes,
		)
	}
}

// RunKeysCreate creates a new API key.
func RunKeysCreate(c *client.Client, opts KeyCreateOpts, jsonOut bool) {
	if opts.Name == "" {
		fmt.Fprintf(os.Stderr, "Error: --name is required\n")
		os.Exit(1)
	}

	var scopes []string
	if opts.Scopes != "" {
		scopes = strings.Split(opts.Scopes, ",")
		for i, s := range scopes {
			scopes[i] = strings.TrimSpace(s)
		}
	}

	body := map[string]any{
		"name":       opts.Name,
		"scopes":     scopes,
		"expires_in": opts.ExpiresIn,
	}

	data, status, err := c.Post("/api/v1/admin/keys", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status == 403 {
		fmt.Fprintf(os.Stderr, "Error: insufficient permissions (admin role required)\n")
		os.Exit(1)
	}

	if status != 201 {
		fmt.Fprintf(os.Stderr, "Failed to create key (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Prefix       string   `json:"prefix"`
		PlaintextKey string   `json:"plaintext_key"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("API key created successfully:\n")
	fmt.Printf("  ID:     %s\n", resp.ID)
	fmt.Printf("  Name:   %s\n", resp.Name)
	fmt.Printf("  Prefix: %s\n", resp.Prefix)
	if len(resp.Scopes) > 0 {
		fmt.Printf("  Scopes: %s\n", strings.Join(resp.Scopes, ", "))
	} else {
		fmt.Printf("  Scopes: (all)\n")
	}
	fmt.Println()
	fmt.Printf("  Key:    %s\n", resp.PlaintextKey)
	fmt.Println()
	fmt.Println("  Save this key now — it will not be shown again.")
}

// RunKeysRevoke revokes an API key by ID.
func RunKeysRevoke(c *client.Client, keyID string, jsonOut bool) {
	if keyID == "" {
		fmt.Fprintf(os.Stderr, "Error: key ID argument is required\n")
		os.Exit(1)
	}

	data, status, err := c.Delete("/api/v1/admin/keys/" + keyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to revoke key (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	fmt.Printf("API key %s revoked\n", keyID)
}
