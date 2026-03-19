package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
)

// UserCreateOpts holds options for creating a user.
type UserCreateOpts struct {
	Username    string
	Password    string
	DisplayName string
	Email       string
	Role        string
}

// RunUsersList lists all users.
func RunUsersList(c *client.Client, jsonOut bool) {
	data, status, err := c.Get("/api/v1/admin/users")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status == 403 {
		fmt.Fprintf(os.Stderr, "Error: insufficient permissions (admin role required)\n")
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to list users (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Users []json.RawMessage `json:"users"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Users: %d total\n", resp.Total)
	fmt.Println(strings.Repeat("─", 110))
	fmt.Printf("%-20s  %-25s  %-20s  %-5s  %-8s  %-20s\n", "USERNAME", "DISPLAY NAME", "ROLE", "MFA", "STATUS", "LAST LOGIN")
	fmt.Println(strings.Repeat("─", 110))

	for _, raw := range resp.Users {
		var u map[string]any
		if err := json.Unmarshal(raw, &u); err != nil {
			continue
		}

		username, _ := u["username"].(string)
		display, _ := u["display_name"].(string)
		role, _ := u["role"].(string)
		mfa := "no"
		if m, ok := u["mfa_enabled"].(bool); ok && m {
			mfa = "yes"
		}
		status := "active"
		if d, ok := u["disabled"].(bool); ok && d {
			status = "disabled"
		}
		lastLogin := "never"
		if ll, ok := u["last_login_at"].(string); ok && ll != "" {
			if t, err := time.Parse(time.RFC3339Nano, ll); err == nil {
				lastLogin = t.Format("2006-01-02 15:04")
			}
		}

		fmt.Printf("%-20s  %-25s  %-20s  %-5s  %-8s  %-20s\n", username, truncate(display, 25), role, mfa, status, lastLogin)
	}
}

// RunUsersCreate creates a new user.
func RunUsersCreate(c *client.Client, opts UserCreateOpts, jsonOut bool) {
	if opts.Username == "" {
		fmt.Fprintf(os.Stderr, "Error: --username is required\n")
		os.Exit(1)
	}
	if opts.Password == "" {
		fmt.Fprintf(os.Stderr, "Error: --password is required\n")
		os.Exit(1)
	}
	if opts.DisplayName == "" {
		fmt.Fprintf(os.Stderr, "Error: --display-name is required\n")
		os.Exit(1)
	}
	if opts.Role == "" {
		opts.Role = "analyst"
	}

	body := map[string]string{
		"username":     opts.Username,
		"password":     opts.Password,
		"display_name": opts.DisplayName,
		"role":         opts.Role,
	}
	if opts.Email != "" {
		body["email"] = opts.Email
	}

	data, status, err := c.Post("/api/v1/admin/users", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status == 403 {
		fmt.Fprintf(os.Stderr, "Error: insufficient permissions (admin role required)\n")
		os.Exit(1)
	}

	if status == 409 {
		fmt.Fprintf(os.Stderr, "Error: username %q already exists\n", opts.Username)
		os.Exit(1)
	}

	if status != 201 {
		fmt.Fprintf(os.Stderr, "Failed to create user (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	fmt.Printf("User %q created successfully (role: %s)\n", opts.Username, opts.Role)
}

// RunUsersDisable disables a user account by username.
func RunUsersDisable(c *client.Client, username string, jsonOut bool) {
	if username == "" {
		fmt.Fprintf(os.Stderr, "Error: username argument is required\n")
		os.Exit(1)
	}

	// First, find user ID by listing users.
	userID := resolveUserID(c, username)

	data, status, err := c.Put("/api/v1/admin/users/"+userID+"/disable", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to disable user (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	fmt.Printf("User %q disabled\n", username)
}

// RunUsersEnable enables a disabled user account by username.
func RunUsersEnable(c *client.Client, username string, jsonOut bool) {
	if username == "" {
		fmt.Fprintf(os.Stderr, "Error: username argument is required\n")
		os.Exit(1)
	}

	userID := resolveUserID(c, username)

	data, status, err := c.Put("/api/v1/admin/users/"+userID+"/enable", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to enable user (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	fmt.Printf("User %q enabled\n", username)
}

// RunUsersResetMFA resets MFA for a user by username.
func RunUsersResetMFA(c *client.Client, username string, jsonOut bool) {
	if username == "" {
		fmt.Fprintf(os.Stderr, "Error: username argument is required\n")
		os.Exit(1)
	}

	userID := resolveUserID(c, username)

	data, status, err := c.Delete("/api/v1/admin/users/" + userID + "/mfa")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to reset MFA (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	if jsonOut {
		fmt.Println(string(data))
		return
	}

	fmt.Printf("MFA reset for user %q\n", username)
}

// resolveUserID looks up a user ID by username via the admin API.
func resolveUserID(c *client.Client, username string) string {
	data, status, err := c.Get("/api/v1/admin/users")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error looking up user: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Failed to look up users (HTTP %d): %s\n", status, string(data))
		os.Exit(1)
	}

	var resp struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing user list: %v\n", err)
		os.Exit(1)
	}

	for _, u := range resp.Users {
		if u.Username == username {
			return u.ID
		}
	}

	fmt.Fprintf(os.Stderr, "Error: user %q not found\n", username)
	os.Exit(1)
	return ""
}
