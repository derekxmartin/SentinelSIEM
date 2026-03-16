package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/SentinelSIEM/sentinel-siem/cmd/sentinel-cli/client"
	"github.com/SentinelSIEM/sentinel-siem/cmd/sentinel-cli/commands"
)

const defaultURL = "http://localhost:8081"

func main() {
	// Global flags.
	var (
		serverURL string
		apiKey    string
		jsonOut   bool
	)

	flag.StringVar(&serverURL, "server", envOrDefault("SENTINEL_URL", defaultURL), "API server URL (env: SENTINEL_URL)")
	flag.StringVar(&apiKey, "api-key", os.Getenv("SENTINEL_API_KEY"), "API key for authentication (env: SENTINEL_API_KEY)")
	flag.BoolVar(&jsonOut, "json", false, "output raw JSON")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SentinelSIEM Management CLI

Usage:
  sentinel-cli [global flags] <command> [subcommand] [flags]

Global Flags:
  --server <url>     API server URL (default: %s, env: SENTINEL_URL)
  --api-key <key>    API key for auth (env: SENTINEL_API_KEY)
  --json             Output raw JSON instead of formatted tables

Commands:
  health                       Check API server health
  query    <query>             Execute an ad-hoc search query
  alerts                       List recent alerts
  rules                        List detection rules
  sources                      List configured log sources
  users    list                List all users
  users    create              Create a new user
  users    disable <username>  Disable a user account
  users    enable  <username>  Enable a disabled user account
  users    reset-mfa <user>    Reset MFA for a user
  keys     list                List API keys
  keys     create              Create a new API key
  keys     revoke  <id>        Revoke an API key

Examples:
  sentinel-cli health
  sentinel-cli --json users list
  sentinel-cli users create --username jsmith --display-name "John Smith" --role analyst
  sentinel-cli users disable jsmith
  sentinel-cli users reset-mfa jsmith
  sentinel-cli keys create --name "ingest-prod" --scopes "ingest"
  sentinel-cli query "source_type:sentinel_edr AND event.action:process_create"
  sentinel-cli alerts --level critical
`, defaultURL)
	}

	// Parse global flags, stopping at the first non-flag argument (command).
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	c := client.New(serverURL, apiKey)
	command := args[0]
	subArgs := args[1:]

	switch command {
	case "health":
		commands.RunHealth(c, jsonOut)

	case "query":
		runQueryCmd(c, subArgs, jsonOut)

	case "alerts":
		runAlertsCmd(c, subArgs, jsonOut)

	case "rules":
		runRulesCmd(c, subArgs, jsonOut)

	case "sources":
		commands.RunSources(c, jsonOut)

	case "users":
		runUsersCmd(c, subArgs, jsonOut)

	case "keys":
		runKeysCmd(c, subArgs, jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

func runQueryCmd(c *client.Client, args []string, jsonOut bool) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	index := fs.String("index", "", "Elasticsearch index pattern")
	size := fs.Int("size", 25, "number of results")
	fs.Parse(args)

	query := fs.Arg(0)
	if query == "" {
		fmt.Fprintf(os.Stderr, "Usage: sentinel-cli query <query> [--index <pattern>] [--size <n>]\n")
		os.Exit(1)
	}

	commands.RunQuery(c, commands.QueryOpts{
		Query: query,
		Index: *index,
		Size:  *size,
	}, jsonOut)
}

func runAlertsCmd(c *client.Client, args []string, jsonOut bool) {
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	size := fs.Int("size", 25, "number of alerts to show")
	level := fs.String("level", "", "filter by severity (low, medium, high, critical)")
	fs.Parse(args)

	commands.RunAlerts(c, commands.AlertsOpts{
		Size:  *size,
		Level: *level,
	}, jsonOut)
}

func runRulesCmd(c *client.Client, args []string, jsonOut bool) {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	size := fs.Int("size", 100, "number of rules to show")
	fs.Parse(args)

	commands.RunRules(c, commands.RulesOpts{
		Size: *size,
	}, jsonOut)
}

func runUsersCmd(c *client.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: sentinel-cli users <list|create|disable|enable|reset-mfa> [flags]\n")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		commands.RunUsersList(c, jsonOut)

	case "create":
		fs := flag.NewFlagSet("users create", flag.ExitOnError)
		username := fs.String("username", "", "username (required)")
		password := fs.String("password", "", "password (required)")
		displayName := fs.String("display-name", "", "display name (required)")
		email := fs.String("email", "", "email address")
		role := fs.String("role", "analyst", "role: admin, soc_lead, detection_engineer, analyst, read_only")
		fs.Parse(subArgs)

		commands.RunUsersCreate(c, commands.UserCreateOpts{
			Username:    *username,
			Password:    *password,
			DisplayName: *displayName,
			Email:       *email,
			Role:        *role,
		}, jsonOut)

	case "disable":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: sentinel-cli users disable <username>\n")
			os.Exit(1)
		}
		commands.RunUsersDisable(c, subArgs[0], jsonOut)

	case "enable":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: sentinel-cli users enable <username>\n")
			os.Exit(1)
		}
		commands.RunUsersEnable(c, subArgs[0], jsonOut)

	case "reset-mfa":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: sentinel-cli users reset-mfa <username>\n")
			os.Exit(1)
		}
		commands.RunUsersResetMFA(c, subArgs[0], jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown users subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: sentinel-cli users <list|create|disable|enable|reset-mfa> [flags]\n")
		os.Exit(1)
	}
}

func runKeysCmd(c *client.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: sentinel-cli keys <list|create|revoke> [flags]\n")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		commands.RunKeysList(c, jsonOut)

	case "create":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		name := fs.String("name", "", "key name (required)")
		scopes := fs.String("scopes", "", "comma-separated scopes: ingest, query, admin")
		expiresIn := fs.Int("expires-in", 0, "expiry in seconds (0 = no expiry)")
		fs.Parse(subArgs)

		commands.RunKeysCreate(c, commands.KeyCreateOpts{
			Name:      *name,
			Scopes:    *scopes,
			ExpiresIn: *expiresIn,
		}, jsonOut)

	case "revoke":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: sentinel-cli keys revoke <key-id>\n")
			os.Exit(1)
		}
		commands.RunKeysRevoke(c, subArgs[0], jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown keys subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: sentinel-cli keys <list|create|revoke> [flags]\n")
		os.Exit(1)
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
