package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/client"
	"github.com/derekxmartin/akeso-siem/cmd/akeso-cli/commands"
)

const (
	defaultURL       = "http://localhost:8081"
	defaultIngestURL = "http://localhost:8080"
)

func main() {
	// Global flags.
	var (
		serverURL string
		apiKey    string
		ingestURL string
		ingestKey string
		jsonOut   bool
	)

	flag.StringVar(&serverURL, "server", envOrDefault("SENTINEL_URL", defaultURL), "API server URL (env: SENTINEL_URL)")
	flag.StringVar(&apiKey, "api-key", os.Getenv("SENTINEL_API_KEY"), "API key for authentication (env: SENTINEL_API_KEY)")
	flag.StringVar(&ingestURL, "ingest-server", envOrDefault("SENTINEL_INGEST_URL", defaultIngestURL), "Ingest server URL (env: SENTINEL_INGEST_URL)")
	flag.StringVar(&ingestKey, "ingest-key", os.Getenv("SENTINEL_INGEST_KEY"), "API key for ingest auth (env: SENTINEL_INGEST_KEY)")
	flag.BoolVar(&jsonOut, "json", false, "output raw JSON")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `AkesoSIEM Management CLI

Usage:
  akeso-cli [global flags] <command> [subcommand] [flags]

Global Flags:
  --server <url>        API server URL (default: %s, env: SENTINEL_URL)
  --api-key <key>       API key for auth (env: SENTINEL_API_KEY)
  --ingest-server <url> Ingest server URL (default: %s, env: SENTINEL_INGEST_URL)
  --ingest-key <key>    API key for ingest (env: SENTINEL_INGEST_KEY)
  --json                Output raw JSON instead of formatted tables

Commands:
  health                       Check API server health
  diagnose                     Full system diagnostics
  query    <query>             Execute an ad-hoc search query
  alerts                       List recent alerts
  rules                        List detection rules
  rules    validate            Validate rules on disk
  rules    update              Validate + hot-reload rules
  rules    update --init       Clone SigmaHQ + validate + reload
  rules    reload              Trigger hot-reload on ingest server
  sources                      List configured log sources
  ingest   test                Send a test event to ingest
  ingest   replay <file>       Replay an NDJSON file to ingest
  users    list                List all users
  users    create              Create a new user
  users    disable <username>  Disable a user account
  users    enable  <username>  Enable a disabled user account
  users    reset-mfa <user>    Reset MFA for a user
  keys     list                List API keys
  keys     create              Create a new API key
  keys     revoke  <id>        Revoke an API key

Examples:
  akeso-cli health
  akeso-cli diagnose
  akeso-cli --json users list
  akeso-cli users create --username jsmith --display-name "John Smith" --role analyst
  akeso-cli users disable jsmith
  akeso-cli users reset-mfa jsmith
  akeso-cli keys create --name "ingest-prod" --scopes "ingest"
  akeso-cli query "source_type:akeso_edr AND event.action:process_create"
  akeso-cli alerts --level critical
  akeso-cli rules validate
  akeso-cli rules update --init
  akeso-cli ingest test --source-type akeso_edr
  akeso-cli ingest replay tests/fixtures/akeso_edr/process_events.ndjson
`, defaultURL, defaultIngestURL)
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

	case "diagnose":
		commands.RunDiagnose(c, commands.DiagnoseOpts{
			IngestURL: ingestURL,
		}, jsonOut)

	case "query":
		runQueryCmd(c, subArgs, jsonOut)

	case "alerts":
		runAlertsCmd(c, subArgs, jsonOut)

	case "rules":
		runRulesCmd(c, subArgs, jsonOut, ingestURL)

	case "sources":
		commands.RunSources(c, jsonOut)

	case "ingest":
		runIngestCmd(subArgs, jsonOut, ingestURL, ingestKey)

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
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli query <query> [--index <pattern>] [--size <n>]\n")
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

func runRulesCmd(c *client.Client, args []string, jsonOut bool, ingestURL string) {
	// If no subcommand or first arg looks like a flag, list rules.
	if len(args) == 0 || (len(args) > 0 && args[0][0] == '-') {
		fs := flag.NewFlagSet("rules", flag.ExitOnError)
		size := fs.Int("size", 100, "number of rules to show")
		fs.Parse(args)

		commands.RunRules(c, commands.RulesOpts{
			Size: *size,
		}, jsonOut)
		return
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "validate":
		fs := flag.NewFlagSet("rules validate", flag.ExitOnError)
		rulesDir := fs.String("rules-dir", "rules", "path to rules directory")
		fs.Parse(subArgs)

		commands.RunRulesValidate(*rulesDir, jsonOut)

	case "update":
		fs := flag.NewFlagSet("rules update", flag.ExitOnError)
		rulesDir := fs.String("rules-dir", "rules", "path to rules directory")
		init := fs.Bool("init", false, "clone SigmaHQ rules first")
		initRepo := fs.String("repo", "", "custom git repo URL for --init")
		fs.Parse(subArgs)

		commands.RunRulesUpdate(c, ingestURL, commands.RulesUpdateOpts{
			RulesDir: *rulesDir,
			Init:     *init,
			InitRepo: *initRepo,
		}, jsonOut)

	case "reload":
		commands.RunRulesReload(c, ingestURL, jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown rules subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli rules [validate|update|reload] [flags]\n")
		os.Exit(1)
	}
}

func runIngestCmd(args []string, jsonOut bool, ingestURL, ingestKey string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli ingest <test|replay> [flags]\n")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "test":
		fs := flag.NewFlagSet("ingest test", flag.ExitOnError)
		sourceType := fs.String("source-type", "akeso_edr", "source_type for test event")
		fs.Parse(subArgs)

		commands.RunIngestTest(commands.IngestTestOpts{
			IngestURL:  ingestURL,
			IngestKey:  ingestKey,
			SourceType: *sourceType,
		}, jsonOut)

	case "replay":
		fs := flag.NewFlagSet("ingest replay", flag.ExitOnError)
		batchSize := fs.Int("batch-size", 500, "events per batch")
		fs.Parse(subArgs)

		file := fs.Arg(0)
		if file == "" {
			fmt.Fprintf(os.Stderr, "Usage: akeso-cli ingest replay <file.ndjson> [--batch-size <n>]\n")
			os.Exit(1)
		}

		commands.RunIngestReplay(commands.IngestReplayOpts{
			IngestURL: ingestURL,
			IngestKey: ingestKey,
			File:      file,
			BatchSize: *batchSize,
		}, jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown ingest subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli ingest <test|replay> [flags]\n")
		os.Exit(1)
	}
}

func runUsersCmd(c *client.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli users <list|create|disable|enable|reset-mfa> [flags]\n")
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
			fmt.Fprintf(os.Stderr, "Usage: akeso-cli users disable <username>\n")
			os.Exit(1)
		}
		commands.RunUsersDisable(c, subArgs[0], jsonOut)

	case "enable":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: akeso-cli users enable <username>\n")
			os.Exit(1)
		}
		commands.RunUsersEnable(c, subArgs[0], jsonOut)

	case "reset-mfa":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: akeso-cli users reset-mfa <username>\n")
			os.Exit(1)
		}
		commands.RunUsersResetMFA(c, subArgs[0], jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown users subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli users <list|create|disable|enable|reset-mfa> [flags]\n")
		os.Exit(1)
	}
}

func runKeysCmd(c *client.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli keys <list|create|revoke> [flags]\n")
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
			fmt.Fprintf(os.Stderr, "Usage: akeso-cli keys revoke <key-id>\n")
			os.Exit(1)
		}
		commands.RunKeysRevoke(c, subArgs[0], jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown keys subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "Usage: akeso-cli keys <list|create|revoke> [flags]\n")
		os.Exit(1)
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
