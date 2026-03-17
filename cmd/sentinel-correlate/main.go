package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/config"
)

func main() {
	configPath := flag.String("config", "sentinel.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logCleanup, err := common.SetupLogging(cfg.Logging, "sentinel-correlate")
	if err != nil {
		log.Fatalf("Failed to setup file logging: %v", err)
	}
	defer logCleanup()

	fmt.Println("sentinel-correlate: Sigma rule evaluation engine")
}
