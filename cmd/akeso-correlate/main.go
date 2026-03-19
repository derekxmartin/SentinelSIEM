package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/derekxmartin/akeso-siem/internal/common"
	"github.com/derekxmartin/akeso-siem/internal/config"
)

func main() {
	configPath := flag.String("config", "akeso.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logCleanup, err := common.SetupLogging(cfg.Logging, "akeso-correlate")
	if err != nil {
		log.Fatalf("Failed to setup file logging: %v", err)
	}
	defer logCleanup()

	fmt.Println("akeso-correlate: Sigma rule evaluation engine")
}
