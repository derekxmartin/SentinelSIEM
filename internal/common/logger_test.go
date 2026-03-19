package common

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/config"
)

func TestSetupLogging_Disabled(t *testing.T) {
	cfg := config.LoggingConfig{FileEnabled: false}
	cleanup, err := SetupLogging(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cleanup()
}

func TestSetupLogging_Enabled(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := config.LoggingConfig{
		FileEnabled: true,
		LogDir:      tmpDir,
		MaxSizeMB:   1,
		MaxFiles:    2,
		MaxAgeDays:  1,
		Compress:    false,
	}

	// Save and restore original log output.
	origOutput := log.Writer()
	defer log.SetOutput(origOutput)

	cleanup, err := SetupLogging(cfg, "test-binary")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	log.Println("hello from test")

	logFile := filepath.Join(tmpDir, "test-binary.log")
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(data), "hello from test") {
		t.Errorf("log file does not contain expected message, got: %s", string(data))
	}
}
