package common

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/derekxmartin/akeso-siem/internal/config"
	"gopkg.in/lumberjack.v2"
)

// SetupLogging configures the stdlib logger to write to both stdout and a
// rotating log file when file logging is enabled. Returns a cleanup function
// that should be deferred by the caller.
func SetupLogging(cfg config.LoggingConfig, binaryName string) (func(), error) {
	if !cfg.FileEnabled {
		return func() {}, nil
	}

	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating log directory %q: %w", cfg.LogDir, err)
	}

	lj := &lumberjack.Logger{
		Filename:   cfg.LogDir + "/" + binaryName + ".log",
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxFiles,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}

	mw := io.MultiWriter(os.Stdout, lj)
	log.SetOutput(mw)

	log.Printf("File logging enabled: %s (max %dMB, %d files, %d days retention)",
		lj.Filename, cfg.MaxSizeMB, cfg.MaxFiles, cfg.MaxAgeDays)

	return func() {
		_ = lj.Close()
	}, nil
}
