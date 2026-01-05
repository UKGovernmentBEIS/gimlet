package protocol

import (
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ParseLogLevel converts a log level string to zerolog.Level.
func ParseLogLevel(level string) zerolog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return zerolog.DebugLevel
	case "INFO":
		return zerolog.InfoLevel
	case "WARN", "WARNING":
		return zerolog.WarnLevel
	case "ERROR":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// InitLogger creates a zerolog logger with the specified level and format.
func InitLogger(logLevel, logFormat string) zerolog.Logger {
	level := ParseLogLevel(logLevel)
	zerolog.SetGlobalLevel(level)

	var output io.Writer = os.Stdout
	if logFormat == "console" {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	}

	return zerolog.New(output).With().Timestamp().Logger()
}

// ParseDuration parses a duration string, supporting both "10s" format and plain seconds.
func ParseDuration(val string, defaultVal time.Duration) time.Duration {
	if val == "" {
		return defaultVal
	}

	// Try parsing as seconds first (e.g., "10" = 10 seconds)
	if seconds, err := strconv.Atoi(val); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// Try parsing as duration string (e.g., "10s", "1m30s")
	if duration, err := time.ParseDuration(val); err == nil {
		return duration
	}

	return defaultVal
}
