package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all resolved agent configuration
type Config struct {
	ServerURL               string
	TargetURL               string
	TokenFile               string
	Token                   string
	ConnectionCheckInterval time.Duration
	ShutdownTimeout         time.Duration
	MaxConcurrentRequests   int
	RequestBufferSize       int
	LogLevel                string
	LogFormat               string
}

// flag values (populated by flag.Parse)
var (
	flagServerURL               string
	flagTargetURL               string
	flagTokenFile               string
	flagToken                   string
	flagConnectionCheckInterval string
	flagShutdownTimeout         string
	flagMaxConcurrentRequests   string
	flagRequestBufferSize       string
	flagLogLevel                string
	flagLogFormat               string
)

func init() {
	flag.StringVar(&flagServerURL, "server-url", "",
		"WebSocket URL for gimlet server (env: GIMLET_AGENT_SERVER_URL)")
	flag.StringVar(&flagTargetURL, "target-url", "",
		"HTTP URL for target backend service (env: GIMLET_AGENT_TARGET_URL)")
	flag.StringVar(&flagTokenFile, "token-file", "",
		"Path to token file for authentication (env: GIMLET_AGENT_TOKEN_FILE)")
	flag.StringVar(&flagToken, "token", "",
		"Token for authentication (env: GIMLET_AGENT_TOKEN)")
	flag.StringVar(&flagConnectionCheckInterval, "connection-check-interval", "",
		"Interval to probe for new servers (env: GIMLET_AGENT_CONNECTION_CHECK_INTERVAL)")
	flag.StringVar(&flagShutdownTimeout, "shutdown-timeout", "",
		"Graceful shutdown timeout for draining requests (env: GIMLET_AGENT_SHUTDOWN_TIMEOUT)")
	flag.StringVar(&flagMaxConcurrentRequests, "max-concurrent-requests", "",
		"Max concurrent requests per agent (env: GIMLET_AGENT_MAX_CONCURRENT_REQUESTS)")
	flag.StringVar(&flagRequestBufferSize, "request-buffer-size", "",
		"Request channel buffer size (env: GIMLET_AGENT_REQUEST_BUFFER_SIZE)")
	flag.StringVar(&flagLogLevel, "log-level", "",
		"Log level: DEBUG, INFO, WARN, ERROR (env: GIMLET_AGENT_LOG_LEVEL, GIMLET_LOG_LEVEL)")
	flag.StringVar(&flagLogFormat, "log-format", "",
		"Log format: json, console (env: GIMLET_AGENT_LOG_FORMAT, GIMLET_LOG_FORMAT)")
}

// Load parses flags, reads env vars, applies defaults, and returns Config
func Load() *Config {
	flag.Parse()

	cfg := &Config{
		ServerURL: resolveString(flagServerURL,
			[]string{"GIMLET_AGENT_SERVER_URL"}, "ws://server:8080/agent"),
		TargetURL: resolveString(flagTargetURL,
			[]string{"GIMLET_AGENT_TARGET_URL"}, "http://backend:8000"),
		TokenFile: resolveString(flagTokenFile,
			[]string{"GIMLET_AGENT_TOKEN_FILE"}, ""),
		Token: resolveString(flagToken,
			[]string{"GIMLET_AGENT_TOKEN"}, ""),
		ConnectionCheckInterval: resolveDuration(flagConnectionCheckInterval,
			[]string{"GIMLET_AGENT_CONNECTION_CHECK_INTERVAL"}, 5*time.Second),
		ShutdownTimeout: resolveDuration(flagShutdownTimeout,
			[]string{"GIMLET_AGENT_SHUTDOWN_TIMEOUT"}, 30*time.Second),
		MaxConcurrentRequests: resolveInt(flagMaxConcurrentRequests,
			[]string{"GIMLET_AGENT_MAX_CONCURRENT_REQUESTS"}, 50),
		RequestBufferSize: resolveInt(flagRequestBufferSize,
			[]string{"GIMLET_AGENT_REQUEST_BUFFER_SIZE"}, 100),
		LogLevel: resolveString(flagLogLevel,
			[]string{"GIMLET_AGENT_LOG_LEVEL", "GIMLET_LOG_LEVEL"}, "INFO"),
		LogFormat: resolveString(flagLogFormat,
			[]string{"GIMLET_AGENT_LOG_FORMAT", "GIMLET_LOG_FORMAT"}, "json"),
	}

	return cfg
}

// resolveString returns the first non-empty value from: flag, env vars, default
func resolveString(flagVal string, envVars []string, defaultVal string) string {
	if flagVal != "" {
		return flagVal
	}
	for _, env := range envVars {
		if val := os.Getenv(env); val != "" {
			return val
		}
	}
	return defaultVal
}

// resolveDuration returns duration from: flag, env vars, default
// Supports both duration strings ("10s", "1m") and plain seconds ("60")
func resolveDuration(flagVal string, envVars []string, defaultVal time.Duration) time.Duration {
	val := resolveString(flagVal, envVars, "")
	if val == "" {
		return defaultVal
	}
	return parseDuration(val, defaultVal)
}

// resolveInt returns int from: flag, env vars, default
func resolveInt(flagVal string, envVars []string, defaultVal int) int {
	val := resolveString(flagVal, envVars, "")
	if val == "" {
		return defaultVal
	}
	parsed, err := strconv.Atoi(val)
	if err != nil || parsed < 0 {
		return defaultVal
	}
	return parsed
}

// parseDuration parses a duration string, supporting both "10s" format and plain seconds
func parseDuration(val string, defaultVal time.Duration) time.Duration {
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

// LoadToken loads the token from file or inline value
func (c *Config) LoadToken() (string, error) {
	// Try file first
	if c.TokenFile != "" {
		data, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Fall back to inline value
	if c.Token != "" {
		return strings.TrimSpace(c.Token), nil
	}

	return "", nil
}

// Validate checks that required config values are set
func (c *Config) Validate() error {
	// Token is validated separately via LoadToken
	return nil
}

// ParseTargetAddr extracts host:port from target URL for TCP connections
func (c *Config) ParseTargetAddr() string {
	addr := c.TargetURL

	// Remove protocol prefix if present
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")

	// Remove trailing slash and path
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}

	// Add default port if not specified
	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}

	return addr
}

// ParseLogLevel converts log level string to a normalized form
func ParseLogLevel(level string) string {
	return strings.ToUpper(level)
}
