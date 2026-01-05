package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Config holds all resolved server configuration
type Config struct {
	HTTPPort              string
	MetricsPort           string // If set, serve /metrics on separate port
	HealthPort            string // If set, serve /health on separate port
	ServerID              string
	TokenPublicKeyFile    string
	TokenPublicKeyDir     string
	TokenPublicKey        string
	TokenIssuer           string
	IdleTimeout           time.Duration
	ShutdownTimeout       time.Duration
	ResponseBufferSize    int
	MaxConcurrentRequests int64
	LogLevel              string
	LogFormat             string
}

// flag values (populated by flag.Parse)
var (
	flagHTTPPort              string
	flagMetricsPort           string
	flagHealthPort            string
	flagServerID              string
	flagTokenPublicKeyFile    string
	flagTokenPublicKeyDir     string
	flagTokenPublicKey        string
	flagTokenIssuer           string
	flagIdleTimeout           string
	flagShutdownTimeout       string
	flagResponseBufferSize    string
	flagMaxConcurrentRequests string
	flagLogLevel              string
	flagLogFormat             string
)

func init() {
	flag.StringVar(&flagHTTPPort, "http-port", "",
		"Port for HTTP server (env: GIMLET_SERVER_HTTP_PORT)")
	flag.StringVar(&flagMetricsPort, "metrics-port", "",
		"Port for /metrics endpoint (env: GIMLET_SERVER_METRICS_PORT)")
	flag.StringVar(&flagHealthPort, "health-port", "",
		"Port for /health endpoint; if empty, served on main port (env: GIMLET_SERVER_HEALTH_PORT)")
	flag.StringVar(&flagServerID, "server-id", "",
		"Server ID (env: GIMLET_SERVER_SERVER_ID)")
	flag.StringVar(&flagTokenPublicKeyFile, "token-public-key-file", "",
		"Path to token public key file (env: GIMLET_SERVER_TOKEN_PUBLIC_KEY_FILE)")
	flag.StringVar(&flagTokenPublicKeyDir, "token-public-key-dir", "",
		"Directory containing token public key files for rotation (env: GIMLET_SERVER_TOKEN_PUBLIC_KEY_DIR)")
	flag.StringVar(&flagTokenPublicKey, "token-public-key", "",
		"Token public key PEM data (env: GIMLET_SERVER_TOKEN_PUBLIC_KEY)")
	flag.StringVar(&flagTokenIssuer, "token-issuer", "",
		"Expected token issuer (env: GIMLET_SERVER_TOKEN_ISSUER)")
	flag.StringVar(&flagIdleTimeout, "idle-timeout", "",
		"Idle timeout for connections (env: GIMLET_SERVER_IDLE_TIMEOUT)")
	flag.StringVar(&flagShutdownTimeout, "shutdown-timeout", "",
		"Graceful shutdown timeout for draining requests (env: GIMLET_SERVER_SHUTDOWN_TIMEOUT)")
	flag.StringVar(&flagResponseBufferSize, "response-buffer-size", "",
		"Response channel buffer size (env: GIMLET_SERVER_RESPONSE_BUFFER_SIZE)")
	flag.StringVar(&flagMaxConcurrentRequests, "max-concurrent-requests", "",
		"Max concurrent requests per server (env: GIMLET_SERVER_MAX_CONCURRENT_REQUESTS)")
	flag.StringVar(&flagLogLevel, "log-level", "",
		"Log level: DEBUG, INFO, WARN, ERROR (env: GIMLET_SERVER_LOG_LEVEL, GIMLET_LOG_LEVEL)")
	flag.StringVar(&flagLogFormat, "log-format", "",
		"Log format: json, console (env: GIMLET_SERVER_LOG_FORMAT, GIMLET_LOG_FORMAT)")
}

// Load parses flags, reads env vars, applies defaults, and returns Config
func Load() *Config {
	flag.Parse()

	cfg := &Config{
		HTTPPort: resolveString(flagHTTPPort,
			[]string{"GIMLET_SERVER_HTTP_PORT"}, "8080"),
		MetricsPort: resolveString(flagMetricsPort,
			[]string{"GIMLET_SERVER_METRICS_PORT"}, "9090"),
		HealthPort: resolveString(flagHealthPort,
			[]string{"GIMLET_SERVER_HEALTH_PORT"}, ""),
		ServerID: resolveString(flagServerID,
			[]string{"GIMLET_SERVER_SERVER_ID"}, uuid.New().String()[:8]),
		TokenPublicKeyFile: resolveString(flagTokenPublicKeyFile,
			[]string{"GIMLET_SERVER_TOKEN_PUBLIC_KEY_FILE"}, ""),
		TokenPublicKeyDir: resolveString(flagTokenPublicKeyDir,
			[]string{"GIMLET_SERVER_TOKEN_PUBLIC_KEY_DIR"}, ""),
		TokenPublicKey: resolveString(flagTokenPublicKey,
			[]string{"GIMLET_SERVER_TOKEN_PUBLIC_KEY"}, ""),
		TokenIssuer: resolveString(flagTokenIssuer,
			[]string{"GIMLET_SERVER_TOKEN_ISSUER"}, "gimlet"),
		IdleTimeout: resolveDuration(flagIdleTimeout,
			[]string{"GIMLET_SERVER_IDLE_TIMEOUT"}, 10*time.Minute),
		ShutdownTimeout: resolveDuration(flagShutdownTimeout,
			[]string{"GIMLET_SERVER_SHUTDOWN_TIMEOUT"}, 30*time.Second),
		ResponseBufferSize: resolveInt(flagResponseBufferSize,
			[]string{"GIMLET_SERVER_RESPONSE_BUFFER_SIZE"}, 100),
		MaxConcurrentRequests: resolveInt64(flagMaxConcurrentRequests,
			[]string{"GIMLET_SERVER_MAX_CONCURRENT_REQUESTS"}, 1000),
		LogLevel: resolveString(flagLogLevel,
			[]string{"GIMLET_SERVER_LOG_LEVEL", "GIMLET_LOG_LEVEL"}, "INFO"),
		LogFormat: resolveString(flagLogFormat,
			[]string{"GIMLET_SERVER_LOG_FORMAT", "GIMLET_LOG_FORMAT"}, "json"),
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
	if err != nil {
		return defaultVal
	}
	return parsed
}

// resolveInt64 returns int64 from: flag, env vars, default
func resolveInt64(flagVal string, envVars []string, defaultVal int64) int64 {
	val := resolveString(flagVal, envVars, "")
	if val == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
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

// LoadRSAPublicKey loads an RSA public key from PEM-encoded data
func LoadRSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaKey, nil
}

// Validate checks that required config values are set and returns an error if not
func (c *Config) Validate() error {
	if c.TokenPublicKeyFile == "" && c.TokenPublicKey == "" && c.TokenPublicKeyDir == "" {
		return fmt.Errorf("one of --token-public-key-file, --token-public-key, or --token-public-key-dir is required")
	}
	return nil
}

// LoadTokenPublicKeys loads the token public key(s) from file, directory, or inline value
// Returns multiple keys to support key rotation
func (c *Config) LoadTokenPublicKeys() ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey

	// Load from directory (supports multiple keys for rotation)
	if c.TokenPublicKeyDir != "" {
		entries, err := os.ReadDir(c.TokenPublicKeyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read token public key directory %s: %w", c.TokenPublicKeyDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Only process .pem and .pub files
			name := entry.Name()
			if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".pub") {
				continue
			}
			path := filepath.Join(c.TokenPublicKeyDir, name)
			pemData, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
			}
			key, err := LoadRSAPublicKey(pemData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key file %s: %w", path, err)
			}
			keys = append(keys, key)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("no valid public key files found in %s", c.TokenPublicKeyDir)
		}
		return keys, nil
	}

	// Load from single file
	if c.TokenPublicKeyFile != "" {
		pemData, err := os.ReadFile(c.TokenPublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read token public key file %s: %w", c.TokenPublicKeyFile, err)
		}
		key, err := LoadRSAPublicKey(pemData)
		if err != nil {
			return nil, err
		}
		return []*rsa.PublicKey{key}, nil
	}

	// Load from inline value
	if c.TokenPublicKey != "" {
		key, err := LoadRSAPublicKey([]byte(c.TokenPublicKey))
		if err != nil {
			return nil, err
		}
		return []*rsa.PublicKey{key}, nil
	}

	return nil, fmt.Errorf("no token public key configured")
}

// LogFields returns key-value pairs for structured logging of config
func (c *Config) LogFields() map[string]interface{} {
	return map[string]interface{}{
		"httpPort":              c.HTTPPort,
		"serverID":              c.ServerID,
		"tokenIssuer":           c.TokenIssuer,
		"idleTimeout":           c.IdleTimeout.String(),
		"shutdownTimeout":       c.ShutdownTimeout.String(),
		"responseBufferSize":    c.ResponseBufferSize,
		"maxConcurrentRequests": c.MaxConcurrentRequests,
		"logLevel":              c.LogLevel,
		"logFormat":             c.LogFormat,
	}
}

// ParseLogLevel converts log level string to a normalized form
func ParseLogLevel(level string) string {
	return strings.ToUpper(level)
}
