package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gimlet/agent/config"
	"gimlet/agent/connection"
	"gimlet/agent/health"
	"gimlet/agent/messages"
	"gimlet/protocol"

	"github.com/rs/zerolog"
)


// ConnectionInfo tracks a connection to a server
type ConnectionInfo struct {
	serverID    string
	serviceName string
	agentID     string
	conn        connection.WebSocketConn // Mutex-protected wrapper for thread-safe writes
	handler     *connection.Handler
}

// AgentState holds shared state for connection management
type AgentState struct {
	connections      map[string]*ConnectionInfo // serverID -> connection
	mu               sync.RWMutex
	inflightRequests atomic.Int32   // Count of in-flight backend requests
	draining         atomic.Bool    // Whether agent is draining
	backendHealthy   atomic.Bool    // Whether backend health check is passing
	requestSemaphore chan struct{}  // Shared rate limit semaphore (global per agent)
	wsDialer         protocol.WebSocketDialer
	tcpDialer        connection.TCPDialer
	healthChecker    *health.Checker
	logger           zerolog.Logger
}

// IncrementRequests implements connection.RequestTracker
func (s *AgentState) IncrementRequests() {
	s.inflightRequests.Add(1)
}

// DecrementRequests implements connection.RequestTracker
func (s *AgentState) DecrementRequests() {
	s.inflightRequests.Add(-1)
}

func (s *AgentState) addConnection(serverID, serviceName, agentID string, conn connection.WebSocketConn, handler *connection.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[serverID] = &ConnectionInfo{
		serverID:    serverID,
		serviceName: serviceName,
		agentID:     agentID,
		conn:        conn,
		handler:     handler,
	}
	s.logger.Info().Str("serverID", serverID).Int("totalConnections", len(s.connections)).Msg("Added connection to server")
}

func (s *AgentState) removeConnection(serverID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn, exists := s.connections[serverID]; exists {
		conn.conn.Close()
		delete(s.connections, serverID)
		s.logger.Info().Str("serverID", serverID).Int("remainingConnections", len(s.connections)).Msg("Removed connection to server")
	}
}

func main() {
	// Load configuration (parses flags and env vars)
	cfg := config.Load()

	// Initialize logger with config
	baseLogger := protocol.InitLogger(cfg.LogLevel, cfg.LogFormat)

	// Load token (required)
	token, err := cfg.LoadToken()
	if err != nil {
		baseLogger.Fatal().Err(err).Msg("Failed to load token")
	}
	if token == "" {
		fmt.Fprintf(os.Stderr, "Configuration error: either --token-file or --token is required (env: GIMLET_AGENT_TOKEN_FILE or GIMLET_AGENT_TOKEN)\n")
		os.Exit(1)
	}

	baseLogger.Info().Str("serverURL", cfg.ServerURL).Str("targetURL", cfg.TargetURL).Msg("Agent starting")
	baseLogger.Info().Dur("interval", cfg.ConnectionCheckInterval).Msg("Connection probe interval configured")
	baseLogger.Info().Int("maxConcurrentRequests", cfg.MaxConcurrentRequests).Msg("Max concurrent requests per agent configured (0 = unlimited)")
	baseLogger.Info().Int("bufferSize", cfg.RequestBufferSize).Msg("Request channel buffer size configured")
	baseLogger.Info().
		Str("url", cfg.HealthCheckURL()).
		Dur("interval", cfg.HealthCheckInterval).
		Dur("timeout", cfg.HealthCheckTimeout).
		Str("codes", cfg.HealthCheckCodes).
		Int("failureThreshold", cfg.HealthCheckFailureThreshold).
		Int("successThreshold", cfg.HealthCheckSuccessThreshold).
		Msg("Health check configured")

	// Parse target URL to extract host:port for TCP connections
	targetAddr := cfg.ParseTargetAddr()
	baseLogger.Info().Str("targetAddr", targetAddr).Msg("Target backend TCP address")

	// Parse health check status codes
	statusMatcher, err := health.ParseStatusCodes(cfg.HealthCheckCodes)
	if err != nil {
		baseLogger.Fatal().Err(err).Str("codes", cfg.HealthCheckCodes).Msg("Invalid health check status codes")
	}

	// Initialize shared state with default dialers
	state := &AgentState{
		connections: make(map[string]*ConnectionInfo),
		wsDialer:    &protocol.DefaultWebSocketDialer{},
		tcpDialer:   &protocol.DefaultTCPDialer{},
		logger:      baseLogger,
	}

	// Initialize shared semaphore for rate limiting (global per agent)
	if cfg.MaxConcurrentRequests > 0 {
		state.requestSemaphore = make(chan struct{}, cfg.MaxConcurrentRequests)
		baseLogger.Info().Msg("Shared rate limit semaphore initialized (global per agent)")
	}

	// Initialize and start health checker
	state.healthChecker = health.NewChecker(health.Config{
		URL:              cfg.HealthCheckURL(),
		Interval:         cfg.HealthCheckInterval,
		Timeout:          cfg.HealthCheckTimeout,
		FailureThreshold: cfg.HealthCheckFailureThreshold,
		SuccessThreshold: cfg.HealthCheckSuccessThreshold,
		StatusMatcher:    statusMatcher,
	}, baseLogger)
	state.healthChecker.Start()

	// Watch for health state changes and broadcast to all connected servers
	go watchHealthState(state)

	// Start connection monitor
	go monitorConnections(state, cfg.ServerURL, token, targetAddr, cfg.ConnectionCheckInterval, cfg.MaxConcurrentRequests, cfg.RequestBufferSize)

	// Start stats logger
	go logStatsLoop(state, 5*time.Second)

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigChan
	state.logger.Info().Str("signal", sig.String()).Msg("Received signal, initiating graceful shutdown")

	// Mark as draining and stop health checker
	state.draining.Store(true)
	state.healthChecker.Stop()

	// Send draining message to all connected servers
	state.mu.RLock()
	for _, connInfo := range state.connections {
		sendDraining(connInfo.conn, connInfo.serverID, state.logger)
	}
	state.mu.RUnlock()

	// Wait for in-flight requests to complete (with configurable timeout)
	state.logger.Info().Int32("inflightRequests", state.inflightRequests.Load()).Msg("Waiting for in-flight requests to complete")
	deadline := time.Now().Add(cfg.ShutdownTimeout)
	for state.inflightRequests.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}

	remaining := state.inflightRequests.Load()
	if remaining > 0 {
		state.logger.Warn().Int32("remaining", remaining).Msg("Timeout reached, requests still in-flight")
	} else {
		state.logger.Info().Msg("All requests completed")
	}

	// Close all connections
	state.mu.Lock()
	for _, connInfo := range state.connections {
		connInfo.conn.Close()
	}
	state.mu.Unlock()

	state.logger.Info().Msg("Graceful shutdown complete")
}

func sendReady(conn connection.WebSocketConn, serverID string, logger zerolog.Logger) {
	readyMsg := messages.StateChangeMessage{
		Type:  "ready",
		State: "ready",
	}
	if err := conn.WriteJSON(readyMsg); err != nil {
		logger.Error().Err(err).Str("serverID", serverID).Msg("Failed to send ready message to server")
	} else {
		logger.Debug().Str("serverID", serverID).Msg("Sent ready message to server")
	}
}

func sendNotReady(conn connection.WebSocketConn, serverID string, logger zerolog.Logger) {
	notReadyMsg := messages.StateChangeMessage{
		Type:  "not_ready",
		State: "not_ready",
	}
	if err := conn.WriteJSON(notReadyMsg); err != nil {
		logger.Error().Err(err).Str("serverID", serverID).Msg("Failed to send not_ready message to server")
	} else {
		logger.Debug().Str("serverID", serverID).Msg("Sent not_ready message to server")
	}
}

func sendDraining(conn connection.WebSocketConn, serverID string, logger zerolog.Logger) {
	drainingMsg := messages.StateChangeMessage{
		Type:  "draining",
		State: "draining",
	}
	if err := conn.WriteJSON(drainingMsg); err != nil {
		logger.Error().Err(err).Str("serverID", serverID).Msg("Failed to send draining message to server")
	} else {
		logger.Debug().Str("serverID", serverID).Msg("Sent draining message to server")
	}
}

// logStatsLoop periodically logs agent statistics
func logStatsLoop(state *AgentState, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if state.draining.Load() {
			return
		}

		state.mu.RLock()
		serverCount := len(state.connections)
		state.mu.RUnlock()

		activeRequests := state.inflightRequests.Load()
		healthState := "unknown"
		if state.healthChecker != nil {
			healthState = string(state.healthChecker.CurrentState())
		}

		logEvent := state.logger.Info().
			Int("servers", serverCount).
			Int32("activeRequests", activeRequests).
			Str("backendHealth", healthState)

		// Include semaphore usage if rate limiting is enabled
		if state.requestSemaphore != nil {
			logEvent = logEvent.Str("semaphore", fmt.Sprintf("%d/%d", len(state.requestSemaphore), cap(state.requestSemaphore)))
		}

		logEvent.Msg("Agent stats")
	}
}

// watchHealthState monitors health checker state changes and broadcasts to all servers
func watchHealthState(state *AgentState) {
	for newState := range state.healthChecker.StateChanges() {
		if state.draining.Load() {
			return
		}

		// Update local health state
		isHealthy := newState == health.StateHealthy
		state.backendHealthy.Store(isHealthy)

		// Broadcast to all connected servers
		state.mu.RLock()
		for _, connInfo := range state.connections {
			if isHealthy {
				sendReady(connInfo.conn, connInfo.serverID, state.logger)
			} else {
				sendNotReady(connInfo.conn, connInfo.serverID, state.logger)
			}
		}
		state.mu.RUnlock()
	}
}

func monitorConnections(state *AgentState, serverURL, token string, targetAddr string, checkInterval time.Duration, maxConcurrentRequests int, requestChannelBufferSize int) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// Bootstrap: try to connect immediately
	tryConnect(state, serverURL, token, targetAddr, maxConcurrentRequests, requestChannelBufferSize)

	for range ticker.C {
		// Stop probing when draining
		if state.draining.Load() {
			return
		}
		// Probe for new servers every interval
		// Server will reject if we're already connected (duplicate detection)
		tryConnect(state, serverURL, token, targetAddr, maxConcurrentRequests, requestChannelBufferSize)
	}
}

func tryConnect(state *AgentState, serverURL, token string, targetAddr string, maxConcurrentRequests int, requestChannelBufferSize int) {
	ws, err := connectWithToken(state.wsDialer, serverURL, token)
	if err != nil {
		state.logger.Error().Err(err).Msg("Connection attempt failed")
		return
	}

	// Read initial message (could be hello or error)
	var msg map[string]interface{}
	if err := ws.ReadJSON(&msg); err != nil {
		state.logger.Error().Err(err).Msg("Failed to read initial message from server")
		ws.Close()
		return
	}

	// Check if it's an error response
	if errorMsg, hasError := msg["error"].(string); hasError {
		agentID := msg["agent_id"]
		serverID := msg["server_id"]
		hint := msg["hint"]

		// Already connected is expected during probing - log at debug level
		if strings.Contains(errorMsg, "Cannot create multiple connections") {
			state.logger.Debug().
				Interface("serverID", serverID).
				Msg("Already connected to server")
		} else {
			state.logger.Warn().
				Str("error", errorMsg).
				Interface("agentID", agentID).
				Interface("serverID", serverID).
				Interface("hint", hint).
				Msg("Server rejected connection")
		}
		ws.Close()
		return
	}

	// Parse as hello message
	var hello messages.HelloMessage
	helloBytes, _ := json.Marshal(msg)
	if err := json.Unmarshal(helloBytes, &hello); err != nil {
		state.logger.Error().Err(err).Msg("Failed to parse hello message")
		ws.Close()
		return
	}

	// Check if already connected to this server
	state.mu.RLock()
	_, exists := state.connections[hello.ServerID]
	state.mu.RUnlock()

	if exists {
		state.logger.Debug().Str("serverID", hello.ServerID).Msg("Already connected to server, closing duplicate")
		ws.Close()
		return
	}

	// Create enhanced logger with agentID and serviceName from hello message
	connLogger := state.logger.With().
		Str("agentID", hello.AgentID).
		Str("service", hello.ServiceName).
		Str("serverID", hello.ServerID).
		Logger()

	// Set up pong handler for keepalive (only if underlying conn supports it)
	if gorillaWS, ok := ws.(*protocol.GorillaWebSocketConn); ok {
		gorillaWS.Conn.SetPongHandler(func(string) error {
			connLogger.Debug().Msg("Received pong from server")
			return nil
		})
	}

	// Wrap the connection with mutex protection for concurrent writes
	wrappedConn := &RealWebSocketConn{WebSocketConn: ws}

	// Start handler for this connection
	handler := connection.NewHandler(
		wrappedConn,
		targetAddr,
		state.tcpDialer,
		state, // Pass state as RequestTracker for inflight request tracking
		connLogger,
		maxConcurrentRequests,
		state.requestSemaphore, // Shared semaphore (global per agent)
		requestChannelBufferSize,
	)

	// Add connection to state (use wrapped conn for thread-safe writes during shutdown)
	state.addConnection(hello.ServerID, hello.ServiceName, hello.AgentID, wrappedConn, handler)

	// Send current health state BEFORE starting concurrent goroutines
	// Uses the mutex-protected wrapper
	if state.backendHealthy.Load() {
		sendReady(wrappedConn, hello.ServerID, connLogger)
	} else {
		sendNotReady(wrappedConn, hello.ServerID, connLogger)
	}

	connLogger.Info().Bool("backendHealthy", state.backendHealthy.Load()).Msg("Connected to server")

	// Start handler in goroutine
	go func() {
		handler.Run()
		// When handler exits (connection lost), remove from state
		state.removeConnection(hello.ServerID)
	}()

	// Start metrics reporter (sends updates every 10 seconds)
	go handler.StartMetricsReporter(10*time.Second, &state.draining)
}

func connectWithToken(dialer protocol.WebSocketDialer, url, token string) (protocol.WebSocketConn, error) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+token)

	ws, resp, err := dialer.Dial(url, headers)
	if err != nil {
		// Include the HTTP response details in the error for better debugging
		if resp != nil {
			defer resp.Body.Close()
			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil && len(body) > 0 {
				return nil, fmt.Errorf("%w: %s %s", err, resp.Status, strings.TrimSpace(string(body)))
			}
			return nil, fmt.Errorf("%w: %s", err, resp.Status)
		}
		return nil, err
	}

	return ws, nil
}

// RealWebSocketConn wraps a protocol.WebSocketConn with mutex protection for concurrent writes
// (gorilla/websocket is not thread-safe for writes)
type RealWebSocketConn struct {
	protocol.WebSocketConn
	writeMu sync.Mutex
}

func (c *RealWebSocketConn) ReadJSON(v interface{}) error {
	return c.WebSocketConn.ReadJSON(v)
}

func (c *RealWebSocketConn) WriteJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.WebSocketConn.WriteJSON(v)
}

func (c *RealWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	return c.WebSocketConn.ReadMessage()
}

func (c *RealWebSocketConn) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.WebSocketConn.WriteMessage(messageType, data)
}

func (c *RealWebSocketConn) Close() error {
	return c.WebSocketConn.Close()
}

func (c *RealWebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.WebSocketConn.SetWriteDeadline(t)
}
