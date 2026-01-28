package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gimlet/protocol"
	"gimlet/server/agentmgr"
	"gimlet/server/auth"
	"gimlet/server/config"
	"gimlet/server/handlers"
	"gimlet/server/interfaces"
	"gimlet/server/metrics"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)


type Server struct {
	serverID        string
	agents          map[string]*agentmgr.Agent
	agentsLock      sync.RWMutex
	agentExpiry     map[string]time.Time // agentID -> JWT expiration time
	agentExpiryLock sync.RWMutex
	idleTimeout     time.Duration
	jwtValidator    *auth.JWTValidator
	metrics         *metrics.Metrics
	startTime       time.Time
	httpHandler     *handlers.HTTPHandler
	logger          zerolog.Logger
	activeRequests  sync.WaitGroup // Tracks in-flight /services/* requests for graceful shutdown
}

// Implement handlers.AgentProvider interface
func (cs *Server) LocalAgents() map[string]*agentmgr.Agent {
	cs.agentsLock.RLock()
	defer cs.agentsLock.RUnlock()

	// Return a copy to avoid lock issues
	agents := make(map[string]*agentmgr.Agent, len(cs.agents))
	for id, ag := range cs.agents {
		agents[id] = ag
	}
	return agents
}

// Implement metrics.ServerInfo interface
func (cs *Server) AgentCounts() map[string]int {
	cs.agentsLock.RLock()
	defer cs.agentsLock.RUnlock()

	serviceCounts := make(map[string]int)
	for _, ag := range cs.agents {
		serviceCounts[ag.ServiceName]++
	}
	return serviceCounts
}

func (cs *Server) ActiveRequestCount() int {
	cs.agentsLock.RLock()
	defer cs.agentsLock.RUnlock()

	total := 0
	for _, ag := range cs.agents {
		total += ag.Load()
	}
	return total
}

func (cs *Server) ServerID() string {
	return cs.serverID
}

func (cs *Server) StartTime() time.Time {
	return cs.startTime
}

func (cs *Server) AgentBufferStats() []metrics.AgentBufferStat {
	cs.agentsLock.RLock()
	defer cs.agentsLock.RUnlock()

	stats := make([]metrics.AgentBufferStat, 0, len(cs.agents))
	for _, ag := range cs.agents {
		stats = append(stats, metrics.AgentBufferStat{
			Service:     ag.ServiceName,
			AgentID:     ag.ID,
			BufferUsage: ag.BufferUsage(),
		})
	}
	return stats
}

func (cs *Server) AgentMetrics() []metrics.AgentMetricsSnapshot {
	cs.agentsLock.RLock()
	defer cs.agentsLock.RUnlock()

	snapshots := make([]metrics.AgentMetricsSnapshot, 0, len(cs.agents))
	for _, ag := range cs.agents {
		ag.MetricsLock.RLock()
		snapshots = append(snapshots, metrics.AgentMetricsSnapshot{
			Service:                 ag.ServiceName,
			AgentID:                 ag.ID,
			RateLimitRejections:     ag.Metrics.RateLimitRejections,
			ConcurrentRequests:      ag.Metrics.ConcurrentRequests,
			RequestChannelBuffer:    ag.Metrics.RequestChannelBuffer,
			BackendFailures:         ag.Metrics.BackendFailures,
			WebsocketWriteErrors:    ag.Metrics.WebsocketWriteErrors,
			FramesSent:              ag.Metrics.FramesSent,
			FramesReceived:          ag.Metrics.FramesReceived,
			Draining:                ag.Metrics.Draining,
			ConnectionUptimeSeconds: ag.Metrics.ConnectionUptimeSeconds,
		})
		ag.MetricsLock.RUnlock()
	}
	return snapshots
}

// Implement handlers.MetricsTracker interface
func (cs *Server) IncrementActiveRequests(service string) {
	cs.metrics.ActiveRequests.WithLabelValues(service).Inc()
}

func (cs *Server) DecrementActiveRequests(service string) {
	cs.metrics.ActiveRequests.WithLabelValues(service).Dec()
}

func (cs *Server) ObserveRequestDuration(service string, duration float64) {
	cs.metrics.RequestDuration.WithLabelValues(service).Observe(duration)
}

func (cs *Server) IncrementRequestsTotal(service string, agentID string, clientID string, statusCode string) {
	cs.metrics.RequestsTotal.WithLabelValues(service, agentID, clientID, statusCode).Inc()
}

func (cs *Server) IncrementWebsocketMessage(direction string, messageType string) {
	cs.metrics.WebsocketMessages.WithLabelValues(direction, messageType).Inc()
}

func (cs *Server) ObserveResponseChannelBuffer(service string, agentID string, bufferUsage float64) {
	cs.metrics.ResponseChannelBuffer.WithLabelValues(service, agentID).Set(bufferUsage)
}

func (cs *Server) IncrementRateLimitRejection(service string, limitType string) {
	cs.metrics.RateLimitRejections.WithLabelValues(service, limitType).Inc()
}

// logStatsLoop periodically logs server statistics
func (cs *Server) logStatsLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		cs.agentsLock.RLock()
		agentCount := len(cs.agents)

		// Build per-service stats
		serviceStats := make(map[string]map[string]int)
		for _, ag := range cs.agents {
			if _, exists := serviceStats[ag.ServiceName]; !exists {
				serviceStats[ag.ServiceName] = map[string]int{"agents": 0, "requests": 0}
			}
			serviceStats[ag.ServiceName]["agents"]++
			serviceStats[ag.ServiceName]["requests"] += ag.Load()
		}

		activeRequests := 0
		for _, stats := range serviceStats {
			activeRequests += stats["requests"]
		}
		cs.agentsLock.RUnlock()

		cs.logger.Info().
			Int("agents", agentCount).
			Int("activeRequests", activeRequests).
			Interface("services", serviceStats).
			Msg("Server stats")
	}
}

func main() {
	// Load configuration (parses flags and env vars)
	cfg := config.Load()

	// Validate required config
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger with config
	baseLogger := protocol.InitLogger(cfg.LogLevel, cfg.LogFormat)
	logger := baseLogger.With().Str("serverID", cfg.ServerID).Logger()

	// Load token public keys (supports multiple for key rotation)
	publicKeys, err := cfg.LoadTokenPublicKeys()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load token public key(s)")
	}

	jwtValidator := auth.NewJWTValidator(publicKeys, cfg.TokenIssuer)
	logger.Info().Str("issuer", cfg.TokenIssuer).Int("keyCount", len(publicKeys)).Msg("Token authentication enabled")

	// Initialize metrics
	m := metrics.New(cfg.ServerID)

	cs := &Server{
		serverID:     cfg.ServerID,
		agents:       make(map[string]*agentmgr.Agent),
		agentExpiry:  make(map[string]time.Time),
		idleTimeout:  cfg.IdleTimeout,
		jwtValidator: jwtValidator,
		metrics:      m,
		startTime:    time.Now(),
		logger:       logger,
	}

	// Initialize HTTP handler
	cs.httpHandler = handlers.NewHTTPHandler(
		jwtValidator,
		cs, // AgentProvider
		cfg.ServerID,
		cfg.IdleTimeout,
		cfg.ResponseBufferSize,
		cfg.MaxConcurrentRequests,
		logger,
		cs, // MetricsTracker
	)
	logger.Info().Dur("timeout", cfg.IdleTimeout).Msg("Idle timeout configured")
	logger.Info().Int("bufferSize", cfg.ResponseBufferSize).Msg("Response channel buffer size configured")
	logger.Info().Int64("maxConcurrentRequests", cfg.MaxConcurrentRequests).Msg("Max concurrent requests per server configured (0 = unlimited)")

	go cs.checkExpiredJWTs()
	go metrics.UpdateLoop(m, cs, 500*time.Millisecond)
	go cs.logStatsLoop(5 * time.Second)

	// Setup HTTP server mux
	mux := http.NewServeMux()
	mux.Handle("/services/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track for graceful shutdown
		cs.activeRequests.Add(1)
		defer cs.activeRequests.Done()
		cs.httpHandler.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/agent", cs.handleAgentWebSocket)

	// Add health endpoint to main mux if no separate port configured
	if cfg.HealthPort == "" {
		mux.HandleFunc("/health", metrics.HealthHandler(cs))
	}

	// Add metrics endpoint to main mux if no separate port configured
	if cfg.MetricsPort == "" {
		mux.Handle("/metrics", metrics.MetricsHandler())
	}

	// Return 404 for unknown paths (don't leak API structure)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	httpServer := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: mux,
	}

	// Start separate health server if configured
	if cfg.HealthPort != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", metrics.HealthHandler(cs))
		go func() {
			logger.Info().Str("port", cfg.HealthPort).Msg("Health endpoint listening")
			if err := http.ListenAndServe(":"+cfg.HealthPort, healthMux); err != nil && err != http.ErrServerClosed {
				logger.Error().Err(err).Msg("Health server error")
			}
		}()
	}

	// Start separate metrics server if configured
	if cfg.MetricsPort != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.MetricsHandler())
		go func() {
			logger.Info().Str("port", cfg.MetricsPort).Msg("Metrics endpoint listening")
			if err := http.ListenAndServe(":"+cfg.MetricsPort, metricsMux); err != nil && err != http.ErrServerClosed {
				logger.Error().Err(err).Msg("Metrics server error")
			}
		}()
	}

	logger.Info().Str("port", cfg.HTTPPort).Msg("Server listening")

	// Start HTTP server in background
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigChan
	logger.Info().Str("signal", sig.String()).Msg("Received signal, initiating graceful shutdown")

	// Create shutdown context with configurable timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Stop accepting new connections (httpServer.Shutdown stops listener immediately)
	// Run shutdown in background - it waits for all handlers to return
	shutdownDone := make(chan struct{})
	go func() {
		// Use background context - Shutdown will wait indefinitely for handlers
		if err := httpServer.Shutdown(context.Background()); err != nil {
			logger.Error().Err(err).Msg("HTTP server shutdown error")
		}
		close(shutdownDone)
	}()

	// Wait for httpServer.Shutdown to complete (all handlers returned)
	// Use timeout only for logging progress, not for forcing shutdown
	logger.Info().Msg("Waiting for in-flight requests to complete...")
	select {
	case <-shutdownDone:
		logger.Info().Msg("All HTTP handlers completed")
	case <-shutdownCtx.Done():
		// Timeout reached, but handlers are still running
		// Close agent connections to unblock any handlers waiting on responses
		logger.Warn().Msg("Shutdown timeout - closing agent connections to unblock handlers")
		cs.agentsLock.Lock()
		for _, ag := range cs.agents {
			ag.Conn.Close()
		}
		cs.agentsLock.Unlock()

		// Now wait for handlers to actually finish
		<-shutdownDone
		logger.Info().Msg("All HTTP handlers completed after agent disconnect")
	}

	// Clean up any remaining agent connections
	cs.agentsLock.Lock()
	for _, ag := range cs.agents {
		ag.Conn.Close()
	}
	cs.agentsLock.Unlock()

	logger.Info().Msg("Graceful shutdown complete")
}

func (cs *Server) handleAgentWebSocket(w http.ResponseWriter, r *http.Request) {
	// Extract and validate JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		http.Error(w, "Invalid Authorization header format (use 'Bearer <token>')", http.StatusUnauthorized)
		return
	}

	agentID, serviceName, expiresAt, err := cs.jwtValidator.ValidateAgentJWT(token)
	if err != nil {
		cs.logger.Info().Err(err).Msg("Agent JWT validation failed")
		http.Error(w, auth.SanitizeJWTError(err), http.StatusUnauthorized)
		return
	}

	cs.logger.Debug().Str("agentID", agentID).Str("service", serviceName).Time("expires", expiresAt).Msg("Agent JWT validated")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		cs.logger.Info().Err(err).Msg("WebSocket upgrade failed")
		return
	}

	wsConn := &interfaces.RealWebSocketConn{Conn: conn}
	ag := agentmgr.NewAgent(agentID, serviceName, wsConn)

	// Check for existing agent with same ID - reject duplicate
	cs.agentsLock.Lock()
	if _, exists := cs.agents[ag.ID]; exists {
		cs.agentsLock.Unlock()
		cs.logger.Info().Str("agentID", ag.ID).Str("serverID", cs.serverID).Msg("Rejecting duplicate connection: agent ID already connected to this server")
		conn.WriteJSON(map[string]string{
			"error":     "Cannot create multiple connections to a server with the same JWT",
			"agent_id":  ag.ID,
			"server_id": cs.serverID,
			"hint":      "The JWT subject (sub) is already connected to this server. Use a different JWT with a unique subject to create additional agents.",
		})
		conn.Close()
		return
	}
	cs.agents[ag.ID] = ag
	cs.agentsLock.Unlock()

	// Track JWT expiry
	cs.agentExpiryLock.Lock()
	cs.agentExpiry[ag.ID] = expiresAt
	cs.agentExpiryLock.Unlock()
	cs.logger.Debug().Str("agentID", ag.ID).Time("expires", expiresAt).Msg("Tracking JWT expiry for agent")

	// NOTE: Agent must explicitly send "ready" message before receiving requests

	hello := agentmgr.HelloMessage{
		ServerID:    cs.serverID,
		AgentID:     agentID,
		ServiceName: serviceName,
	}
	ag.WriteLock.Lock()
	err = conn.WriteJSON(hello)
	ag.WriteLock.Unlock()
	if err == nil {
		cs.metrics.WebsocketMessages.WithLabelValues("sent", "hello").Inc()
	}

	cs.logger.Info().Str("agentID", ag.ID).Str("service", serviceName).Msg("Agent connected (waiting for ready signal)")

	// Start ping/pong keepalive goroutine
	go cs.sendPings(ag)

	go cs.handleAgentMessages(ag)
}

func (cs *Server) sendPings(ag *agentmgr.Agent) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ag.WriteLock.Lock()
		ag.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := ag.Conn.WriteMessage(websocket.PingMessage, []byte{})
		ag.Conn.SetWriteDeadline(time.Time{})
		ag.WriteLock.Unlock()

		if err != nil {
			cs.logger.Debug().Err(err).Str("agentID", ag.ID).Msg("Failed to send ping to agent (connection likely dead)")
			return
		}
		cs.logger.Debug().Str("agentID", ag.ID).Msg("Sent ping to agent")
	}
}

func (cs *Server) handleAgentMessages(ag *agentmgr.Agent) {
	defer func() {
		cs.cleanupAgent(ag)
	}()

	for {
		messageType, frame, err := ag.Conn.ReadMessage()
		if err != nil {
			cs.logger.Info().Err(err).Str("agentID", ag.ID).Msg("Agent disconnected")
			return
		}

		if messageType == websocket.TextMessage {
			// JSON control messages (ready, draining)
			var msg map[string]interface{}
			if err := json.Unmarshal(frame, &msg); err != nil {
				cs.logger.Info().Err(err).Str("agentID", ag.ID).Msg("Agent sent invalid JSON")
				continue
			}

			msgType, ok := msg["type"].(string)
			if !ok {
				cs.logger.Info().Str("agentID", ag.ID).Interface("msg", msg).Msg("Agent sent message with invalid or missing 'type' field")
				continue
			}

			// Track WebSocket messages received
			cs.metrics.WebsocketMessages.WithLabelValues("recv", msgType).Inc()

			if msgType == "ready" {
				ag.SetReady(true)
				cs.logger.Info().Str("agentID", ag.ID).Msg("Agent is now ready to accept requests")
				continue
			}

			if msgType == "draining" {
				ag.SetReady(false)
				cs.logger.Info().Str("agentID", ag.ID).Msg("Agent is draining (no new requests, finishing existing)")
				continue
			}

			if msgType == "metrics" {
				// Update agent metrics
				ag.MetricsLock.Lock()
				if rateLimitRej, ok := msg["rate_limit_rejections"].(float64); ok {
					ag.Metrics.RateLimitRejections = int64(rateLimitRej)
				}
				if concReq, ok := msg["concurrent_requests"].(float64); ok {
					ag.Metrics.ConcurrentRequests = int(concReq)
				}
				if reqBuf, ok := msg["request_channel_buffer"].(float64); ok {
					ag.Metrics.RequestChannelBuffer = int(reqBuf)
				}
				if backendFail, ok := msg["backend_failures"].(float64); ok {
					ag.Metrics.BackendFailures = int64(backendFail)
				}
				if wsErrors, ok := msg["websocket_write_errors"].(float64); ok {
					ag.Metrics.WebsocketWriteErrors = int64(wsErrors)
				}
				if draining, ok := msg["draining"].(bool); ok {
					ag.Metrics.Draining = draining
				}
				if uptime, ok := msg["connection_uptime_seconds"].(float64); ok {
					ag.Metrics.ConnectionUptimeSeconds = int64(uptime)
				}
				// Parse frame counts
				if framesSent, ok := msg["frames_sent"].(map[string]interface{}); ok {
					ag.Metrics.FramesSent = make(map[string]int64)
					for k, v := range framesSent {
						if count, ok := v.(float64); ok {
							ag.Metrics.FramesSent[k] = int64(count)
						}
					}
				}
				if framesRecv, ok := msg["frames_received"].(map[string]interface{}); ok {
					ag.Metrics.FramesReceived = make(map[string]int64)
					for k, v := range framesRecv {
						if count, ok := v.(float64); ok {
							ag.Metrics.FramesReceived[k] = int64(count)
						}
					}
				}
				ag.Metrics.LastUpdate = time.Now()
				ag.MetricsLock.Unlock()

				cs.logger.Debug().Str("agentID", ag.ID).Msg("Updated agent metrics")
				continue
			}

		} else if messageType == websocket.BinaryMessage {
			// Binary frame - decode and deliver to response channel
			frameType, requestID, payload, err := protocol.DecodeFrame(frame)
			if err != nil {
				cs.logger.Info().Err(err).Str("agentID", ag.ID).Msg("Agent sent invalid binary frame")
				continue
			}

			// Track frame type for metrics
			var frameTypeName string
			switch frameType {
			case protocol.FrameTypeStart:
				frameTypeName = "response_start"
			case protocol.FrameTypeData:
				frameTypeName = "response_data"
			case protocol.FrameTypeEnd:
				frameTypeName = "response_end"
			default:
				frameTypeName = "unknown"
			}
			cs.metrics.WebsocketMessages.WithLabelValues("recv", frameTypeName).Inc()

			cs.logger.Debug().Str("agentID", ag.ID).Str("frameType", frameTypeName).Str("requestID", requestID).Int("payloadBytes", len(payload)).Msg("Agent sent frame")

			// Deliver frame to waiting response channel
			if !ag.DeliverResponseFrame(requestID, frame) {
				cs.logger.Warn().Str("requestID", requestID).Msg("No channel or buffer full for request")
			}

			// Clean up on end frame
			if frameType == protocol.FrameTypeEnd {
				ag.CleanupRequest(requestID)
			}
		}
	}
}

func (cs *Server) cleanupAgent(ag *agentmgr.Agent) {
	// Only remove from map if this agent is still the current one
	// (not replaced by a reconnection)
	cs.agentsLock.Lock()
	if currentAgent, exists := cs.agents[ag.ID]; exists && currentAgent == ag {
		delete(cs.agents, ag.ID)
		cs.agentsLock.Unlock()

		// Close all pending request channels immediately
		pendingCount := ag.CleanupAllRequests()

		// Remove JWT expiry tracking
		cs.agentExpiryLock.Lock()
		delete(cs.agentExpiry, ag.ID)
		cs.agentExpiryLock.Unlock()

		if pendingCount > 0 {
			cs.logger.Info().Str("agentID", ag.ID).Int("pendingRequests", pendingCount).Msg("Cleaned up agent")
		} else {
			cs.logger.Info().Str("agentID", ag.ID).Msg("Cleaned up agent")
		}
	} else {
		cs.agentsLock.Unlock()
		cs.logger.Info().Str("agentID", ag.ID).Msg("Agent already replaced, skipping cleanup")
	}

	// Always close the connection
	ag.Conn.Close()
}

func (cs *Server) checkExpiredJWTs() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		cs.agentExpiryLock.RLock()
		expiredAgents := make([]string, 0)
		for agentID, expiresAt := range cs.agentExpiry {
			if now.After(expiresAt) {
				expiredAgents = append(expiredAgents, agentID)
			}
		}
		cs.agentExpiryLock.RUnlock()

		if len(expiredAgents) > 0 {
			cs.logger.Info().Int("count", len(expiredAgents)).Msg("Found expired agent JWTs, terminating connections")
			for _, agentID := range expiredAgents {
				cs.terminateExpiredAgent(agentID)
			}
		}
	}
}

func (cs *Server) terminateExpiredAgent(agentID string) {
	cs.agentsLock.RLock()
	ag, exists := cs.agents[agentID]
	cs.agentsLock.RUnlock()

	if !exists {
		// Agent already disconnected, just clean up expiry map
		cs.agentExpiryLock.Lock()
		delete(cs.agentExpiry, agentID)
		cs.agentExpiryLock.Unlock()
		return
	}

	cs.logger.Info().Str("agentID", agentID).Msg("Terminating agent: JWT expired")

	// Send expiry notification
	expiryMsg := map[string]interface{}{
		"type":    "token_expired",
		"message": "JWT token has expired",
	}
	ag.WriteLock.Lock()
	ag.Conn.WriteJSON(expiryMsg)
	ag.WriteLock.Unlock()

	// Close connection (cleanup will handle removal from maps)
	ag.Conn.Close()
}
