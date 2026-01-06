package handlers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gimlet/protocol"
	"gimlet/server/agentmgr"
	"gimlet/server/auth"
	"gimlet/server/errors"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// AgentProvider provides access to local agents
type AgentProvider interface {
	GetLocalAgents() map[string]*agentmgr.Agent
}

// HTTPHandler handles HTTP requests with streaming responses
type HTTPHandler struct {
	jwtValidator              *auth.JWTValidator
	agentProvider             AgentProvider
	serverID                  string
	idleTimeout               time.Duration
	responseChannelBufferSize int
	maxConcurrentRequests     int64
	requestSemaphore          chan struct{}
	logger                    zerolog.Logger
	metricsTracker            MetricsTracker
	rrCounter                 atomic.Uint64 // Round-robin counter for agent selection
}

// MetricsTracker tracks request metrics
type MetricsTracker interface {
	IncrementActiveRequests(service string)
	DecrementActiveRequests(service string)
	ObserveRequestDuration(service string, duration float64)
	IncrementRequestsTotal(service string, agentID string, clientID string, statusCode string)
	IncrementWebsocketMessage(direction string, messageType string)
	ObserveResponseChannelBuffer(service string, agentID string, bufferUsage float64)
	IncrementRateLimitRejection(service string, limitType string)
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(
	jwtValidator *auth.JWTValidator,
	agentProvider AgentProvider,
	serverID string,
	idleTimeout time.Duration,
	responseChannelBufferSize int,
	maxConcurrentRequests int64,
	logger zerolog.Logger,
	metricsTracker MetricsTracker,
) *HTTPHandler {
	h := &HTTPHandler{
		jwtValidator:              jwtValidator,
		agentProvider:             agentProvider,
		serverID:                  serverID,
		idleTimeout:               idleTimeout,
		responseChannelBufferSize: responseChannelBufferSize,
		maxConcurrentRequests:     maxConcurrentRequests,
		logger:                    logger,
		metricsTracker:            metricsTracker,
	}

	// Initialize semaphore if limit is set
	if maxConcurrentRequests > 0 {
		h.requestSemaphore = make(chan struct{}, maxConcurrentRequests)
	}

	return h
}

// Hop-by-hop headers that should not be forwarded
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// ServeHTTP implements http.Handler for proxying requests to agents
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	finalStatus := 0
	agentID := ""
	clientID := ""

	ctx := r.Context()

	// Extract service name from path (/services/<service>/...)
	service, rewrittenPath := h.extractServiceFromPath(r.URL.Path)
	if service == "" {
		h.logger.Error().Str("path", r.URL.Path).Msg("Invalid path - expected /services/<service>/...")
		http.Error(w, "Invalid path - expected /services/<service>/...", http.StatusBadRequest)
		return
	}

	// Check global server rate limit
	if h.requestSemaphore != nil {
		select {
		case h.requestSemaphore <- struct{}{}:
			defer func() { <-h.requestSemaphore }()
		default:
			h.logger.Warn().Str("service", service).Int64("serverLimit", h.maxConcurrentRequests).Msg("Rate limit exceeded for service")
			h.metricsTracker.IncrementRateLimitRejection(service, "server")
			finalStatus = http.StatusTooManyRequests
			http.Error(w, errors.Format(errors.CodeRateLimitExceeded,
				fmt.Sprintf("Server concurrent request limit reached (%d)", h.maxConcurrentRequests)),
				http.StatusTooManyRequests)
			return
		}
	}

	h.metricsTracker.IncrementActiveRequests(service)
	defer func() {
		h.metricsTracker.DecrementActiveRequests(service)
		h.metricsTracker.ObserveRequestDuration(service, time.Since(start).Seconds())
		if finalStatus > 0 {
			h.metricsTracker.IncrementRequestsTotal(service, agentID, clientID, fmt.Sprintf("%d", finalStatus))
		}
	}()

	h.logger.Debug().Str("method", r.Method).Str("path", r.URL.Path).Str("service", service).Msg("HTTP request")

	// Validate client JWT
	token := r.Header.Get("Authorization")
	if token == "" {
		finalStatus = http.StatusUnauthorized
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	} else {
		finalStatus = http.StatusUnauthorized
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	var services []string
	var err error
	clientID, services, _, err = h.jwtValidator.ValidateClientJWT(token)
	if err != nil {
		h.logger.Error().Err(err).Str("service", service).Msg("Client JWT validation failed")
		finalStatus = http.StatusUnauthorized
		http.Error(w, auth.SanitizeJWTError(err), http.StatusUnauthorized)
		return
	}

	if !auth.MatchesAny(service, services) {
		h.logger.Error().Str("clientID", clientID).Str("service", service).Strs("allowedServices", services).Msg("Client not authorized for service")
		finalStatus = http.StatusForbidden
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	h.logger.Debug().Str("clientID", clientID).Str("service", service).Msg("Client JWT validated")

	// Select agent (round-robin)
	allAgents := h.agentProvider.GetLocalAgents()
	type agentEntry struct {
		id    string
		agent *agentmgr.Agent
	}
	var eligible []agentEntry
	for id, agent := range allAgents {
		if agent.ServiceName == service && agent.IsReady() {
			eligible = append(eligible, agentEntry{id, agent})
		}
	}

	if len(eligible) == 0 {
		finalStatus = http.StatusServiceUnavailable
		http.Error(w, errors.Format(errors.CodeAgentUnavailable,
			fmt.Sprintf("No agents available for service %s", service)),
			http.StatusServiceUnavailable)
		return
	}

	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].id < eligible[j].id
	})

	idx := h.rrCounter.Add(1) % uint64(len(eligible))
	selected := eligible[idx]
	ag := selected.agent
	agentID = selected.id

	h.logger.Debug().Str("agentID", agentID).Str("service", service).Int("agentCount", len(eligible)).Msg("Selected agent (round-robin)")

	requestID := uuid.New().String()
	reqLogger := h.logger.With().Str("requestID", requestID).Str("service", service).Str("agentID", agentID).Str("clientID", clientID).Logger()

	// Register response channel before sending request
	respCh := ag.RegisterResponseChannel(requestID, h.responseChannelBufferSize)
	defer ag.CleanupRequest(requestID)
	defer func() {
		// Always send CANCEL when handler returns
		if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
			reqLogger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
		}
		h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
	}()

	// Stream request to agent
	if err := h.streamRequestToAgent(ctx, ag, requestID, r, rewrittenPath, reqLogger); err != nil {
		reqLogger.Error().Err(err).Msg("Failed to stream request to agent")
		finalStatus = http.StatusBadGateway
		http.Error(w, errors.Format(errors.CodeAgentUnavailable, "Failed to forward request to agent"), http.StatusBadGateway)
		return
	}

	// Stream response to client
	finalStatus = h.streamResponseToClient(ctx, w, respCh, requestID, reqLogger)
}

// streamRequestToAgent streams the HTTP request to the agent
func (h *HTTPHandler) streamRequestToAgent(ctx context.Context, ag *agentmgr.Agent, requestID string, r *http.Request, rewrittenPath string, logger zerolog.Logger) error {
	// Serialize request headers
	headerBytes, err := serializeRequestHeaders(r, rewrittenPath)
	if err != nil {
		return fmt.Errorf("failed to serialize headers: %w", err)
	}

	logger.Debug().Msg("Sending request headers to agent")

	// Send headers as START frame
	if err := ag.SendHTTPRequestStart(requestID, headerBytes); err != nil {
		return fmt.Errorf("failed to send start frame: %w", err)
	}
	h.metricsTracker.IncrementWebsocketMessage("sent", "request_start")

	// Stream request body as DATA frames
	if r.Body != nil {
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-ctx.Done():
				ag.SendHTTPRequestEnd(requestID, "client disconnected")
				return ctx.Err()
			default:
			}

			n, readErr := r.Body.Read(buf)
			if n > 0 {
				if err := ag.SendHTTPRequestData(requestID, buf[:n]); err != nil {
					return fmt.Errorf("failed to send data frame: %w", err)
				}
				h.metricsTracker.IncrementWebsocketMessage("sent", "request_data")
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return fmt.Errorf("failed to read request body: %w", readErr)
			}
		}
	}

	// Send END frame
	if err := ag.SendHTTPRequestEnd(requestID, ""); err != nil {
		return fmt.Errorf("failed to send end frame: %w", err)
	}
	h.metricsTracker.IncrementWebsocketMessage("sent", "request_end")

	return nil
}

// streamResponseToClient streams response frames from agent to the http.ResponseWriter
func (h *HTTPHandler) streamResponseToClient(ctx context.Context, w http.ResponseWriter, respCh <-chan []byte, requestID string, logger zerolog.Logger) int {
	flusher, ok := w.(http.Flusher)
	if !ok {
		logger.Error().Msg("ResponseWriter does not support Flusher")
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	idleTimer := time.NewTimer(h.idleTimeout)
	defer idleTimer.Stop()

	headersSent := false
	statusCode := 0

	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			logger.Info().Msg("Client disconnected")
			return statusCode

		case <-idleTimer.C:
			logger.Error().Dur("idleTimeout", h.idleTimeout).Msg("Request idle timeout")
			if !headersSent {
				http.Error(w, errors.Format(errors.CodeTimeout, "Request timeout"), http.StatusGatewayTimeout)
			}
			return http.StatusGatewayTimeout

		case frame, ok := <-respCh:
			// Reset idle timer
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(h.idleTimeout)

			if !ok {
				// Channel closed (agent disconnected)
				if !headersSent {
					logger.Error().Msg("Request failed: agent disconnected before response")
					http.Error(w, errors.Format(errors.CodeAgentDisconnect, "Agent disconnected"), http.StatusBadGateway)
					return http.StatusBadGateway
				}
				logger.Debug().Int("statusCode", statusCode).Msg("Request completed")
				return statusCode
			}

			frameType, _, payload, err := protocol.DecodeFrame(frame)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to decode response frame")
				if !headersSent {
					http.Error(w, "Invalid response from agent", http.StatusBadGateway)
				}
				return http.StatusBadGateway
			}

			switch frameType {
			case protocol.FrameTypeStart:
				// Parse response headers from START frame
				resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
				if err != nil {
					logger.Error().Err(err).Msg("Failed to parse response headers")
					http.Error(w, "Invalid response format", http.StatusBadGateway)
					return http.StatusBadGateway
				}

				statusCode = resp.StatusCode

				// Copy headers to ResponseWriter, filtering hop-by-hop headers
				for key, values := range resp.Header {
					if hopByHopHeaders[key] {
						continue
					}
					for _, v := range values {
						w.Header().Add(key, v)
					}
				}
				w.WriteHeader(resp.StatusCode)
				headersSent = true

				logger.Debug().Int("statusCode", resp.StatusCode).Msg("Sent response headers")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_start")

			case protocol.FrameTypeData:
				if !headersSent {
					logger.Warn().Msg("Received data frame before start frame")
					continue
				}

				if _, err := w.Write(payload); err != nil {
					logger.Error().Err(err).Msg("Failed to write response chunk to client")
					return statusCode
				}
				flusher.Flush()

				logger.Debug().Int("chunkBytes", len(payload)).Msg("Sent chunk")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_data")

			case protocol.FrameTypeEnd:
				errorMsg := string(payload)
				if errorMsg != "" {
					logger.Error().Str("error", errorMsg).Msg("Request ended with error")
					if !headersSent {
						http.Error(w, errors.Format(errors.CodeBackendError, errorMsg), http.StatusBadGateway)
						return http.StatusBadGateway
					}
				}
				logger.Debug().Int("statusCode", statusCode).Msg("Request completed")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_end")
				return statusCode
			}
		}
	}
}

// HandleTCPConnection handles a raw TCP connection as an HTTP proxy
// Deprecated: Use ServeHTTP instead
func (h *HTTPHandler) HandleTCPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	start := time.Now()
	finalStatus := 0
	agentID := ""
	clientID := ""

	// Parse HTTP request headers from TCP stream
	buffered := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(buffered)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to parse HTTP request")
		h.writeHTTPError(clientConn, http.StatusBadRequest, "Bad Request")
		return
	}

	// Extract service name from path (/services/<service>/...)
	service, rewrittenPath := h.extractServiceFromPath(req.URL.Path)
	if service == "" {
		h.logger.Error().Str("path", req.URL.Path).Msg("Invalid path - expected /services/<service>/...")
		h.writeHTTPError(clientConn, http.StatusBadRequest, "Invalid path - expected /services/<service>/...")
		return
	}

	// Check global server rate limit
	if h.requestSemaphore != nil {
		select {
		case h.requestSemaphore <- struct{}{}:
			defer func() { <-h.requestSemaphore }()
		default:
			h.logger.Warn().Str("service", service).Int64("serverLimit", h.maxConcurrentRequests).Msg("Rate limit exceeded for service")
			h.metricsTracker.IncrementRateLimitRejection(service, "server")
			finalStatus = http.StatusTooManyRequests
			h.writeHTTPError(clientConn, http.StatusTooManyRequests,
				errors.Format(errors.CodeRateLimitExceeded,
					fmt.Sprintf("Server concurrent request limit reached (%d)", h.maxConcurrentRequests)))
			return
		}
	}

	h.metricsTracker.IncrementActiveRequests(service)
	defer func() {
		h.metricsTracker.DecrementActiveRequests(service)
		h.metricsTracker.ObserveRequestDuration(service, time.Since(start).Seconds())
		if finalStatus > 0 {
			h.metricsTracker.IncrementRequestsTotal(service, agentID, clientID, fmt.Sprintf("%d", finalStatus))
		}
	}()

	h.logger.Debug().Str("method", req.Method).Str("path", req.URL.Path).Str("service", service).Msg("HTTP request")

	// Validate client JWT
	token := req.Header.Get("Authorization")
	if token == "" {
		finalStatus = http.StatusUnauthorized
		h.writeHTTPError(clientConn, http.StatusUnauthorized, "Missing Authorization header")
		return
	}

	// Strip "Bearer " prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	} else {
		finalStatus = http.StatusUnauthorized
		h.writeHTTPError(clientConn, http.StatusUnauthorized, "Invalid Authorization header format")
		return
	}

	var services []string
	clientID, services, _, err = h.jwtValidator.ValidateClientJWT(token)
	if err != nil {
		h.logger.Error().Err(err).Str("service", service).Msg("Client JWT validation failed")
		finalStatus = http.StatusUnauthorized
		h.writeHTTPError(clientConn, http.StatusUnauthorized, auth.SanitizeJWTError(err))
		return
	}

	// Check if client is authorized for this service
	if !auth.MatchesAny(service, services) {
		h.logger.Error().Str("clientID", clientID).Str("service", service).Strs("allowedServices", services).Msg("Client not authorized for service")
		finalStatus = http.StatusForbidden
		h.writeHTTPError(clientConn, http.StatusForbidden, "Forbidden")
		return
	}

	h.logger.Debug().Str("clientID", clientID).Str("service", service).Msg("Client JWT validated")

	// Local-only agent selection: round-robin through ready agents
	allAgents := h.agentProvider.GetLocalAgents()

	// Collect eligible agents (ready, matching service)
	type agentEntry struct {
		id    string
		agent *agentmgr.Agent
	}
	var eligible []agentEntry
	for id, agent := range allAgents {
		if agent.ServiceName == service && agent.IsReady() {
			eligible = append(eligible, agentEntry{id, agent})
		}
	}

	if len(eligible) == 0 {
		finalStatus = http.StatusServiceUnavailable
		h.writeHTTPError(clientConn, http.StatusServiceUnavailable,
			errors.Format(errors.CodeAgentUnavailable, fmt.Sprintf("No agents available for service %s", service)))
		return
	}

	// Sort by ID for deterministic round-robin order
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].id < eligible[j].id
	})

	// Round-robin selection
	idx := h.rrCounter.Add(1) % uint64(len(eligible))
	selected := eligible[idx]
	ag := selected.agent
	agentID = selected.id

	h.logger.Debug().Str("agentID", agentID).Str("service", service).Int("agentCount", len(eligible)).Msg("Selected agent (round-robin)")

	requestID := uuid.New().String()

	// Create child logger with requestID context
	reqLogger := h.logger.With().Str("requestID", requestID).Str("service", service).Str("agentID", agentID).Str("clientID", clientID).Logger()

	// Register response channel before sending request
	respCh := ag.RegisterResponseChannel(requestID, h.responseChannelBufferSize)
	defer ag.CleanupRequest(requestID)

	// Serialize request headers with rewritten path
	headerBytes, err := serializeRequestHeaders(req, rewrittenPath)
	if err != nil {
		reqLogger.Error().Err(err).Msg("Failed to serialize request headers")
		finalStatus = http.StatusInternalServerError
		h.writeHTTPError(clientConn, http.StatusInternalServerError, "Failed to serialize request")
		return
	}

	reqLogger.Debug().Msg("Sending request headers to agent")

	// Send headers as start frame
	if err := ag.SendHTTPRequestStart(requestID, headerBytes); err != nil {
		reqLogger.Error().Err(err).Msg("Failed to send request start to agent")
		finalStatus = http.StatusBadGateway
		h.writeHTTPError(clientConn, http.StatusBadGateway, errors.Format(errors.CodeAgentUnavailable, "Failed to forward request to agent"))
		return
	}
	h.metricsTracker.IncrementWebsocketMessage("sent", "request_start")

	// Stream request body from buffered reader (which has the body)
	if req.Body != nil {
		buffer := make([]byte, 64*1024) // 64KB chunks

		for {
			n, readErr := req.Body.Read(buffer)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buffer[:n])

				if err := ag.SendHTTPRequestData(requestID, chunk); err != nil {
					reqLogger.Error().Err(err).Msg("Failed to send request data to agent")
					ag.SendHTTPRequestEnd(requestID, fmt.Sprintf("Failed to send body: %v", err))
					finalStatus = http.StatusBadGateway
					h.writeHTTPError(clientConn, http.StatusBadGateway, "Failed to stream request body")
					return
				}
				h.metricsTracker.IncrementWebsocketMessage("sent", "request_data")
			}

			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				reqLogger.Error().Err(readErr).Msg("Error reading request body")
				ag.SendHTTPRequestEnd(requestID, fmt.Sprintf("Read error: %v", readErr))
				finalStatus = http.StatusBadRequest
				h.writeHTTPError(clientConn, http.StatusBadRequest, "Failed to read request body")
				return
			}
		}
	}

	// Send request end frame
	if err := ag.SendHTTPRequestEnd(requestID, ""); err != nil {
		reqLogger.Error().Err(err).Msg("Failed to send request end to agent")
		finalStatus = http.StatusBadGateway
		h.writeHTTPError(clientConn, http.StatusBadGateway, "Failed to complete request")
		return
	}
	h.metricsTracker.IncrementWebsocketMessage("sent", "request_end")

	// Stream response from agent directly to TCP connection
	finalStatus = h.streamResponseToTCP(clientConn, respCh, requestID, ag, service, reqLogger)
}

// extractServiceFromPath extracts service name from URL path
// e.g., "/services/model-v1/predict" -> ("model-v1", "/predict")
// Returns service name and rewritten path (with /services/<service> prefix stripped)
func (h *HTTPHandler) extractServiceFromPath(path string) (service string, rewrittenPath string) {
	const prefix = "/services/"

	if !strings.HasPrefix(path, prefix) {
		return "", path
	}

	// Remove "/services/" prefix
	remainder := path[len(prefix):]

	// Handle empty service name (e.g., "/services/" or "/services")
	if remainder == "" {
		return "", path
	}

	// Find the next slash to get service name
	slashIdx := strings.Index(remainder, "/")
	if slashIdx == -1 {
		// Path is "/services/service-name" with no trailing path
		return remainder, "/"
	}

	service = remainder[:slashIdx]
	rewrittenPath = remainder[slashIdx:]

	if service == "" {
		return "", path
	}

	return service, rewrittenPath
}

// writeHTTPError writes an HTTP error response to the TCP connection
func (h *HTTPHandler) writeHTTPError(conn net.Conn, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, http.StatusText(statusCode), len(message), message)
	if _, err := conn.Write([]byte(response)); err != nil {
		h.logger.Debug().Err(err).Int("statusCode", statusCode).Msg("Failed to write HTTP error response")
	}
}

// streamResponseToTCP streams binary frames from agent to TCP connection
func (h *HTTPHandler) streamResponseToTCP(
	conn net.Conn,
	respCh <-chan []byte,
	requestID string,
	ag *agentmgr.Agent,
	service string,
	logger zerolog.Logger,
) int {
	idleTimer := time.NewTimer(h.idleTimeout)
	defer idleTimer.Stop()

	// Monitor client connection for closure
	// When the client fully closes the connection (e.g., curl finishes), we detect it
	// and can immediately signal the agent to clean up the backend connection.
	clientClosed := make(chan struct{})
	monitorDone := make(chan struct{})
	defer close(monitorDone) // Signal monitor goroutine to exit when we return

	go func() {
		buf := make([]byte, 1)
		// This blocks until client sends data (unlikely) or closes connection
		_, err := conn.Read(buf)
		if err != nil {
			// Only signal clientClosed if we haven't been told to stop
			select {
			case <-monitorDone:
				return
			default:
				close(clientClosed)
			}
		}
	}()

	headersSent := false
	statusCode := 0

	for {
		select {
		case frame, ok := <-respCh:
			// Reset idle timer
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(h.idleTimeout)

			if !ok {
				// Channel closed - check if this was normal completion
				if !headersSent {
					logger.Error().Msg("Request failed: agent disconnected before response")
					h.writeHTTPError(conn, http.StatusBadGateway, errors.Format(errors.CodeAgentDisconnect, "Agent disconnected"))
					return http.StatusBadGateway
				}
				logger.Debug().Int("statusCode", statusCode).Msg("Request completed")
				return statusCode
			}

			// Decode frame
			frameType, _, payload, err := protocol.DecodeFrame(frame)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to decode response frame")
				if !headersSent {
					h.writeHTTPError(conn, http.StatusBadGateway, "Invalid response from agent")
				}
				return http.StatusBadGateway
			}

			switch frameType {
			case protocol.FrameTypeStart:
				// Parse HTTP response headers to extract status code
				resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
				if err != nil {
					logger.Error().Err(err).Msg("Failed to parse response headers")
					h.writeHTTPError(conn, http.StatusBadGateway, "Invalid response format")
					return http.StatusBadGateway
				}

				statusCode = resp.StatusCode
				headersSent = true

				// Write raw response bytes (headers + any body) directly to TCP connection
				if _, err := conn.Write(payload); err != nil {
					logger.Error().Err(err).Msg("Failed to write response start to client")
					// Send cancel to agent (client disconnected)
					if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
						logger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
					}
					h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
					return statusCode
				}

				logger.Debug().Int("statusCode", resp.StatusCode).Msg("Sent response_start")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_start")

			case protocol.FrameTypeData:
				if !headersSent {
					logger.Warn().Msg("Received data frame before start frame")
					continue
				}

				// Write chunk directly to TCP connection
				if _, err := conn.Write(payload); err != nil {
					logger.Error().Err(err).Msg("Failed to write response chunk to client")
					// Send cancel to agent (client disconnected)
					if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
						logger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
					}
					h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
					return statusCode
				}

				logger.Debug().Int("chunkBytes", len(payload)).Msg("Sent chunk")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_data")

			case protocol.FrameTypeEnd:
				errorMsg := string(payload)
				if errorMsg != "" {
					logger.Error().Str("error", errorMsg).Msg("Request ended with error")
					if !headersSent {
						h.writeHTTPError(conn, http.StatusBadGateway, errors.Format(errors.CodeBackendError, errorMsg))
						return http.StatusBadGateway
					}
				}
				logger.Debug().Int("statusCode", statusCode).Msg("Request completed")
				h.metricsTracker.IncrementWebsocketMessage("recv", "response_end")
				// Wait for client to close connection, then send CANCEL to agent
				// so it can clean up the backend connection immediately.
				<-clientClosed
				logger.Debug().Msg("Client closed connection after response")
				if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
					logger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
				}
				h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
				return statusCode
			}

		case <-idleTimer.C:
			logger.Error().Dur("idleTimeout", h.idleTimeout).Msg("Request idle timeout")
			// Send cancel to agent (request timed out)
			if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
				logger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
			}
			h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
			if !headersSent {
				h.writeHTTPError(conn, http.StatusGatewayTimeout, errors.Format(errors.CodeTimeout, "Request timeout"))
			}
			return http.StatusGatewayTimeout

		case <-clientClosed:
			logger.Info().Msg("Client closed connection")
			// Send cancel to agent so it can clean up the backend connection
			if cancelErr := ag.SendHTTPRequestCancel(requestID); cancelErr != nil {
				logger.Debug().Err(cancelErr).Msg("Failed to send cancel frame to agent")
			}
			h.metricsTracker.IncrementWebsocketMessage("sent", "request_cancel")
			// Don't write error - client already closed
			return statusCode
		}
	}
}

// serializeRequestHeaders serializes just the HTTP request headers (not body)
// Uses rewrittenPath instead of the original request URI
func serializeRequestHeaders(r *http.Request, rewrittenPath string) ([]byte, error) {
	var buf bytes.Buffer

	// Build request URI with rewritten path + query string
	requestURI := rewrittenPath
	if r.URL.RawQuery != "" {
		requestURI = rewrittenPath + "?" + r.URL.RawQuery
	}

	fmt.Fprintf(&buf, "%s %s HTTP/%d.%d\r\n",
		r.Method,
		requestURI,
		r.ProtoMajor,
		r.ProtoMinor,
	)

	// Host header (not in r.Header map, stored in r.Host)
	if r.Host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	}

	// All other headers
	if err := r.Header.Write(&buf); err != nil {
		return nil, err
	}

	// Blank line to mark end of headers
	buf.WriteString("\r\n")

	return buf.Bytes(), nil
}


