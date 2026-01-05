package connection

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gimlet/protocol"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// WebSocketConn is re-exported from protocol for backward compatibility
type WebSocketConn = protocol.WebSocketConn

// RequestTracker tracks in-flight request count
type RequestTracker interface {
	IncrementRequests()
	DecrementRequests()
}

// TCPDialer abstracts TCP connection dialing for testing
type TCPDialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

// ConnectionMetrics tracks metrics for this specific agent-server connection
type ConnectionMetrics struct {
	rateLimitRejections  int64
	backendFailures      int64
	websocketWriteErrors int64
	framesSent           map[string]int64
	framesReceived       map[string]int64
	mu                   sync.RWMutex
	connectionStartTime  time.Time
}

// NewConnectionMetrics creates a new metrics tracker
func NewConnectionMetrics() *ConnectionMetrics {
	return &ConnectionMetrics{
		framesSent:          make(map[string]int64),
		framesReceived:      make(map[string]int64),
		connectionStartTime: time.Now(),
	}
}

// Increment methods for metrics (thread-safe with atomics where possible)
func (m *ConnectionMetrics) incrementRateLimitRejections() {
	m.mu.Lock()
	m.rateLimitRejections++
	m.mu.Unlock()
}

func (m *ConnectionMetrics) incrementBackendFailures() {
	m.mu.Lock()
	m.backendFailures++
	m.mu.Unlock()
}

func (m *ConnectionMetrics) incrementWebsocketWriteErrors() {
	m.mu.Lock()
	m.websocketWriteErrors++
	m.mu.Unlock()
}

func (m *ConnectionMetrics) incrementFrameSent(frameType string) {
	m.mu.Lock()
	m.framesSent[frameType]++
	m.mu.Unlock()
}

func (m *ConnectionMetrics) incrementFrameReceived(frameType string) {
	m.mu.Lock()
	m.framesReceived[frameType]++
	m.mu.Unlock()
}

// requestState holds the channels for a single in-flight request
type requestState struct {
	dataCh chan []byte
	done   chan struct{}
}

// Handler manages a WebSocket connection and routes messages
type Handler struct {
	conn                     WebSocketConn
	backendAddr              string // e.g., "backend:80"
	dialer                   TCPDialer
	writeLock                sync.Mutex
	requestTracker           RequestTracker
	logger                   zerolog.Logger
	maxConcurrentRequests    int
	requestSemaphore         chan struct{} // Shared semaphore (global per agent, not per connection)
	requestChannelBufferSize int
	metrics                  *ConnectionMetrics

	// Request routing - maps requestID to request state (includes done channel for safe cleanup)
	requestHandlers map[string]*requestState
	handlerMu       sync.Mutex

	// Shutdown signaling
	done chan struct{}
}

// NewHandler creates a new connection handler with a shared semaphore
func NewHandler(conn WebSocketConn, backendAddr string, dialer TCPDialer, tracker RequestTracker, logger zerolog.Logger, maxConcurrentRequests int, requestSemaphore chan struct{}, requestChannelBufferSize int) *Handler {
	h := &Handler{
		conn:                     conn,
		backendAddr:              backendAddr,
		dialer:                   dialer,
		requestTracker:           tracker,
		logger:                   logger,
		maxConcurrentRequests:    maxConcurrentRequests,
		requestSemaphore:         requestSemaphore, // Use shared semaphore
		requestChannelBufferSize: requestChannelBufferSize,
		requestHandlers:          make(map[string]*requestState),
		metrics:                  NewConnectionMetrics(),
		done:                     make(chan struct{}),
	}

	return h
}

// closeAllRequestChannels closes all pending request channels on connection shutdown
func (h *Handler) closeAllRequestChannels() {
	h.handlerMu.Lock()
	defer h.handlerMu.Unlock()

	for requestID, state := range h.requestHandlers {
		h.logger.Debug().Str("requestID", requestID).Msg("Closing request channel on connection shutdown")
		// Close done first to unblock any pending deliverFrame calls
		close(state.done)
		// Then close data channel to signal receivers
		close(state.dataCh)
		delete(h.requestHandlers, requestID)
	}
}

// deliverFrame safely delivers a frame to a request handler.
// Returns false if the request doesn't exist or has been cleaned up.
// This avoids TOCTOU races by using the done channel as a cancellation signal.
func (h *Handler) deliverFrame(requestID string, frame []byte) bool {
	h.handlerMu.Lock()
	state, exists := h.requestHandlers[requestID]
	h.handlerMu.Unlock()

	if !exists {
		return false
	}

	// Use select to either deliver the frame or detect cleanup.
	// This avoids blocking forever if the handler exits between our check and send.
	select {
	case state.dataCh <- frame:
		return true
	case <-state.done:
		// Request was cleaned up while we were waiting to send
		return false
	}
}

// writeFrame writes a frame to WebSocket and tracks metrics
func (h *Handler) writeFrame(frame []byte) error {
	// Decode frame to get type
	if len(frame) < 2 {
		return fmt.Errorf("frame too short")
	}
	frameType := frame[0]

	h.writeLock.Lock()
	err := h.conn.WriteMessage(websocket.BinaryMessage, frame)
	h.writeLock.Unlock()

	if err != nil {
		h.metrics.incrementWebsocketWriteErrors()
		return err
	}

	h.metrics.incrementFrameSent(protocol.FrameTypeToString(frameType))
	return nil
}

// StartMetricsReporter starts a goroutine that periodically sends metrics to the server
func (h *Handler) StartMetricsReporter(interval time.Duration, drainingFlag interface{ Load() bool }) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			metricsUpdate := h.collectMetricsUpdate(drainingFlag)
			if err := h.sendMetricsUpdate(metricsUpdate); err != nil {
				h.logger.Warn().Err(err).Msg("Failed to send metrics update")
			}
		}
	}
}

// collectMetricsUpdate collects current metrics snapshot
func (h *Handler) collectMetricsUpdate(drainingFlag interface{ Load() bool }) map[string]interface{} {
	h.metrics.mu.RLock()
	defer h.metrics.mu.RUnlock()

	// Count concurrent requests and buffer usage
	h.handlerMu.Lock()
	concurrentRequests := len(h.requestHandlers)
	bufferUsage := 0
	for _, state := range h.requestHandlers {
		bufferUsage += len(state.dataCh)
	}
	h.handlerMu.Unlock()

	// Copy frame counts
	framesSent := make(map[string]int64)
	for k, v := range h.metrics.framesSent {
		framesSent[k] = v
	}

	framesReceived := make(map[string]int64)
	for k, v := range h.metrics.framesReceived {
		framesReceived[k] = v
	}

	draining := false
	if drainingFlag != nil {
		draining = drainingFlag.Load()
	}

	uptime := int64(time.Since(h.metrics.connectionStartTime).Seconds())

	return map[string]interface{}{
		"type":                      "metrics",
		"rate_limit_rejections":     h.metrics.rateLimitRejections,
		"concurrent_requests":       concurrentRequests,
		"request_channel_buffer":    bufferUsage,
		"backend_failures":          h.metrics.backendFailures,
		"frames_sent":               framesSent,
		"frames_received":           framesReceived,
		"websocket_write_errors":    h.metrics.websocketWriteErrors,
		"draining":                  draining,
		"connection_uptime_seconds": uptime,
	}
}

// sendMetricsUpdate sends a metrics update message to the server
func (h *Handler) sendMetricsUpdate(metrics map[string]interface{}) error {
	h.writeLock.Lock()
	defer h.writeLock.Unlock()
	return h.conn.WriteJSON(metrics)
}

// Run starts the message processing loop
func (h *Handler) Run() {
	defer h.conn.Close()
	defer close(h.done)
	defer h.closeAllRequestChannels()

	for {
		messageType, frame, err := h.conn.ReadMessage()
		if err != nil {
			h.logger.Error().Err(err).Msg("WebSocket read error")
			return
		}

		if messageType == websocket.BinaryMessage {
			// Route binary frames to appropriate request handler
			frameType, requestID, _, err := protocol.DecodeFrame(frame)
			if err != nil {
				h.logger.Error().Err(err).Msg("Failed to decode binary frame")
				continue
			}

			// Track received frame
			h.metrics.incrementFrameReceived(protocol.FrameTypeToString(frameType))

			if frameType == protocol.FrameTypeStart {
				// Check agent rate limit BEFORE creating handler
				if h.requestSemaphore != nil {
					select {
					case h.requestSemaphore <- struct{}{}:
						// Acquired - continue
						h.logger.Debug().Str("requestID", requestID).Int("agentLimit", h.maxConcurrentRequests).Int("currentLoad", len(h.requestSemaphore)).Msg("Acquired semaphore slot")
					default:
						// Semaphore full - send 429 response
						h.logger.Warn().Str("requestID", requestID).Int("agentLimit", h.maxConcurrentRequests).Msg("Rate limit exceeded for request")
						h.sendRateLimitResponse(requestID, h.maxConcurrentRequests)
						continue
					}
				} else {
					h.logger.Debug().Str("requestID", requestID).Msg("No rate limit configured (semaphore is nil)")
				}

				// New request - create handler and state
				state := &requestState{
					dataCh: make(chan []byte, h.requestChannelBufferSize),
					done:   make(chan struct{}),
				}
				h.handlerMu.Lock()
				h.requestHandlers[requestID] = state
				h.handlerMu.Unlock()

				go h.handleHTTPRequest(requestID, state.dataCh)
				state.dataCh <- frame // Send start frame
			} else {
				// Route to existing handler using safe delivery
				// This avoids TOCTOU races where the handler exits between check and send
				h.deliverFrame(requestID, frame)
			}
		}
	}
}

// handleHTTPRequest streams raw bytes between WebSocket frames and backend TCP connection
// This is a "dumb pipe" - no HTTP parsing, just byte streaming
func (h *Handler) handleHTTPRequest(requestID string, frameCh <-chan []byte) {
	defer func() {
		h.handlerMu.Lock()
		state, exists := h.requestHandlers[requestID]
		if exists {
			delete(h.requestHandlers, requestID)
		}
		h.handlerMu.Unlock()

		// Close done channel to unblock any pending deliverFrame calls
		if exists {
			close(state.done)
		}

		// Release semaphore slot
		if h.requestSemaphore != nil {
			<-h.requestSemaphore
		}
	}()

	// Create child logger with requestID context
	reqLogger := h.logger.With().Str("requestID", requestID).Logger()
	reqLogger.Debug().Msg("Handling request")

	// Track in-flight requests for graceful shutdown
	if h.requestTracker != nil {
		h.requestTracker.IncrementRequests()
		defer h.requestTracker.DecrementRequests()
	}

	// Open raw TCP connection to backend
	conn, err := h.dialer.DialTimeout("tcp", h.backendAddr, 5*time.Second)
	if err != nil {
		reqLogger.Error().Err(err).Msg("Failed to connect to backend")
		h.metrics.incrementBackendFailures()
		h.sendErrorResponse(requestID, 502, "Bad Gateway")
		return
	}
	defer conn.Close()

	// Channels for coordination between goroutines
	requestDone := make(chan error, 1)
	responseDone := make(chan struct{})
	requestReleased := make(chan struct{}) // Signaled when server releases the request (client done or disconnected)

	// Goroutine: Stream request frames → backend TCP (no parsing, just write payloads)
	// IMPORTANT: This goroutine must stay alive after receiving FrameTypeEnd to handle
	// potential close frames from server (e.g., when client disconnects or idle timeout
	// fires while backend keeps connection open for HTTP/1.1 keep-alive)
	go func() {
		endReceived := false

		for {
			select {
			case frame, ok := <-frameCh:
				if !ok {
					// Channel closed (WebSocket connection died)
					if !endReceived {
						requestDone <- fmt.Errorf("frame channel closed unexpectedly")
					}
					return
				}

				frameType, _, payload, err := protocol.DecodeFrame(frame)
				if err != nil {
					if !endReceived {
						requestDone <- err
					}
					return
				}

				switch frameType {
				case protocol.FrameTypeStart, protocol.FrameTypeData:
					if endReceived {
						// Ignore data after END (shouldn't happen)
						continue
					}
					// Write payload directly to TCP (raw bytes, no parsing)
					if _, err := conn.Write(payload); err != nil {
						requestDone <- err
						return
					}

				case protocol.FrameTypeEnd:
					errorMsg := string(payload)
					if errorMsg != "" {
						requestDone <- fmt.Errorf("request error: %s", errorMsg)
					} else {
						requestDone <- nil
					}
					endReceived = true
					// DON'T return - continue listening for CANCEL in case backend
					// doesn't close the connection (HTTP/1.1 keep-alive)

				case protocol.FrameTypeCancel:
					reqLogger.Debug().Msg("Released by server")
					close(requestReleased)
					conn.Close() // Close backend connection - unblocks response Read()
					if !endReceived {
						requestDone <- fmt.Errorf("released by server")
					}
					return
				}

			case <-responseDone:
				// Response streaming finished, request goroutine can exit
				return
			}
		}
	}()

	// Main goroutine: Stream backend TCP → response frames (no parsing, just read bytes)
	buffer := make([]byte, 64*1024) // 64KB chunks
	firstChunk := true
	var responseErr error

	for {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buffer[:n])

			// First chunk from backend is FrameTypeStart (contains HTTP headers)
			// Subsequent chunks are FrameTypeData (body bytes)
			var frameType byte
			if firstChunk {
				frameType = protocol.FrameTypeStart
				firstChunk = false
			} else {
				frameType = protocol.FrameTypeData
			}

			frame := protocol.EncodeFrame(frameType, requestID, chunk)
			if err := h.writeFrame(frame); err != nil {
				reqLogger.Error().Err(err).Msg("Failed to send response frame")
				responseErr = err
				break
			}
		}

		if readErr != nil {
			if readErr != io.EOF {
				responseErr = readErr
			}
			break
		}
	}

	// Signal to request goroutine that response streaming is done
	close(responseDone)

	// Check if server released the request
	wasReleased := false
	select {
	case <-requestReleased:
		wasReleased = true
	default:
	}

	// Wait for request streaming to complete with timeout
	// The goroutine should always send, but a defensive timeout prevents indefinite blocking
	// Also listen on h.done to allow fast shutdown when connection closes
	select {
	case reqErr := <-requestDone:
		if reqErr != nil && !wasReleased {
			reqLogger.Error().Err(reqErr).Msg("Request streaming error")
		}
		// If released by server, the error is expected - don't log as error
	case <-h.done:
		// Connection shutting down, exit immediately
		reqLogger.Debug().Msg("Connection closing, abandoning request wait")
	case <-time.After(30 * time.Second):
		reqLogger.Warn().Msg("Timeout waiting for request goroutine to complete")
	}

	// Send end frame
	if responseErr != nil {
		if wasReleased {
			// Connection errors after release are expected - don't log as error
			reqLogger.Debug().Err(responseErr).Msg("Backend connection closed after release")
		} else {
			reqLogger.Error().Err(responseErr).Msg("Backend read error")
		}
		endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(fmt.Sprintf("Backend error: %v", responseErr)))
		h.writeFrame(endFrame)
	} else {
		endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
		h.writeFrame(endFrame)
		reqLogger.Debug().Msg("Completed request")
	}
}

// sendErrorResponse sends an error response to the server
func (h *Handler) sendErrorResponse(requestID string, statusCode int, statusText string) {
	// Minimal HTTP error response
	errorResponse := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", statusCode, statusText)

	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(errorResponse))
	h.writeFrame(startFrame)

	// Send end frame
	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	h.writeFrame(endFrame)
}

func (h *Handler) sendRateLimitResponse(requestID string, limit int) {
	// Track rate limit rejection
	h.metrics.incrementRateLimitRejections()

	msg := fmt.Sprintf("Agent concurrent request limit reached (%d)", limit)
	errorResponse := fmt.Sprintf(
		"HTTP/1.1 429 Too Many Requests\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		len(msg), msg,
	)

	// Send start frame with error response
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(errorResponse))
	h.writeFrame(startFrame)

	// Send end frame
	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	h.writeFrame(endFrame)
}
