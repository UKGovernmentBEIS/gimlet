package agentmgr

import (
	"sync"
	"time"

	"gimlet/protocol"

	"github.com/gorilla/websocket"
)

// requestState holds the channels for a single in-flight request
type requestState struct {
	dataCh chan []byte
	done   chan struct{}
}

// Agent represents a connected agent
type Agent struct {
	ID          string
	ServiceName string
	Conn        protocol.WebSocketConn
	requests    map[string]*requestState // requestID -> request state
	RespLock    sync.Mutex
	WriteLock   sync.Mutex
	Ready       bool // Whether agent is ready to accept new requests
	ReadyLock   sync.RWMutex

	// Agent-reported metrics (updated periodically via metrics messages)
	Metrics     AgentMetrics
	MetricsLock sync.RWMutex
}

// AgentMetrics holds metrics reported by the agent
type AgentMetrics struct {
	RateLimitRejections     int64
	ConcurrentRequests      int
	RequestChannelBuffer    int
	BackendFailures         int64
	FramesSent              map[string]int64
	FramesReceived          map[string]int64
	WebsocketWriteErrors    int64
	Draining                bool
	ConnectionUptimeSeconds int64
	LastUpdate              time.Time
}

// HelloMessage is sent to agent on connection
type HelloMessage struct {
	ServerID    string `json:"server_id"`
	AgentID     string `json:"agent_id"`
	ServiceName string `json:"service_name"`
}

// NewAgent creates a new agent instance
func NewAgent(id, serviceName string, conn protocol.WebSocketConn) *Agent {
	return &Agent{
		ID:          id,
		ServiceName: serviceName,
		Conn:        conn,
		requests:    make(map[string]*requestState),
		Ready:       false, // Agent must explicitly signal ready
	}
}

// GetLoad returns the current number of active requests (thread-safe)
func (a *Agent) GetLoad() int {
	a.RespLock.Lock()
	defer a.RespLock.Unlock()
	return len(a.requests)
}

// SendHTTPRequestStart sends the HTTP request start frame (headers only)
func (a *Agent) SendHTTPRequestStart(requestID string, httpHeaders []byte) error {
	frame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, httpHeaders)

	a.WriteLock.Lock()
	err := a.Conn.WriteMessage(websocket.BinaryMessage, frame)
	a.WriteLock.Unlock()

	return err
}

// SendHTTPRequestData sends an HTTP request body chunk
func (a *Agent) SendHTTPRequestData(requestID string, chunk []byte) error {
	frame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, chunk)

	a.WriteLock.Lock()
	err := a.Conn.WriteMessage(websocket.BinaryMessage, frame)
	a.WriteLock.Unlock()

	return err
}

// SendHTTPRequestEnd signals end of request (success or error)
func (a *Agent) SendHTTPRequestEnd(requestID string, errorMsg string) error {
	frame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(errorMsg))

	a.WriteLock.Lock()
	err := a.Conn.WriteMessage(websocket.BinaryMessage, frame)
	a.WriteLock.Unlock()

	return err
}

// SendHTTPRequestCancel signals that the request was cancelled (client disconnect)
func (a *Agent) SendHTTPRequestCancel(requestID string) error {
	frame := protocol.EncodeFrame(protocol.FrameTypeCancel, requestID, []byte{})

	a.WriteLock.Lock()
	err := a.Conn.WriteMessage(websocket.BinaryMessage, frame)
	a.WriteLock.Unlock()

	return err
}

// RegisterResponseChannel creates a channel for receiving response frames
func (a *Agent) RegisterResponseChannel(requestID string, bufferSize int) chan []byte {
	state := &requestState{
		dataCh: make(chan []byte, bufferSize),
		done:   make(chan struct{}),
	}

	a.RespLock.Lock()
	a.requests[requestID] = state
	a.RespLock.Unlock()

	return state.dataCh
}

// DeliverResponseFrame delivers a response frame to the waiting channel.
// Returns false if the request doesn't exist or has been cleaned up.
func (a *Agent) DeliverResponseFrame(requestID string, frame []byte) bool {
	a.RespLock.Lock()
	state, exists := a.requests[requestID]
	a.RespLock.Unlock()

	if !exists {
		return false
	}

	// Use select to either deliver the frame or detect cleanup.
	// This avoids panic/recover by using the done channel as a cancellation signal.
	select {
	case state.dataCh <- frame:
		return true
	case <-state.done:
		// Request was cleaned up while we were waiting to send
		return false
	}
}

// CleanupRequest removes a response channel and closes it
func (a *Agent) CleanupRequest(requestID string) {
	a.RespLock.Lock()
	state, exists := a.requests[requestID]
	if exists {
		delete(a.requests, requestID)
	}
	a.RespLock.Unlock()

	if exists {
		// Close done first to unblock any pending DeliverResponseFrame calls
		close(state.done)
		// Then close the data channel to signal receivers
		close(state.dataCh)
	}
}

// IsReady returns whether the agent is ready to accept new requests
func (a *Agent) IsReady() bool {
	a.ReadyLock.RLock()
	defer a.ReadyLock.RUnlock()
	return a.Ready
}

// SetReady sets the agent's readiness state
func (a *Agent) SetReady(ready bool) {
	a.ReadyLock.Lock()
	defer a.ReadyLock.Unlock()
	a.Ready = ready
}

// GetBufferUsage returns the total number of buffered frames across all active requests
func (a *Agent) GetBufferUsage() int {
	a.RespLock.Lock()
	defer a.RespLock.Unlock()

	totalBuffered := 0
	for _, state := range a.requests {
		totalBuffered += len(state.dataCh)
	}
	return totalBuffered
}

// CleanupAllRequests closes all pending request channels and returns the count.
// Used when agent disconnects to clean up all in-flight requests.
func (a *Agent) CleanupAllRequests() int {
	a.RespLock.Lock()
	pendingCount := len(a.requests)
	// Collect all states to close outside the lock
	states := make([]*requestState, 0, pendingCount)
	for _, state := range a.requests {
		states = append(states, state)
	}
	// Clear the map
	a.requests = make(map[string]*requestState)
	a.RespLock.Unlock()

	// Close all channels outside the lock
	for _, state := range states {
		close(state.done)
		close(state.dataCh)
	}

	return pendingCount
}
