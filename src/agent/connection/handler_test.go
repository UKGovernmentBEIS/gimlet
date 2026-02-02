package connection

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gimlet/protocol"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// TestAgentRateLimitInit tests semaphore initialization with different limits
func TestAgentRateLimitInit(t *testing.T) {
	tests := []struct {
		name             string
		maxConcurrent    int
		expectSemaphore  bool
		expectedCapacity int
	}{
		{
			name:             "limit enabled",
			maxConcurrent:    5,
			expectSemaphore:  true,
			expectedCapacity: 5,
		},
		{
			name:             "limit disabled (0)",
			maxConcurrent:    0,
			expectSemaphore:  false,
			expectedCapacity: 0,
		},
		{
			name:             "large limit",
			maxConcurrent:    100,
			expectSemaphore:  true,
			expectedCapacity: 100,
		},
		{
			name:             "limit of 1",
			maxConcurrent:    1,
			expectSemaphore:  true,
			expectedCapacity: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create semaphore externally (simulating AgentState initialization)
			var semaphore chan struct{}
			if tt.maxConcurrent > 0 {
				semaphore = make(chan struct{}, tt.maxConcurrent)
			}

			handler := NewHandler(nil, "backend:80", &protocol.DefaultTCPDialer{}, nil, zerolog.New(io.Discard), tt.maxConcurrent, semaphore, 10)

			if tt.expectSemaphore {
				if handler.requestSemaphore == nil {
					t.Error("Expected semaphore to be initialized but it was nil")
				} else if cap(handler.requestSemaphore) != tt.expectedCapacity {
					t.Errorf("Expected semaphore capacity %d, got %d",
						tt.expectedCapacity, cap(handler.requestSemaphore))
				}
			} else {
				if handler.requestSemaphore != nil {
					t.Error("Expected semaphore to be nil when limit is 0")
				}
			}

			// Verify maxConcurrentRequests field is set correctly
			if handler.maxConcurrentRequests != tt.maxConcurrent {
				t.Errorf("Expected maxConcurrentRequests %d, got %d",
					tt.maxConcurrent, handler.maxConcurrentRequests)
			}
		})
	}
}

// TestSemaphoreAcquireRelease tests basic semaphore acquire and release behavior
func TestSemaphoreAcquireRelease(t *testing.T) {
	semaphore := make(chan struct{}, 2)
	handler := NewHandler(nil, "backend:80", &protocol.DefaultTCPDialer{}, nil, zerolog.New(io.Discard), 2, semaphore, 10)

	if handler.requestSemaphore == nil {
		t.Fatal("Semaphore not initialized")
	}

	// Acquire 2 slots
	select {
	case handler.requestSemaphore <- struct{}{}:
	default:
		t.Fatal("Failed to acquire first slot")
	}

	select {
	case handler.requestSemaphore <- struct{}{}:
	default:
		t.Fatal("Failed to acquire second slot")
	}

	// Third should fail (would block if using blocking send)
	select {
	case handler.requestSemaphore <- struct{}{}:
		t.Fatal("Should not be able to acquire third slot")
	default:
		// Expected - semaphore is full
	}

	// Release one slot
	<-handler.requestSemaphore

	// Now should be able to acquire again
	select {
	case handler.requestSemaphore <- struct{}{}:
	default:
		t.Fatal("Should be able to acquire slot after release")
	}

	// Verify still at capacity
	select {
	case handler.requestSemaphore <- struct{}{}:
		t.Fatal("Should not exceed capacity after release and re-acquire")
	default:
		// Expected
	}
}

// TestSemaphoreWithZeroLimit tests that no semaphore is created when limit is 0
func TestSemaphoreWithZeroLimit(t *testing.T) {
	handler := NewHandler(nil, "backend:80", &protocol.DefaultTCPDialer{}, nil, zerolog.New(io.Discard), 0, nil, 10)

	if handler.requestSemaphore != nil {
		t.Error("Semaphore should be nil when limit is 0 (unlimited)")
	}

	if handler.maxConcurrentRequests != 0 {
		t.Errorf("Expected maxConcurrentRequests to be 0, got %d", handler.maxConcurrentRequests)
	}
}

// mockWebSocketConn implements WebSocketConn for testing
type mockWebSocketConn struct {
	mu             sync.Mutex
	writtenFrames  [][]byte
	readMessages   [][]byte
	readIndex      int
	readCh         chan []byte // For async message delivery
	closed         bool
	closeErr       error
	jsonMessages   []interface{}
}

func newMockWebSocketConn() *mockWebSocketConn {
	return &mockWebSocketConn{
		readCh: make(chan []byte, 100),
	}
}

func (m *mockWebSocketConn) ReadJSON(v interface{}) error {
	return nil
}

func (m *mockWebSocketConn) WriteJSON(v interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jsonMessages = append(m.jsonMessages, v)
	return nil
}

func (m *mockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	msg, ok := <-m.readCh
	if !ok {
		return 0, nil, io.EOF
	}
	return websocket.BinaryMessage, msg, nil
}

func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return m.closeErr
	}
	m.writtenFrames = append(m.writtenFrames, data)
	return nil
}

func (m *mockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
	return nil
}

func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockWebSocketConn) sendFrame(frame []byte) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if !closed {
		m.readCh <- frame
	}
}

func (m *mockWebSocketConn) getWrittenFrames() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]byte, len(m.writtenFrames))
	copy(result, m.writtenFrames)
	return result
}

// mockRequestTracker implements RequestTracker for testing
type mockRequestTracker struct {
	count int32
}

func (m *mockRequestTracker) IncrementRequests() {
	atomic.AddInt32(&m.count, 1)
}

func (m *mockRequestTracker) DecrementRequests() {
	atomic.AddInt32(&m.count, -1)
}

func (m *mockRequestTracker) Count() int32 {
	return atomic.LoadInt32(&m.count)
}

// TestCancelAfterEndProcessed tests that CANCEL frames are processed after END
// This is the key fix: the request goroutine must stay alive after END to handle CANCEL
func TestCancelAfterEndProcessed(t *testing.T) {
	// Start a mock backend that doesn't close after sending response
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Track backend connections
	backendConnClosed := make(chan struct{})

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}

		// Read request from agent
		buf := make([]byte, 1024)
		conn.Read(buf)

		// Send response but DON'T close - simulating HTTP/1.1 keep-alive
		response := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
		conn.Write([]byte(response))

		// Wait for connection to be closed by agent (via CANCEL)
		conn.Read(buf) // This will return when agent closes connection
		close(backendConnClosed)
	}()

	// Create mock WebSocket connection
	mockWS := newMockWebSocketConn()
	tracker := &mockRequestTracker{}
	semaphore := make(chan struct{}, 10)

	handler := NewHandler(mockWS, backendAddr, &protocol.DefaultTCPDialer{}, tracker, zerolog.New(io.Discard), 10, semaphore, 10)

	// Start handler in background
	handlerDone := make(chan struct{})
	go func() {
		handler.Run()
		close(handlerDone)
	}()

	requestID := "test-request-123"

	// Send START frame with HTTP request
	httpRequest := "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(httpRequest))
	mockWS.sendFrame(startFrame)

	// Send END frame - request complete
	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	mockWS.sendFrame(endFrame)

	// Wait a bit for response to be sent
	time.Sleep(100 * time.Millisecond)

	// Verify we received response frames
	frames := mockWS.getWrittenFrames()
	if len(frames) == 0 {
		t.Fatal("Expected response frames from agent")
	}

	// Now send CANCEL frame (simulating server detecting client closure)
	cancelFrame := protocol.EncodeFrame(protocol.FrameTypeCancel, requestID, []byte(""))
	mockWS.sendFrame(cancelFrame)

	// Wait for backend connection to be closed
	select {
	case <-backendConnClosed:
		// Success - CANCEL was processed and backend connection was closed
	case <-time.After(2 * time.Second):
		t.Fatal("Backend connection was not closed after CANCEL - request goroutine may have exited after END")
	}

	// Give the request handler time to fully clean up after backend closes
	time.Sleep(100 * time.Millisecond)

	// Clean up
	mockWS.Close()
	<-handlerDone

	// Verify request tracker shows 0 in-flight requests
	// Allow a brief moment for final cleanup
	time.Sleep(50 * time.Millisecond)
	if tracker.Count() != 0 {
		t.Errorf("Expected 0 in-flight requests, got %d", tracker.Count())
	}
}

// TestCancelBeforeEndProcessed tests that CANCEL works when received before END
func TestCancelBeforeEndProcessed(t *testing.T) {
	// Start a mock backend
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()
	backendConnClosed := make(chan struct{})

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}

		// Wait for connection to be closed by agent
		buf := make([]byte, 1024)
		conn.Read(buf) // Blocks until closed
		close(backendConnClosed)
	}()

	// Create mock WebSocket connection
	mockWS := newMockWebSocketConn()
	tracker := &mockRequestTracker{}
	semaphore := make(chan struct{}, 10)

	handler := NewHandler(mockWS, backendAddr, &protocol.DefaultTCPDialer{}, tracker, zerolog.New(io.Discard), 10, semaphore, 10)

	// Start handler in background
	handlerDone := make(chan struct{})
	go func() {
		handler.Run()
		close(handlerDone)
	}()

	requestID := "test-request-456"

	// Send START frame with partial HTTP request
	httpRequest := "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(httpRequest))
	mockWS.sendFrame(startFrame)

	// Wait a bit for request to start processing
	time.Sleep(50 * time.Millisecond)

	// Send CANCEL before END (simulating client disconnect during upload)
	cancelFrame := protocol.EncodeFrame(protocol.FrameTypeCancel, requestID, []byte(""))
	mockWS.sendFrame(cancelFrame)

	// Wait for backend connection to be closed
	select {
	case <-backendConnClosed:
		// Success - CANCEL was processed
	case <-time.After(2 * time.Second):
		t.Fatal("Backend connection was not closed after CANCEL")
	}

	// Clean up
	mockWS.Close()
	<-handlerDone
}

// TestResponseDoneSignalsRequestGoroutine tests that when response streaming
// finishes normally (EOF from backend), the request goroutine also exits cleanly
func TestResponseDoneSignalsRequestGoroutine(t *testing.T) {
	// Start a mock backend that closes after sending response (normal behavior)
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}

		// Read request
		buf := make([]byte, 1024)
		conn.Read(buf)

		// Send response and close (normal HTTP behavior with Connection: close)
		response := "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello"
		conn.Write([]byte(response))
		conn.Close()
	}()

	// Create mock WebSocket connection
	mockWS := newMockWebSocketConn()
	tracker := &mockRequestTracker{}
	semaphore := make(chan struct{}, 10)

	handler := NewHandler(mockWS, backendAddr, &protocol.DefaultTCPDialer{}, tracker, zerolog.New(io.Discard), 10, semaphore, 10)

	// Start handler in background
	handlerDone := make(chan struct{})
	go func() {
		handler.Run()
		close(handlerDone)
	}()

	requestID := "test-request-789"

	// Send full request
	httpRequest := "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(httpRequest))
	mockWS.sendFrame(startFrame)

	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	mockWS.sendFrame(endFrame)

	// Wait for response to complete
	time.Sleep(200 * time.Millisecond)

	// Verify we received response frames including END
	frames := mockWS.getWrittenFrames()
	if len(frames) < 2 {
		t.Fatalf("Expected at least 2 frames (start + end), got %d", len(frames))
	}

	// Check last frame is END
	lastFrame := frames[len(frames)-1]
	frameType, _, _, err := protocol.DecodeFrame(lastFrame)
	if err != nil {
		t.Fatalf("Failed to decode last frame: %v", err)
	}
	if frameType != protocol.FrameTypeEnd {
		t.Errorf("Expected last frame to be END (0x%02x), got 0x%02x", protocol.FrameTypeEnd, frameType)
	}

	// Clean up
	mockWS.Close()
	<-handlerDone

	// Verify clean exit
	if tracker.Count() != 0 {
		t.Errorf("Expected 0 in-flight requests after completion, got %d", tracker.Count())
	}
}

// TestDeliverFrameRaceSafety tests that deliverFrame handles the race condition
// where a handler exits between checking existence and sending to the channel.
// This verifies the done channel pattern prevents blocking/panics.
func TestDeliverFrameRaceSafety(t *testing.T) {
	handler := NewHandler(nil, "backend:80", &protocol.DefaultTCPDialer{}, nil, zerolog.New(io.Discard), 0, nil, 10)

	requestID := "test-request-123"

	// Manually create a request state (simulating what Run() does)
	state := &requestState{
		dataCh: make(chan []byte, 10),
		done:   make(chan struct{}),
	}
	handler.handlerMu.Lock()
	handler.requestHandlers[requestID] = state
	handler.handlerMu.Unlock()

	// Verify delivery works normally
	testFrame := []byte("test-frame-data")
	delivered := handler.deliverFrame(requestID, testFrame)
	if !delivered {
		t.Error("Expected frame to be delivered successfully")
	}

	// Verify frame was received
	select {
	case frame := <-state.dataCh:
		if string(frame) != string(testFrame) {
			t.Errorf("Expected frame %q, got %q", testFrame, frame)
		}
	default:
		t.Error("Expected frame in channel")
	}

	// Now simulate handler cleanup - close done channel and remove from map
	handler.handlerMu.Lock()
	delete(handler.requestHandlers, requestID)
	handler.handlerMu.Unlock()
	close(state.done)

	// Try to deliver after cleanup - should return false, not block or panic
	done := make(chan bool, 1)
	go func() {
		result := handler.deliverFrame(requestID, testFrame)
		done <- result
	}()

	select {
	case result := <-done:
		if result {
			t.Error("Expected delivery to fail after cleanup")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("deliverFrame blocked - done channel pattern not working")
	}
}

// slowWriteConn wraps a net.Conn to delay writes, simulating a slow backend
type slowWriteConn struct {
	net.Conn
	writeDelay   time.Duration
	writeCalled  chan struct{}
	allowWrite   chan struct{}
	bytesWritten int
	mu           sync.Mutex
}

func (s *slowWriteConn) Write(b []byte) (int, error) {
	// Signal that write was called
	select {
	case s.writeCalled <- struct{}{}:
	default:
	}

	// Wait for permission to complete (or timeout)
	select {
	case <-s.allowWrite:
	case <-time.After(s.writeDelay):
	}

	s.mu.Lock()
	s.bytesWritten += len(b)
	s.mu.Unlock()

	return s.Conn.Write(b)
}

// slowWriteDialer returns connections that delay writes
type slowWriteDialer struct {
	listener     net.Listener
	writeDelay   time.Duration
	lastConn     *slowWriteConn
	writeCalled  chan struct{}
	allowWrite   chan struct{}
	mu           sync.Mutex
}

func (d *slowWriteDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, d.listener.Addr().String(), timeout)
	if err != nil {
		return nil, err
	}

	slowConn := &slowWriteConn{
		Conn:        conn,
		writeDelay:  d.writeDelay,
		writeCalled: d.writeCalled,
		allowWrite:  d.allowWrite,
	}

	d.mu.Lock()
	d.lastConn = slowConn
	d.mu.Unlock()

	return slowConn, nil
}

// TestResponseDoneRaceCondition tests the race condition where response streaming
// completes while the request goroutine is blocked on conn.Write() with an END
// frame buffered. Without the fix, this would cause a 30s timeout wait.
// This is a regression test for the "Timeout waiting for request goroutine to complete" issue.
func TestResponseDoneRaceCondition(t *testing.T) {
	// Create a backend that:
	// 1. Accepts connection
	// 2. Waits to read (so agent's conn.Write blocks due to TCP backpressure)
	// 3. Eventually reads and sends response
	// 4. Closes connection (triggers responseDone)
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer backendListener.Close()

	backendConnected := make(chan struct{})
	backendAllowRead := make(chan struct{})
	backendDone := make(chan struct{})

	go func() {
		defer close(backendDone)
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Signal that connection was accepted
		close(backendConnected)

		// Wait before reading - this causes TCP backpressure on agent's writes
		<-backendAllowRead

		// Read the request
		buf := make([]byte, 4096)
		conn.Read(buf)

		// Send response and close immediately (triggers responseDone on agent)
		response := "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
		conn.Write([]byte(response))
	}()

	// Create channels for coordinating the slow write
	writeCalled := make(chan struct{}, 10)
	allowWrite := make(chan struct{})

	dialer := &slowWriteDialer{
		listener:    backendListener,
		writeDelay:  10 * time.Second, // Long delay to ensure we control timing
		writeCalled: writeCalled,
		allowWrite:  allowWrite,
	}

	mockWS := newMockWebSocketConn()
	tracker := &mockRequestTracker{}
	semaphore := make(chan struct{}, 10)

	handler := NewHandler(mockWS, backendListener.Addr().String(), dialer, tracker, zerolog.New(io.Discard), 10, semaphore, 100)

	// Start handler
	handlerDone := make(chan struct{})
	go func() {
		handler.Run()
		close(handlerDone)
	}()

	requestID := "race-test-request"

	// Send START frame with a request body - this triggers the dial to backend
	httpRequest := "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(httpRequest))
	mockWS.sendFrame(startFrame)

	// Wait for backend to accept connection (dial happened)
	select {
	case <-backendConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for backend connection")
	}

	// Wait for the first write to be called (START frame payload being written)
	select {
	case <-writeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for first write")
	}

	// Now send DATA frame - this will also try to write to blocked backend
	dataFrame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte("some request body data"))
	mockWS.sendFrame(dataFrame)

	// Give time for DATA to be queued
	time.Sleep(50 * time.Millisecond)

	// Send END frame - this gets BUFFERED in frameCh while request goroutine is blocked
	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	mockWS.sendFrame(endFrame)

	// Give time for END to be buffered
	time.Sleep(50 * time.Millisecond)

	// Now unblock the backend reads AND allow writes to complete
	close(backendAllowRead)
	close(allowWrite)

	// The backend will now:
	// 1. Read the request
	// 2. Send response
	// 3. Close connection
	// This triggers responseDone on the agent

	// Wait for backend to finish
	<-backendDone

	// KEY ASSERTION: The handler should complete quickly, NOT wait 30 seconds
	// If the fix is not in place, this would timeout after 30+ seconds
	cleanupStart := time.Now()

	// Close the WebSocket to trigger handler shutdown
	time.Sleep(100 * time.Millisecond)
	mockWS.Close()

	select {
	case <-handlerDone:
		cleanupDuration := time.Since(cleanupStart)
		// Should complete well under 5 seconds (the short timeout path)
		// With the fix, it should be nearly instant
		if cleanupDuration > 3*time.Second {
			t.Errorf("Handler took too long to clean up (%v) - possible timeout path hit", cleanupDuration)
		}
		t.Logf("Handler cleanup completed in %v", cleanupDuration)
	case <-time.After(35 * time.Second):
		t.Fatal("Handler did not exit - likely stuck in 30s timeout wait (race condition not fixed)")
	}

	// Verify request tracker is clean
	if tracker.Count() != 0 {
		t.Errorf("Expected 0 in-flight requests, got %d", tracker.Count())
	}
}

// TestDeliverFrameDoneChannelUnblocks tests that closing the done channel
// unblocks a pending deliverFrame call (simulates handler exit during delivery).
func TestDeliverFrameDoneChannelUnblocks(t *testing.T) {
	handler := NewHandler(nil, "backend:80", &protocol.DefaultTCPDialer{}, nil, zerolog.New(io.Discard), 0, nil, 1) // buffer size 1

	requestID := "test-request-456"

	// Create state with small buffer
	state := &requestState{
		dataCh: make(chan []byte, 1),
		done:   make(chan struct{}),
	}
	handler.handlerMu.Lock()
	handler.requestHandlers[requestID] = state
	handler.handlerMu.Unlock()

	// Fill the buffer
	state.dataCh <- []byte("frame1")

	// Start a goroutine that will block trying to deliver (buffer full)
	deliveryDone := make(chan bool, 1)
	go func() {
		result := handler.deliverFrame(requestID, []byte("frame2"))
		deliveryDone <- result
	}()

	// Give it a moment to start blocking
	time.Sleep(10 * time.Millisecond)

	// Close the done channel (simulates handler exit)
	close(state.done)

	// The blocked delivery should now return false
	select {
	case result := <-deliveryDone:
		if result {
			t.Error("Expected delivery to fail when done channel closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("deliverFrame did not unblock when done channel closed")
	}
}
