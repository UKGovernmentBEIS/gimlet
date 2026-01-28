package agentmgr

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"gimlet/protocol"

	"github.com/gorilla/websocket"
)

// MockWebSocketConn for testing
type MockWebSocketConn struct {
	mu           sync.Mutex
	writeCalls   []interface{}
	binaryWrites [][]byte
	writeErrors  []error
	writeDelay   time.Duration
	closed       bool
}

func NewMockWebSocketConn() *MockWebSocketConn {
	return &MockWebSocketConn{
		writeCalls:   make([]interface{}, 0),
		binaryWrites: make([][]byte, 0),
	}
}

func (m *MockWebSocketConn) ReadJSON(v interface{}) error {
	return fmt.Errorf("not implemented in mock")
}

func (m *MockWebSocketConn) WriteJSON(v interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeDelay > 0 {
		time.Sleep(m.writeDelay)
	}

	m.writeCalls = append(m.writeCalls, v)

	if len(m.writeErrors) > 0 {
		err := m.writeErrors[0]
		m.writeErrors = m.writeErrors[1:]
		return err
	}

	return nil
}

func (m *MockWebSocketConn) ReadMessage() (int, []byte, error) {
	return 0, nil, fmt.Errorf("not implemented in mock")
}

func (m *MockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeDelay > 0 {
		time.Sleep(m.writeDelay)
	}

	if messageType == websocket.BinaryMessage {
		m.binaryWrites = append(m.binaryWrites, data)
	}

	if len(m.writeErrors) > 0 {
		err := m.writeErrors[0]
		m.writeErrors = m.writeErrors[1:]
		return err
	}

	return nil
}

func (m *MockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *MockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil // Mock implementation, no-op for tests
}

func (m *MockWebSocketConn) WriteCalls() []interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]interface{}{}, m.writeCalls...)
}

func (m *MockWebSocketConn) BinaryWrites() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte{}, m.binaryWrites...)
}

func (m *MockWebSocketConn) WriteCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.writeCalls)
}

func (m *MockWebSocketConn) BinaryWriteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.binaryWrites)
}

// TestAgentConcurrentFrameWrites tests that multiple goroutines can write binary frames to an agent without data races
func TestAgentConcurrentFrameWrites(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	numRequests := 100
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	// Fire 100 concurrent SendHTTPRequestStart calls
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestID := fmt.Sprintf("req-%d", id)
			headers := []byte(fmt.Sprintf("GET /test HTTP/1.1\r\nHost: backend\r\n\r\n"))
			err := agent.SendHTTPRequestStart(requestID, headers)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent write failed: %v", err)
	}

	// Verify all writes succeeded
	writeCount := mock.BinaryWriteCount()
	if writeCount != numRequests {
		t.Errorf("Expected %d binary writes, got %d", numRequests, writeCount)
	}
}

// TestAgentConcurrentResponseDelivery tests handling concurrent response frame delivery
func TestAgentConcurrentResponseDelivery(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	numRequests := 50

	// Register response channels for all requests
	channels := make([]chan []byte, numRequests)
	for i := 0; i < numRequests; i++ {
		requestID := fmt.Sprintf("req-%d", i)
		channels[i] = agent.RegisterResponseChannel(requestID, 10)
	}

	// Fire concurrent frame deliveries
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestID := fmt.Sprintf("req-%d", id)

			// Create response start frame
			responseHeaders := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, responseHeaders)

			if !agent.DeliverResponseFrame(requestID, startFrame) {
				t.Errorf("Failed to deliver response frame for request %d", id)
			}

			// Cleanup after delivery
			agent.CleanupRequest(requestID)
		}(i)
	}

	// Wait for all responses to be delivered
	wg.Wait()

	// Verify all channels received frames
	for i, ch := range channels {
		select {
		case frame := <-ch:
			frameType, _, _, err := protocol.DecodeFrame(frame)
			if err != nil {
				t.Errorf("Failed to decode frame for request %d: %v", i, err)
			}
			if frameType != protocol.FrameTypeStart {
				t.Errorf("Expected FrameTypeStart, got %d", frameType)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("Timeout waiting for response %d", i)
		}
	}

	// Verify all channels were cleaned up
	agent.RespLock.Lock()
	pendingCount := len(agent.requests)
	agent.RespLock.Unlock()
	if pendingCount != 0 {
		t.Errorf("Expected 0 pending requests after responses, got %d", pendingCount)
	}
}

// TestAgentRequestCleanup tests that request cleanup works correctly
func TestAgentRequestCleanup(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	// Register channel
	ch := agent.RegisterResponseChannel("timeout-req", 10)

	// Verify channel exists
	agent.RespLock.Lock()
	pendingCount := len(agent.requests)
	agent.RespLock.Unlock()
	if pendingCount != 1 {
		t.Fatalf("Expected 1 pending request, got %d", pendingCount)
	}

	// Cleanup
	agent.CleanupRequest("timeout-req")

	// Verify channel was removed and closed
	agent.RespLock.Lock()
	pendingCount = len(agent.requests)
	agent.RespLock.Unlock()
	if pendingCount != 0 {
		t.Errorf("Expected 0 pending requests after cleanup, got %d", pendingCount)
	}

	// Verify channel is closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Channel should be closed after cleanup")
		}
	case <-time.After(10 * time.Millisecond):
		t.Error("Expected channel to be closed")
	}

	// Late response should not crash or block
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, "timeout-req", []byte("HTTP/1.1 200 OK\r\n\r\n"))
	found := agent.DeliverResponseFrame("timeout-req", startFrame)
	if found {
		t.Error("DeliverResponseFrame should return false for cleaned up request")
	}
}

// TestAgentWriteErrorHandling tests that write errors are handled properly
func TestAgentWriteErrorHandling(t *testing.T) {
	mock := NewMockWebSocketConn()
	mock.writeErrors = []error{fmt.Errorf("connection closed")}

	agent := NewAgent("test-agent", "test-service", mock)

	headers := []byte("GET /test HTTP/1.1\r\nHost: backend\r\n\r\n")
	err := agent.SendHTTPRequestStart("error-req", headers)

	if err == nil {
		t.Error("Expected error from SendHTTPRequestStart, got nil")
	}
}

// TestAgentConcurrentMixed tests mixed concurrent operations
func TestAgentConcurrentMixed(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	var wg sync.WaitGroup
	numOps := 30

	// Concurrent frame sends and channel registration
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestID := fmt.Sprintf("req-%d", id)
			headers := []byte(fmt.Sprintf("GET /test HTTP/1.1\r\nHost: backend\r\n\r\n"))
			agent.SendHTTPRequestStart(requestID, headers)

			// Also register response channel
			agent.RegisterResponseChannel(requestID, 10)
		}(i)
	}

	// Wait for all registrations to complete before delivering frames
	wg.Wait()

	// Concurrent frame deliveries
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestID := fmt.Sprintf("req-%d", id)
			startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte("HTTP/1.1 200 OK\r\n\r\n"))
			agent.DeliverResponseFrame(requestID, startFrame)
		}(i)
	}

	// Wait for all deliveries to complete before cleanup
	wg.Wait()

	// Sequential cleanup after deliveries are done (no race)
	for i := 0; i < numOps; i++ {
		agent.CleanupRequest(fmt.Sprintf("req-%d", i))
	}

	// After all operations, pending count should be 0
	agent.RespLock.Lock()
	count := len(agent.requests)
	agent.RespLock.Unlock()
	if count != 0 {
		t.Errorf("Expected 0 pending requests after cleanup, got %d", count)
	}
}

// TestAgentReadinessState tests agent readiness state transitions
func TestAgentReadinessState(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	// Agent should start as not ready
	if agent.IsReady() {
		t.Error("Agent should start as not ready")
	}

	// Mark as ready
	agent.SetReady(true)
	if !agent.IsReady() {
		t.Error("Agent should be ready after SetReady(true)")
	}

	// Mark as draining (not ready)
	agent.SetReady(false)
	if agent.IsReady() {
		t.Error("Agent should not be ready after SetReady(false)")
	}
}

// TestAgentReadinessConcurrent tests concurrent readiness state changes
func TestAgentReadinessConcurrent(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	var wg sync.WaitGroup
	numOps := 100

	// Concurrent readers
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agent.IsReady()
		}()
	}

	// Concurrent writers (toggle state)
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agent.SetReady(id%2 == 0)
		}(i)
	}

	wg.Wait()

	// Should not panic or deadlock - exact final state is non-deterministic
	// but that's ok, we're testing thread-safety
	_ = agent.IsReady()
}

// TestFrameEncoding tests binary frame encoding and decoding
func TestFrameEncoding(t *testing.T) {
	testCases := []struct {
		name      string
		frameType byte
		requestID string
		payload   []byte
	}{
		{"start frame", protocol.FrameTypeStart, "req-123", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"data frame", protocol.FrameTypeData, "req-456", []byte("some body data")},
		{"end frame empty", protocol.FrameTypeEnd, "req-789", []byte("")},
		{"end frame with error", protocol.FrameTypeEnd, "req-999", []byte("connection timeout")},
		{"long request ID", protocol.FrameTypeStart, "very-long-request-id-0123456789abcdef", []byte("test")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := protocol.EncodeFrame(tc.frameType, tc.requestID, tc.payload)

			// Decode
			decodedType, decodedID, decodedPayload, err := protocol.DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("DecodeFrame failed: %v", err)
			}

			// Verify
			if decodedType != tc.frameType {
				t.Errorf("Frame type mismatch: expected %d, got %d", tc.frameType, decodedType)
			}
			if decodedID != tc.requestID {
				t.Errorf("Request ID mismatch: expected %q, got %q", tc.requestID, decodedID)
			}
			if string(decodedPayload) != string(tc.payload) {
				t.Errorf("Payload mismatch: expected %q, got %q", tc.payload, decodedPayload)
			}
		})
	}
}

// TestFrameDecodingErrors tests error handling in frame decoding
func TestFrameDecodingErrors(t *testing.T) {
	testCases := []struct {
		name  string
		frame []byte
	}{
		{"empty frame", []byte{}},
		{"too short", []byte{0x01, 0x00}},
		{"truncated ID length", []byte{0x01, 0x00, 0x00, 0x00}},
		{"truncated ID", []byte{0x01, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}}, // Says 5 bytes, only has 2
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := protocol.DecodeFrame(tc.frame)
			if err == nil {
				t.Error("Expected error for malformed frame, got nil")
			}
		})
	}
}

// TestBackpressureBlocking tests that DeliverResponseFrame blocks instead of dropping frames
func TestBackpressureBlocking(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	// Use small buffer to trigger backpressure quickly
	bufferSize := 3
	requestID := "backpressure-test"
	ch := agent.RegisterResponseChannel(requestID, bufferSize)

	// Fill the buffer completely
	for i := 0; i < bufferSize; i++ {
		frame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte(fmt.Sprintf("frame-%d", i)))
		success := agent.DeliverResponseFrame(requestID, frame)
		if !success {
			t.Fatalf("Failed to deliver frame %d to buffer", i)
		}
	}

	// Verify buffer is full
	if len(ch) != bufferSize {
		t.Fatalf("Expected buffer to be full (%d), got %d", bufferSize, len(ch))
	}

	// Try to send one more frame - this should block
	extraFrame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte("extra-frame"))

	deliveryComplete := make(chan bool, 1)
	go func() {
		// This should block until we start consuming
		agent.DeliverResponseFrame(requestID, extraFrame)
		deliveryComplete <- true
	}()

	// Wait a bit to ensure goroutine is blocked
	time.Sleep(50 * time.Millisecond)

	select {
	case <-deliveryComplete:
		t.Fatal("DeliverResponseFrame should have blocked but returned immediately")
	default:
		// Good - it's blocking as expected
	}

	// Now start consuming frames
	framesReceived := make([][]byte, 0)
	for i := 0; i < bufferSize; i++ {
		frame := <-ch
		framesReceived = append(framesReceived, frame)
	}

	// Wait for the blocked delivery to complete
	select {
	case <-deliveryComplete:
		// Good - delivery unblocked after we consumed
	case <-time.After(1 * time.Second):
		t.Fatal("DeliverResponseFrame didn't unblock after consuming from channel")
	}

	// Receive the extra frame that was blocked
	extraReceived := <-ch
	framesReceived = append(framesReceived, extraReceived)

	// Verify all frames were received (no drops)
	expectedCount := bufferSize + 1
	if len(framesReceived) != expectedCount {
		t.Errorf("Expected to receive %d frames, got %d", expectedCount, len(framesReceived))
	}

	// Verify frame contents
	for i := 0; i < bufferSize; i++ {
		_, _, payload, _ := protocol.DecodeFrame(framesReceived[i])
		expected := fmt.Sprintf("frame-%d", i)
		if string(payload) != expected {
			t.Errorf("Frame %d: expected %q, got %q", i, expected, string(payload))
		}
	}

	// Verify extra frame
	_, _, payload, _ := protocol.DecodeFrame(framesReceived[bufferSize])
	if string(payload) != "extra-frame" {
		t.Errorf("Extra frame: expected %q, got %q", "extra-frame", string(payload))
	}
}

// TestBackpressureNoFrameLoss tests that no frames are lost under heavy load with backpressure
func TestBackpressureNoFrameLoss(t *testing.T) {
	mock := NewMockWebSocketConn()
	agent := NewAgent("test-agent", "test-service", mock)

	// Use realistic buffer size but send way more frames
	bufferSize := 10
	frameCount := 1000 // Send 100x the buffer size
	requestID := "high-volume-test"
	ch := agent.RegisterResponseChannel(requestID, bufferSize)

	// Sender goroutine - sends many frames (will be blocked by backpressure)
	sendComplete := make(chan bool)
	go func() {
		for i := 0; i < frameCount; i++ {
			frame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte(fmt.Sprintf("frame-%d", i)))
			agent.DeliverResponseFrame(requestID, frame)
		}
		sendComplete <- true
	}()

	// Consumer goroutine - consumes frames (with some delay to create backpressure)
	framesReceived := make([][]byte, 0)
	var receiveMu sync.Mutex
	receiveComplete := make(chan bool)
	go func() {
		for i := 0; i < frameCount; i++ {
			frame := <-ch
			receiveMu.Lock()
			framesReceived = append(framesReceived, frame)
			receiveMu.Unlock()

			// Small delay to simulate slow consumer
			if i%10 == 0 {
				time.Sleep(1 * time.Millisecond)
			}
		}
		receiveComplete <- true
	}()

	// Wait for both to complete
	select {
	case <-sendComplete:
		// Sender finished
	case <-time.After(10 * time.Second):
		t.Fatal("Sender timed out")
	}

	select {
	case <-receiveComplete:
		// Receiver finished
	case <-time.After(10 * time.Second):
		t.Fatal("Receiver timed out")
	}

	// Verify all frames received (no loss)
	receiveMu.Lock()
	receivedCount := len(framesReceived)
	receiveMu.Unlock()

	if receivedCount != frameCount {
		t.Errorf("Frame loss detected: sent %d, received %d (lost %d)",
			frameCount, receivedCount, frameCount-receivedCount)
	}

	// Verify frame ordering and contents
	receiveMu.Lock()
	for i := 0; i < frameCount; i++ {
		_, _, payload, _ := protocol.DecodeFrame(framesReceived[i])
		expected := fmt.Sprintf("frame-%d", i)
		if string(payload) != expected {
			t.Errorf("Frame %d: expected %q, got %q", i, expected, string(payload))
			break // Don't spam errors
		}
	}
	receiveMu.Unlock()
}
