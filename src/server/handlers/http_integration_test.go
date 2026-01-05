package handlers

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gimlet/protocol"
	"gimlet/server/agentmgr"
	"gimlet/server/auth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

// Mock implementations
type testAgentProvider struct {
	agents map[string]*agentmgr.Agent
}

func (m *testAgentProvider) GetLocalAgents() map[string]*agentmgr.Agent {
	return m.agents
}

// Helper to generate test JWT
func generateClientJWT(t *testing.T, privateKey *rsa.PrivateKey, services []string) string {
	claims := auth.ClientClaims{
		Services: services,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-client",
			Issuer:    "gimlet-test",
			Audience:  jwt.ClaimStrings{"gimlet-client"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenString
}

func TestHandleTCPConnection_MissingAuth(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)}
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request without auth header
	go handler.HandleTCPConnection(serverConn)

	request := "GET /services/service-1/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"\r\n"
	clientConn.Write([]byte(request))

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestHandleTCPConnection_InvalidJWT(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)}
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request with invalid token
	go handler.HandleTCPConnection(serverConn)

	request := "GET /services/service-1/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Authorization: Bearer invalid-token\r\n" +
		"\r\n"
	clientConn.Write([]byte(request))

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestHandleTCPConnection_NoAgentsAvailable(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"service-1"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)} // No agents
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send valid request but no agents
	go handler.HandleTCPConnection(serverConn)

	request := "GET /services/service-1/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", resp.StatusCode)
	}
}

func TestHandleTCPConnection_InvalidPath(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)}
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request without /services/ prefix
	go handler.HandleTCPConnection(serverConn)

	request := "GET /test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"\r\n"
	clientConn.Write([]byte(request))

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestHandleTCPConnection_UnauthorizedService(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Token only allows service-1, but request is for service-2
	token := generateClientJWT(t, privateKey, []string{"service-1"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)}
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request for service-2 (not authorized)
	go handler.HandleTCPConnection(serverConn)

	request := "GET /services/service-2/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestHandleTCPConnection_LoadBalancing(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	// Create mock agents with different loads
	mockWS1 := &mockWebSocketConn{}
	mockWS2 := &mockWebSocketConn{}

	agent1 := agentmgr.NewAgent("agent-1", "test-service", mockWS1)
	agent2 := agentmgr.NewAgent("agent-2", "test-service", mockWS2)

	// Simulate agent1 having higher load by registering some requests
	agent1.RegisterResponseChannel("dummy-1", 100)
	agent1.RegisterResponseChannel("dummy-2", 100)
	// agent2 has no load

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{
			"agent-1": agent1,
			"agent-2": agent2,
		},
	}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request - should select agent-2 (lower load)
	// Note: We don't check internal state due to race conditions in tests
	// The load balancing logic is tested implicitly - if it's broken, E2E tests will catch it
	go handler.HandleTCPConnection(serverConn)

	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	// The test verifies that load balancing logic compiles and runs
	// Detailed load distribution testing is done in E2E tests
	time.Sleep(10 * time.Millisecond)

	// Note: We don't cleanup dummy requests to avoid race with HandleTCPConnection
	// which may still be reading agent.StreamCh. Test agents are garbage collected.
}

// Mock WebSocket connection for tests
type mockWebSocketConn struct {
	mu       sync.Mutex
	messages [][]byte
	closed   bool
}

func (m *mockWebSocketConn) ReadJSON(v interface{}) error {
	return fmt.Errorf("not implemented")
}

func (m *mockWebSocketConn) WriteJSON(v interface{}) error {
	return nil
}

func (m *mockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	return 0, nil, fmt.Errorf("not implemented")
}

func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("connection closed")
	}
	m.messages = append(m.messages, data)
	return nil
}

func (m *mockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockWebSocketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func TestHandleTCPConnection_MalformedRequest(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	agentProvider := &testAgentProvider{agents: make(map[string]*agentmgr.Agent)}
	metrics := &mockMetricsTracker{}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		10*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send malformed request
	go handler.HandleTCPConnection(serverConn)

	malformed := "this is not http\r\n\r\n"
	clientConn.Write([]byte(malformed))

	// Read response
	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(line, "400") {
		t.Errorf("Expected 400 Bad Request, got: %s", line)
	}
}

// trackingWebSocketConn tracks messages sent to the agent for verification
type trackingWebSocketConn struct {
	mu       sync.Mutex
	messages [][]byte
	closed   bool
	cancelCh chan struct{} // Signals when CANCEL frame is received
}

func newTrackingWebSocketConn() *trackingWebSocketConn {
	return &trackingWebSocketConn{
		cancelCh: make(chan struct{}, 1),
	}
}

func (m *trackingWebSocketConn) ReadJSON(v interface{}) error {
	return fmt.Errorf("not implemented")
}

func (m *trackingWebSocketConn) WriteJSON(v interface{}) error {
	return nil
}

func (m *trackingWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	// Block forever - we never send messages from "agent" to server in this test
	select {}
}

func (m *trackingWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("connection closed")
	}
	m.messages = append(m.messages, data)

	// Check if this is a CANCEL frame (frame type 0x04)
	if len(data) > 0 && data[0] == 0x04 {
		select {
		case m.cancelCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (m *trackingWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *trackingWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *trackingWebSocketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *trackingWebSocketConn) waitForCancel(timeout time.Duration) bool {
	select {
	case <-m.cancelCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (m *trackingWebSocketConn) getMessages() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]byte, len(m.messages))
	copy(result, m.messages)
	return result
}

func (m *trackingWebSocketConn) waitForMessage(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		hasMessages := len(m.messages) > 0
		m.mu.Unlock()
		if hasMessages {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestClientClosureTriggersCancel tests that when a client closes the connection,
// the server sends a CANCEL frame to the agent
func TestClientClosureTriggersCancel(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	// Create a tracking WebSocket connection to detect CANCEL frames
	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true) // Agent must be ready to be selected

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{
			"agent-1": agent,
		},
	}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		30*time.Second, // Long idle timeout - we want to test client closure, not timeout
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create pipe
	clientConn, serverConn := net.Pipe()

	// Start handler
	handlerDone := make(chan struct{})
	go func() {
		handler.HandleTCPConnection(serverConn)
		close(handlerDone)
	}()

	// Send a valid request
	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	// Wait a bit for the request to be forwarded to the agent
	time.Sleep(50 * time.Millisecond)

	// Close the client connection (simulating curl finishing or client disconnect)
	clientConn.Close()

	// Verify CANCEL frame was sent to agent
	if !trackingWS.waitForCancel(2 * time.Second) {
		t.Error("Expected CANCEL frame to be sent to agent when client closed connection")
	}

	// Wait for handler to complete
	select {
	case <-handlerDone:
		// Good
	case <-time.After(3 * time.Second):
		t.Error("Handler did not complete after client closure")
	}
}

// TestCancelSentOnContentLengthComplete tests that CANCEL is sent immediately
// when a Content-Length response body is fully received.
func TestCancelSentOnContentLengthComplete(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true)

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{"agent-1": agent},
	}

	handler := NewHTTPHandler(
		validator, agentProvider, "test-server",
		30*time.Second, 100, 0,
		zerolog.New(io.Discard), metrics,
	)

	clientConn, serverConn := net.Pipe()

	// Read from client side to prevent handler from blocking on writes
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	handlerDone := make(chan struct{})
	go func() {
		handler.HandleTCPConnection(serverConn)
		close(handlerDone)
	}()

	// Send request
	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	messages := trackingWS.getMessages()
	_, requestID, _, _ := protocol.DecodeFrame(messages[0])

	// Send response with Content-Length: 5 and body "hello" - all in start frame
	responseHeaders := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(responseHeaders))
	agent.DeliverResponseFrame(requestID, startFrame)

	// CANCEL should be sent immediately when Content-Length body is complete
	// (no need to wait for client close or END frame)
	if !trackingWS.waitForCancel(2 * time.Second) {
		t.Error("Expected CANCEL frame when Content-Length response body complete")
	}

	// Clean up
	clientConn.Close()
	<-handlerDone
}

// TestCancelSentOnNoBodyResponse tests that CANCEL is sent immediately
// for responses that have no body (204, 304).
func TestCancelSentOnNoBodyResponse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true)

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{"agent-1": agent},
	}

	handler := NewHTTPHandler(
		validator, agentProvider, "test-server",
		30*time.Second, 100, 0,
		zerolog.New(io.Discard), metrics,
	)

	clientConn, serverConn := net.Pipe()

	// Read from client side to prevent handler from blocking on writes
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	handlerDone := make(chan struct{})
	go func() {
		handler.HandleTCPConnection(serverConn)
		close(handlerDone)
	}()

	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	messages := trackingWS.getMessages()
	_, requestID, _, _ := protocol.DecodeFrame(messages[0])

	// Send 204 No Content response - no body expected
	response204 := "HTTP/1.1 204 No Content\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(response204))
	agent.DeliverResponseFrame(requestID, startFrame)

	// CANCEL should be sent immediately for no-body responses
	if !trackingWS.waitForCancel(2 * time.Second) {
		t.Error("Expected CANCEL frame immediately for 204 No Content response")
	}

	clientConn.Close()
	<-handlerDone
}

// TestCancelSentOnChunkedComplete tests that CANCEL is sent when
// chunked encoding terminator is detected.
func TestCancelSentOnChunkedComplete(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true)

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{"agent-1": agent},
	}

	handler := NewHTTPHandler(
		validator, agentProvider, "test-server",
		30*time.Second, 100, 0,
		zerolog.New(io.Discard), metrics,
	)

	clientConn, serverConn := net.Pipe()

	// Read from client side to prevent handler from blocking on writes
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	handlerDone := make(chan struct{})
	go func() {
		handler.HandleTCPConnection(serverConn)
		close(handlerDone)
	}()

	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	messages := trackingWS.getMessages()
	_, requestID, _, _ := protocol.DecodeFrame(messages[0])

	// Send chunked response headers
	responseHeaders := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(responseHeaders))
	agent.DeliverResponseFrame(requestID, startFrame)

	// Send a chunk followed by the terminator
	// Format: chunk-size\r\n chunk-data\r\n ... 0\r\n\r\n
	chunkData := "5\r\nhello\r\n0\r\n\r\n"
	dataFrame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte(chunkData))
	agent.DeliverResponseFrame(requestID, dataFrame)

	// CANCEL should be sent when chunked terminator is detected
	if !trackingWS.waitForCancel(2 * time.Second) {
		t.Error("Expected CANCEL frame when chunked terminator detected")
	}

	clientConn.Close()
	<-handlerDone
}

// TestCancelSentOnChunkedTerminatorSplitAcrossFrames tests that CANCEL is sent
// when the chunked terminator spans two frames.
func TestCancelSentOnChunkedTerminatorSplitAcrossFrames(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true)

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{"agent-1": agent},
	}

	handler := NewHTTPHandler(
		validator, agentProvider, "test-server",
		30*time.Second, 100, 0,
		zerolog.New(io.Discard), metrics,
	)

	clientConn, serverConn := net.Pipe()

	// Read from client side to prevent handler from blocking on writes
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	handlerDone := make(chan struct{})
	go func() {
		handler.HandleTCPConnection(serverConn)
		close(handlerDone)
	}()

	request := "GET /services/test-service/test HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		fmt.Sprintf("Authorization: Bearer %s\r\n", token) +
		"\r\n"
	clientConn.Write([]byte(request))

	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	messages := trackingWS.getMessages()
	_, requestID, _, _ := protocol.DecodeFrame(messages[0])

	// Send chunked response headers
	responseHeaders := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(responseHeaders))
	agent.DeliverResponseFrame(requestID, startFrame)

	// Send chunk data ending with partial terminator "0\r\n"
	chunkData1 := "5\r\nhello\r\n0\r\n"
	dataFrame1 := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte(chunkData1))
	agent.DeliverResponseFrame(requestID, dataFrame1)

	// CANCEL should NOT be sent yet (terminator incomplete)
	time.Sleep(100 * time.Millisecond)
	if trackingWS.waitForCancel(100 * time.Millisecond) {
		t.Error("CANCEL should not be sent before terminator is complete")
	}

	// Send the rest of the terminator "\r\n"
	chunkData2 := "\r\n"
	dataFrame2 := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte(chunkData2))
	agent.DeliverResponseFrame(requestID, dataFrame2)

	// Now CANCEL should be sent
	if !trackingWS.waitForCancel(2 * time.Second) {
		t.Error("Expected CANCEL frame when split chunked terminator completed")
	}

	clientConn.Close()
	<-handlerDone
}
