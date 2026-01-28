package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

func (m *testAgentProvider) LocalAgents() map[string]*agentmgr.Agent {
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

func TestServeHTTP_MissingAuth(t *testing.T) {
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

	// Create request without auth header
	req := httptest.NewRequest("GET", "/services/service-1/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_InvalidJWT(t *testing.T) {
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

	// Create request with invalid token
	req := httptest.NewRequest("GET", "/services/service-1/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_NoAgentsAvailable(t *testing.T) {
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

	// Create valid request but no agents
	req := httptest.NewRequest("GET", "/services/service-1/test", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_InvalidPath(t *testing.T) {
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

	// Create request without /services/ prefix
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_UnauthorizedService(t *testing.T) {
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

	// Create request for service-2 (not authorized)
	req := httptest.NewRequest("GET", "/services/service-2/test", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_LoadBalancing(t *testing.T) {
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

	// Create valid request
	req := httptest.NewRequest("GET", "/services/test-service/test", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w := httptest.NewRecorder()

	// The test verifies that load balancing logic compiles and runs
	// Detailed load distribution testing is done in E2E tests
	handler.ServeHTTP(w, req)

	// Note: We don't check response status here since it depends on agent response
	// which we haven't mocked. The test just ensures no panic/crash.
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

// TestServeHTTP_AgentResponseStreaming tests that responses from agents are properly
// streamed to the client through the ServeHTTP handler
func TestServeHTTP_AgentResponseStreaming(t *testing.T) {
	// Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	token := generateClientJWT(t, privateKey, []string{"*"})
	validator := auth.NewJWTValidator([]*rsa.PublicKey{&privateKey.PublicKey}, "gimlet-test")
	metrics := &mockMetricsTracker{}

	// Create a tracking WebSocket connection
	trackingWS := newTrackingWebSocketConn()
	agent := agentmgr.NewAgent("agent-1", "test-service", trackingWS)
	agent.SetReady(true)

	agentProvider := &testAgentProvider{
		agents: map[string]*agentmgr.Agent{
			"agent-1": agent,
		},
	}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		30*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	// Create a test server that uses our handler
	ts := httptest.NewServer(http.HandlerFunc(handler.ServeHTTP))
	defer ts.Close()

	// Make request in background
	responseCh := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest("GET", ts.URL+"/services/test-service/test", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("Request error: %v", err)
			return
		}
		responseCh <- resp
	}()

	// Wait for request to be forwarded to agent
	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	// Extract requestID from the first message (Start frame)
	messages := trackingWS.getMessages()
	if len(messages) == 0 {
		t.Fatal("No messages received by agent")
	}

	// Decode the Start frame to get requestID
	frameType, requestID, _, err := protocol.DecodeFrame(messages[0])
	if err != nil {
		t.Fatalf("Failed to decode frame: %v", err)
	}
	if frameType != protocol.FrameTypeStart {
		t.Fatalf("Expected Start frame, got frame type %d", frameType)
	}

	// Simulate agent sending a response with headers-only START (new protocol)
	responseHeaders := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	startFrame := protocol.EncodeFrame(protocol.FrameTypeStart, requestID, []byte(responseHeaders))
	if !agent.DeliverResponseFrame(requestID, startFrame) {
		t.Fatal("Failed to deliver response start frame")
	}

	// Send body in DATA frame (new protocol)
	dataFrame := protocol.EncodeFrame(protocol.FrameTypeData, requestID, []byte("hello"))
	if !agent.DeliverResponseFrame(requestID, dataFrame) {
		t.Fatal("Failed to deliver response data frame")
	}

	// Send END frame
	endFrame := protocol.EncodeFrame(protocol.FrameTypeEnd, requestID, []byte(""))
	if !agent.DeliverResponseFrame(requestID, endFrame) {
		t.Fatal("Failed to deliver response end frame")
	}

	// Wait for response
	select {
	case resp := <-responseCh:
		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello" {
			t.Errorf("Expected body 'hello', got '%s'", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

// TestServeHTTP_CancelOnAgentDisconnect tests that when an agent disconnects
// mid-request, the handler returns an appropriate error
func TestServeHTTP_CancelOnAgentDisconnect(t *testing.T) {
	// Setup
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
		agents: map[string]*agentmgr.Agent{
			"agent-1": agent,
		},
	}

	handler := NewHTTPHandler(
		validator,
		agentProvider,
		"test-server",
		30*time.Second,
		100,
		0,
		zerolog.New(io.Discard),
		metrics,
	)

	ts := httptest.NewServer(http.HandlerFunc(handler.ServeHTTP))
	defer ts.Close()

	// Make request in background
	responseCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", ts.URL+"/services/test-service/test", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		responseCh <- resp
	}()

	// Wait for request to be forwarded
	if !trackingWS.waitForMessage(2 * time.Second) {
		t.Fatal("Request was not forwarded to agent")
	}

	// Extract requestID
	messages := trackingWS.getMessages()
	_, requestID, _, _ := protocol.DecodeFrame(messages[0])

	// Simulate agent disconnect by closing the response channel
	agent.CleanupRequest(requestID)

	// Wait for response - should be 502 Bad Gateway
	select {
	case resp := <-responseCh:
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected status 502, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "Agent disconnected") {
			t.Errorf("Expected 'Agent disconnected' in body, got: %s", body)
		}
	case err := <-errCh:
		t.Fatalf("Request failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}
