package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)
// TestExtractServiceFromPath tests extracting service names from URL paths
func TestExtractServiceFromPath(t *testing.T) {
	h := &HTTPHandler{}
	tests := []struct {
		name            string
		path            string
		expectedService string
		expectedPath    string
	}{
		{
			name:            "valid service path",
			path:            "/services/model-v1/predict",
			expectedService: "model-v1",
			expectedPath:    "/predict",
		},
		{
			name:            "service with no trailing path",
			path:            "/services/model-v1",
			expectedService: "model-v1",
			expectedPath:    "/",
		},
		{
			name:            "service with root path",
			path:            "/services/model-v1/",
			expectedService: "model-v1",
			expectedPath:    "/",
		},
		{
			name:            "service with deep path",
			path:            "/services/model-v1/api/v2/predict",
			expectedService: "model-v1",
			expectedPath:    "/api/v2/predict",
		},
		{
			name:            "no services prefix",
			path:            "/api/predict",
			expectedService: "",
			expectedPath:    "/api/predict",
		},
		{
			name:            "root path",
			path:            "/",
			expectedService: "",
			expectedPath:    "/",
		},
		{
			name:            "services prefix only",
			path:            "/services/",
			expectedService: "",
			expectedPath:    "/services/",
		},
		{
			name:            "service with hyphens",
			path:            "/services/my-service-v2/health",
			expectedService: "my-service-v2",
			expectedPath:    "/health",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, rewrittenPath := h.extractServiceFromPath(tt.path)
			if service != tt.expectedService {
				t.Errorf("Expected service %q, got %q", tt.expectedService, service)
			}
			if rewrittenPath != tt.expectedPath {
				t.Errorf("Expected path %q, got %q", tt.expectedPath, rewrittenPath)
			}
		})
	}
}
// TestSerializeRequestHeaders tests HTTP request header serialization
func TestSerializeRequestHeaders(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		originalPath  string
		rewrittenPath string
		host          string
		headers       map[string]string
		expectError   bool
		validate      func(*testing.T, []byte)
	}{
		{
			name:          "simple GET request with path rewrite",
			method:        "GET",
			originalPath:  "/services/model-v1/api/data",
			rewrittenPath: "/api/data",
			host:          "backend.local",
			headers: map[string]string{
				"User-Agent": "test-client/1.0",
			},
			expectError: false,
			validate: func(t *testing.T, data []byte) {
				str := string(data)
				if !strings.Contains(str, "GET /api/data HTTP/1.1\r\n") {
					t.Error("Missing or incorrect request line")
				}
				if !strings.Contains(str, "Host: backend.local\r\n") {
					t.Error("Missing Host header")
				}
				if !strings.Contains(str, "User-Agent: test-client/1.0\r\n") {
					t.Error("Missing User-Agent header")
				}
				if !strings.HasSuffix(str, "\r\n\r\n") {
					t.Error("Missing blank line at end of headers")
				}
			},
		},
		{
			name:          "POST request with multiple headers",
			method:        "POST",
			originalPath:  "/services/model-v1/api/create",
			rewrittenPath: "/api/create",
			host:          "api.example.com",
			headers: map[string]string{
				"Content-Type":   "application/json",
				"Content-Length": "123",
				"Authorization":  "Bearer token123",
			},
			expectError: false,
			validate: func(t *testing.T, data []byte) {
				str := string(data)
				if !strings.Contains(str, "POST /api/create HTTP/1.1\r\n") {
					t.Error("Missing or incorrect request line")
				}
				if !strings.Contains(str, "Host: api.example.com\r\n") {
					t.Error("Missing Host header")
				}
				if !strings.Contains(str, "Content-Type: application/json\r\n") {
					t.Error("Missing Content-Type header")
				}
				if !strings.Contains(str, "Authorization: Bearer token123\r\n") {
					t.Error("Missing Authorization header")
				}
			},
		},
		{
			name:          "path with query string preserved",
			method:        "GET",
			originalPath:  "/services/model-v1/search?q=test&limit=10",
			rewrittenPath: "/search",
			host:          "search.local",
			headers: map[string]string{
				"Accept": "application/json",
			},
			expectError: false,
			validate: func(t *testing.T, data []byte) {
				str := string(data)
				if !strings.Contains(str, "GET /search?q=test&limit=10 HTTP/1.1\r\n") {
					t.Error("Query string not preserved in request line")
				}
			},
		},
		{
			name:          "custom headers with special characters",
			method:        "GET",
			originalPath:  "/services/model-v1/",
			rewrittenPath: "/",
			host:          "test.local",
			headers: map[string]string{
				"X-Custom-Header": "value-with-dashes",
				"X-Request-ID":    "uuid-1234-5678",
			},
			expectError: false,
			validate: func(t *testing.T, data []byte) {
				str := string(data)
				if !strings.Contains(str, "X-Custom-Header: value-with-dashes\r\n") {
					t.Error("Custom header not serialized correctly")
				}
				// Go canonicalizes "X-Request-ID" to "X-Request-Id"
				if !strings.Contains(str, "X-Request-Id: uuid-1234-5678\r\n") {
					t.Error("X-Request-Id header not serialized correctly")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with original path
			req, err := http.NewRequest(tt.method, "http://"+tt.host+tt.originalPath, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			// Add custom headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			// Serialize with rewritten path
			data, err := serializeRequestHeaders(req, tt.rewrittenPath)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}
// TestSerializeRequestHeadersProto tests protocol version handling
func TestSerializeRequestHeadersProto(t *testing.T) {
	tests := []struct {
		name     string
		proto    string
		major    int
		minor    int
		expected string
	}{
		{"HTTP/1.1", "HTTP/1.1", 1, 1, "HTTP/1.1"},
		{"HTTP/1.0", "HTTP/1.0", 1, 0, "HTTP/1.0"},
		{"HTTP/2.0", "HTTP/2.0", 2, 0, "HTTP/2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test.local/services/model/test", nil)
			req.Proto = tt.proto
			req.ProtoMajor = tt.major
			req.ProtoMinor = tt.minor
			data, err := serializeRequestHeaders(req, "/test")
			if err != nil {
				t.Fatalf("serializeRequestHeaders failed: %v", err)
			}
			str := string(data)
			expectedLine := "GET /test " + tt.expected + "\r\n"
			if !strings.HasPrefix(str, expectedLine) {
				t.Errorf("Expected request line to start with %q, got %q", expectedLine, str[:len(expectedLine)])
			}
		})
	}
}

// mockMetricsTracker implements MetricsTracker for testing
type mockMetricsTracker struct{}
func (m *mockMetricsTracker) IncrementActiveRequests(service string)                         {}
func (m *mockMetricsTracker) DecrementActiveRequests(service string)                         {}
func (m *mockMetricsTracker) ObserveRequestDuration(service string, duration float64)        {}
func (m *mockMetricsTracker) IncrementRequestsTotal(service string, agentID string, clientID string, statusCode string) {}
func (m *mockMetricsTracker) IncrementWebsocketMessage(direction string, messageType string) {}
func (m *mockMetricsTracker) ObserveResponseChannelBuffer(service string, agentID string, bufferUsage float64) {
}
func (m *mockMetricsTracker) IncrementRateLimitRejection(service string, limitType string) {}
// TestRateLimitSemaphoreInit tests semaphore initialization with different limits
func TestRateLimitSemaphoreInit(t *testing.T) {
	tests := []struct {
		name             string
		maxConcurrent    int64
		expectSemaphore  bool
		expectedCapacity int
	}{
		{
			name:             "limit enabled",
			maxConcurrent:    10,
			expectSemaphore:  true,
			expectedCapacity: 10,
		},
		{
			name:             "limit disabled (0)",
			maxConcurrent:    0,
			expectSemaphore:  false,
			expectedCapacity: 0,
		},
		{
			name:             "large limit",
			maxConcurrent:    1000,
			expectSemaphore:  true,
			expectedCapacity: 1000,
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
			handler := NewHTTPHandler(
				nil, // jwtValidator
				nil, // agentProvider
				"test-server",
				10*time.Second,
				100, // responseChannelBufferSize
				tt.maxConcurrent,
				zerolog.New(io.Discard), // logger (discard output for tests)
				&mockMetricsTracker{},
			)
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
