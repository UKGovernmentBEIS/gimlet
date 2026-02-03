package health

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestParseStatusCodes(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantErr bool
		codes   []int // codes that should match
		notCodes []int // codes that should not match
	}{
		{
			name:    "single code",
			spec:    "200",
			wantErr: false,
			codes:   []int{200},
			notCodes: []int{201, 404, 500},
		},
		{
			name:    "range",
			spec:    "200-299",
			wantErr: false,
			codes:   []int{200, 250, 299},
			notCodes: []int{199, 300, 404},
		},
		{
			name:    "multiple ranges",
			spec:    "200-299,301-399",
			wantErr: false,
			codes:   []int{200, 250, 301, 350},
			notCodes: []int{300, 400, 500},
		},
		{
			name:    "mixed single and range",
			spec:    "200,204,301-399",
			wantErr: false,
			codes:   []int{200, 204, 301, 350, 399},
			notCodes: []int{201, 300, 400},
		},
		{
			name:    "with spaces",
			spec:    "200 , 204 , 301 - 399",
			wantErr: false,
			codes:   []int{200, 204, 301},
			notCodes: []int{201, 300},
		},
		{
			name:    "invalid range",
			spec:    "299-200",
			wantErr: true,
		},
		{
			name:    "invalid code",
			spec:    "abc",
			wantErr: true,
		},
		{
			name:    "empty",
			spec:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := ParseStatusCodes(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseStatusCodes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			for _, code := range tt.codes {
				if !matcher.Matches(code) {
					t.Errorf("Matches(%d) = false, want true", code)
				}
			}
			for _, code := range tt.notCodes {
				if matcher.Matches(code) {
					t.Errorf("Matches(%d) = true, want false", code)
				}
			}
		})
	}
}

func TestChecker_HealthyBackend(t *testing.T) {
	// Create a test server that always returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Wait for state change
	select {
	case state := <-checker.StateChanges():
		if state != StateHealthy {
			t.Errorf("Expected StateHealthy, got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for healthy state")
	}

	if checker.CurrentState() != StateHealthy {
		t.Errorf("CurrentState() = %v, want StateHealthy", checker.CurrentState())
	}
}

func TestChecker_UnhealthyBackend(t *testing.T) {
	// Create a test server that always returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Wait for state change (should become unhealthy after 2 failures)
	select {
	case state := <-checker.StateChanges():
		if state != StateUnhealthy {
			t.Errorf("Expected StateUnhealthy, got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for unhealthy state")
	}

	if checker.CurrentState() != StateUnhealthy {
		t.Errorf("CurrentState() = %v, want StateUnhealthy", checker.CurrentState())
	}
}

func TestChecker_UnreachableBackend(t *testing.T) {
	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              "http://localhost:59999/health", // Unlikely to be listening
		Interval:         50 * time.Millisecond,
		Timeout:          100 * time.Millisecond,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Wait for state change (should become unhealthy after 2 failures)
	select {
	case state := <-checker.StateChanges():
		if state != StateUnhealthy {
			t.Errorf("Expected StateUnhealthy, got %v", state)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for unhealthy state")
	}
}

func TestChecker_StateTransitions(t *testing.T) {
	var requestCount atomic.Int32

	// Server that alternates: first 3 requests fail, then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Should first become unhealthy (after 2 failures)
	select {
	case state := <-checker.StateChanges():
		if state != StateUnhealthy {
			t.Errorf("First state change: expected StateUnhealthy, got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for unhealthy state")
	}

	// Then should become healthy (after 1 success, since threshold is 1)
	select {
	case state := <-checker.StateChanges():
		if state != StateHealthy {
			t.Errorf("Second state change: expected StateHealthy, got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for healthy state")
	}
}

func TestChecker_SuccessThreshold(t *testing.T) {
	var requestCount atomic.Int32

	// Server: 2 failures, then 3 successes needed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 3, // Need 3 consecutive successes
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Should first become unhealthy
	select {
	case state := <-checker.StateChanges():
		if state != StateUnhealthy {
			t.Errorf("First state change: expected StateUnhealthy, got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for unhealthy state")
	}

	// Then should become healthy after 3 successes
	select {
	case state := <-checker.StateChanges():
		if state != StateHealthy {
			t.Errorf("Second state change: expected StateHealthy, got %v", state)
		}
		// Verify we got enough successful requests (at least 3 successes after 2 failures)
		if requestCount.Load() < 5 {
			t.Errorf("Expected at least 5 requests, got %d", requestCount.Load())
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for healthy state")
	}
}

func TestChecker_Stop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	matcher, _ := ParseStatusCodes("200-299")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()

	// Wait for healthy state
	<-checker.StateChanges()

	// Stop should complete without blocking
	done := make(chan struct{})
	go func() {
		checker.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good, stop completed
	case <-time.After(1 * time.Second):
		t.Error("Stop() blocked for too long")
	}
}

func TestChecker_CustomStatusCodes(t *testing.T) {
	// Server returns 204 No Content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	// Matcher only accepts 200
	matcher, _ := ParseStatusCodes("200")
	checker := NewChecker(Config{
		URL:              server.URL + "/health",
		Interval:         50 * time.Millisecond,
		Timeout:          1 * time.Second,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		StatusMatcher:    matcher,
	}, zerolog.Nop())

	checker.Start()
	defer checker.Stop()

	// Should become unhealthy because 204 is not accepted
	select {
	case state := <-checker.StateChanges():
		if state != StateUnhealthy {
			t.Errorf("Expected StateUnhealthy (204 not in allowed codes), got %v", state)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for unhealthy state")
	}
}
