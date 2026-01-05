package auth

import "testing"

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		patterns []string
		expected bool
	}{
		{
			name:     "exact match",
			service:  "service-1",
			patterns: []string{"service-1", "service-2"},
			expected: true,
		},
		{
			name:     "no match",
			service:  "service-3",
			patterns: []string{"service-1", "service-2"},
			expected: false,
		},
		{
			name:     "wildcard suffix match",
			service:  "user-service-v1",
			patterns: []string{"user-*"},
			expected: true,
		},
		{
			name:     "wildcard prefix match",
			service:  "my-service",
			patterns: []string{"*-service"},
			expected: true,
		},
		{
			name:     "wildcard middle match",
			service:  "api-v1-prod",
			patterns: []string{"api-*-prod"},
			expected: true,
		},
		{
			name:     "star matches all",
			service:  "any-service",
			patterns: []string{"*"},
			expected: true,
		},
		{
			name:     "empty patterns",
			service:  "service-1",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "wildcard no match",
			service:  "service-1",
			patterns: []string{"api-*", "user-*"},
			expected: false,
		},
		{
			name:     "multiple patterns with match",
			service:  "user-api-v2",
			patterns: []string{"admin-*", "user-*", "guest-*"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesAny(tt.service, tt.patterns)
			if result != tt.expected {
				t.Errorf("MatchesAny(%q, %v) = %v, want %v",
					tt.service, tt.patterns, result, tt.expected)
			}
		})
	}
}
