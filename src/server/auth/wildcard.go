package auth

import "path/filepath"

// MatchesAny checks if service matches any of the wildcard patterns
func MatchesAny(service string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, service); matched {
			return true
		}
	}
	return false
}
