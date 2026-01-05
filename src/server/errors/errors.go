package errors

import "fmt"

// Error codes for Gimlet infrastructure errors
const (
	CodeBufferFull        = "BUFFER_FULL"
	CodeClientDisconnect  = "CLIENT_DISCONNECT"
	CodeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
	CodeTimeout           = "TIMEOUT"
	CodeAgentUnavailable  = "AGENT_UNAVAILABLE"
	CodeBackendError      = "BACKEND_ERROR"
	CodeAgentDisconnect   = "AGENT_DISCONNECT"
)

// Format creates a standardized error response body
func Format(code, message string) string {
	return fmt.Sprintf(`Gimlet Infrastructure Error

Error Code: %s
Message: %s

This error originated from the Gimlet tunnel infrastructure, not your backend service.
Request ID and additional details may be available in the response headers.`, code, message)
}
