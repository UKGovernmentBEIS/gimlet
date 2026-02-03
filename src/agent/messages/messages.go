package messages

// RegisterMessage is sent by the agent to register with a server
type RegisterMessage struct {
	Type        string `json:"type"`
	AgentID     string `json:"agent_id"`
	ServiceName string `json:"service_name"`
}

// HelloMessage is sent by server after successful registration
type HelloMessage struct {
	ServerID    string `json:"server_id"`
	AgentID     string `json:"agent_id"`
	ServiceName string `json:"service_name"`
}

// StateChangeMessage is sent by agent to change its readiness state
type StateChangeMessage struct {
	Type  string `json:"type"`  // "ready", "not_ready", or "draining"
	State string `json:"state"` // "ready", "not_ready", or "draining"
}

// MetricsUpdate is sent periodically by agent to report connection-level metrics
type MetricsUpdate struct {
	Type                  string            `json:"type"` // "metrics"
	RateLimitRejections   int64             `json:"rate_limit_rejections"`
	ConcurrentRequests    int               `json:"concurrent_requests"`
	RequestChannelBuffer  int               `json:"request_channel_buffer"`
	BackendFailures       int64             `json:"backend_failures"`
	FramesSent            map[string]int64  `json:"frames_sent"`     // by frame type
	FramesReceived        map[string]int64  `json:"frames_received"` // by frame type
	WebsocketWriteErrors  int64             `json:"websocket_write_errors"`
	Draining              bool              `json:"draining"`
	ConnectionUptimeSeconds int64           `json:"connection_uptime_seconds"`
}
