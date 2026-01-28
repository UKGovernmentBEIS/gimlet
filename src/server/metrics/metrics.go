package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ctx = context.Background()

// Metrics holds all Prometheus metrics for a server
type Metrics struct {
	AgentConnections      *prometheus.GaugeVec
	RequestsTotal         *prometheus.CounterVec
	RequestDuration       *prometheus.HistogramVec
	ActiveRequests        *prometheus.GaugeVec
	WebsocketMessages     *prometheus.CounterVec
	ResponseChannelBuffer *prometheus.GaugeVec
	RateLimitRejections   *prometheus.CounterVec

	// Agent-reported metrics (per agent connection)
	AgentRateLimitRejections  *prometheus.GaugeVec
	AgentConcurrentRequests   *prometheus.GaugeVec
	AgentRequestChannelBuffer *prometheus.GaugeVec
	AgentBackendFailures      *prometheus.GaugeVec
	AgentWebsocketWriteErrors *prometheus.GaugeVec
	AgentFramesSent           *prometheus.GaugeVec
	AgentFramesReceived       *prometheus.GaugeVec
	AgentDraining             *prometheus.GaugeVec
	AgentConnectionUptime     *prometheus.GaugeVec
}

// New creates and registers Prometheus metrics for a server
func New(serverID string) *Metrics {
	m := &Metrics{
		AgentConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_connections",
				Help:        "Number of agent WebSocket connections per service (per server)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service"},
		),
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "gimlet_requests_total",
				Help:        "Total HTTP requests handled (per server)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id", "client_id", "status"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:        "gimlet_request_duration_seconds",
				Help:        "HTTP request latency in seconds (per server)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
				Buckets:     []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0},
			},
			[]string{"service"},
		),
		ActiveRequests: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_active_requests",
				Help:        "Number of in-flight HTTP requests (per server)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service"},
		),
		WebsocketMessages: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "gimlet_websocket_messages_total",
				Help:        "Total WebSocket messages sent/received (per server)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"direction", "type"},
		),
		ResponseChannelBuffer: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_response_channel_buffer_usage",
				Help:        "Current buffer usage of response channels (per service, agent)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		RateLimitRejections: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "gimlet_rate_limit_rejections_total",
				Help:        "Total requests rejected due to rate limits",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "limit_type"},
		),
		AgentRateLimitRejections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_rate_limit_rejections_total",
				Help:        "Agent-reported rate limit rejections (per agent connection)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentConcurrentRequests: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_concurrent_requests",
				Help:        "Agent-reported concurrent requests being handled",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentRequestChannelBuffer: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_request_channel_buffer_usage",
				Help:        "Agent-reported request channel buffer usage",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentBackendFailures: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_backend_failures_total",
				Help:        "Agent-reported backend connection failures",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentWebsocketWriteErrors: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_websocket_write_errors_total",
				Help:        "Agent-reported WebSocket write errors",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentFramesSent: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_frames_sent_total",
				Help:        "Agent-reported frames sent to server",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id", "frame_type"},
		),
		AgentFramesReceived: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_frames_received_total",
				Help:        "Agent-reported frames received from server",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id", "frame_type"},
		),
		AgentDraining: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_draining",
				Help:        "Agent draining state (1 = draining, 0 = active)",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
		AgentConnectionUptime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:        "gimlet_agent_connection_uptime_seconds",
				Help:        "Agent connection uptime in seconds",
				ConstLabels: prometheus.Labels{"server_id": serverID},
			},
			[]string{"service", "agent_id"},
		),
	}

	prometheus.MustRegister(m.AgentConnections)
	prometheus.MustRegister(m.RequestsTotal)
	prometheus.MustRegister(m.RequestDuration)
	prometheus.MustRegister(m.ActiveRequests)
	prometheus.MustRegister(m.WebsocketMessages)
	prometheus.MustRegister(m.ResponseChannelBuffer)
	prometheus.MustRegister(m.RateLimitRejections)
	prometheus.MustRegister(m.AgentRateLimitRejections)
	prometheus.MustRegister(m.AgentConcurrentRequests)
	prometheus.MustRegister(m.AgentRequestChannelBuffer)
	prometheus.MustRegister(m.AgentBackendFailures)
	prometheus.MustRegister(m.AgentWebsocketWriteErrors)
	prometheus.MustRegister(m.AgentFramesSent)
	prometheus.MustRegister(m.AgentFramesReceived)
	prometheus.MustRegister(m.AgentDraining)
	prometheus.MustRegister(m.AgentConnectionUptime)

	return m
}

// MetricsHandler returns the Prometheus HTTP handler
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// AgentBufferStat holds buffer usage stats for an agent
type AgentBufferStat struct {
	Service     string
	AgentID     string
	BufferUsage int
}

// AgentMetricsSnapshot holds a snapshot of agent-reported metrics
type AgentMetricsSnapshot struct {
	Service                 string
	AgentID                 string
	RateLimitRejections     int64
	ConcurrentRequests      int
	RequestChannelBuffer    int
	BackendFailures         int64
	WebsocketWriteErrors    int64
	FramesSent              map[string]int64
	FramesReceived          map[string]int64
	Draining                bool
	ConnectionUptimeSeconds int64
}

// ServerInfo provides server state for health/metrics reporting
type ServerInfo interface {
	AgentCounts() map[string]int
	ActiveRequestCount() int
	ServerID() string
	StartTime() time.Time
	AgentBufferStats() []AgentBufferStat
	AgentMetrics() []AgentMetricsSnapshot
}

// HealthHandler returns a health check endpoint handler
func HealthHandler(server ServerInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := map[string]interface{}{
			"status":          "healthy",
			"server_id":       server.ServerID(),
			"uptime":          time.Since(server.StartTime()).String(),
			"agents":          server.AgentCounts(),
			"active_requests": server.ActiveRequestCount(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	}
}

// UpdateLoop periodically updates gauge metrics from server state
func UpdateLoop(m *Metrics, server ServerInfo, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		serviceCounts := server.AgentCounts()
		for service, count := range serviceCounts {
			m.AgentConnections.WithLabelValues(service).Set(float64(count))
		}

		bufferStats := server.AgentBufferStats()
		for _, stat := range bufferStats {
			m.ResponseChannelBuffer.WithLabelValues(stat.Service, stat.AgentID).Set(float64(stat.BufferUsage))
		}

		// Update agent-reported metrics
		agentMetrics := server.AgentMetrics()
		for _, am := range agentMetrics {
			m.AgentRateLimitRejections.WithLabelValues(am.Service, am.AgentID).Set(float64(am.RateLimitRejections))
			m.AgentConcurrentRequests.WithLabelValues(am.Service, am.AgentID).Set(float64(am.ConcurrentRequests))
			m.AgentRequestChannelBuffer.WithLabelValues(am.Service, am.AgentID).Set(float64(am.RequestChannelBuffer))
			m.AgentBackendFailures.WithLabelValues(am.Service, am.AgentID).Set(float64(am.BackendFailures))
			m.AgentWebsocketWriteErrors.WithLabelValues(am.Service, am.AgentID).Set(float64(am.WebsocketWriteErrors))

			// Set draining state (0 or 1)
			drainingValue := 0.0
			if am.Draining {
				drainingValue = 1.0
			}
			m.AgentDraining.WithLabelValues(am.Service, am.AgentID).Set(drainingValue)
			m.AgentConnectionUptime.WithLabelValues(am.Service, am.AgentID).Set(float64(am.ConnectionUptimeSeconds))

			// Update frame counts by type
			for frameType, count := range am.FramesSent {
				m.AgentFramesSent.WithLabelValues(am.Service, am.AgentID, frameType).Set(float64(count))
			}
			for frameType, count := range am.FramesReceived {
				m.AgentFramesReceived.WithLabelValues(am.Service, am.AgentID, frameType).Set(float64(count))
			}
		}
	}
}
