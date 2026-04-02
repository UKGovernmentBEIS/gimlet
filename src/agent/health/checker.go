package health

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// State represents the health state of the backend
type State string

const (
	StateUnknown  State = "unknown"
	StateHealthy  State = "healthy"
	StateUnhealthy State = "unhealthy"
)

// StatusCodeMatcher checks if a status code is acceptable
type StatusCodeMatcher struct {
	ranges [][2]int // pairs of [min, max] inclusive
}

// ParseStatusCodes parses a status code specification like "200-299" or "200,204,301-399"
func ParseStatusCodes(spec string) (*StatusCodeMatcher, error) {
	matcher := &StatusCodeMatcher{}

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range like "200-299"
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			min, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid status code: %s", rangeParts[0])
			}
			max, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid status code: %s", rangeParts[1])
			}
			if min > max {
				return nil, fmt.Errorf("invalid range: min > max in %s", part)
			}
			matcher.ranges = append(matcher.ranges, [2]int{min, max})
		} else {
			// Single code like "200"
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid status code: %s", part)
			}
			matcher.ranges = append(matcher.ranges, [2]int{code, code})
		}
	}

	if len(matcher.ranges) == 0 {
		return nil, fmt.Errorf("no valid status codes in spec: %s", spec)
	}

	return matcher, nil
}

// Matches returns true if the status code is acceptable
func (m *StatusCodeMatcher) Matches(code int) bool {
	for _, r := range m.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}

// Config holds health checker configuration
type Config struct {
	URL              string
	Interval         time.Duration
	Timeout          time.Duration
	FailureThreshold int
	SuccessThreshold int
	StatusMatcher    *StatusCodeMatcher
}

// Checker performs periodic health checks against a backend
type Checker struct {
	config Config
	client *http.Client
	logger zerolog.Logger

	state            State
	consecutiveOK    int
	consecutiveFail  int
	stateMu          sync.RWMutex

	// Channels
	stateChangeCh chan State
	stopCh        chan struct{}
	stoppedCh     chan struct{}
}

// NewChecker creates a new health checker
func NewChecker(cfg Config, logger zerolog.Logger) *Checker {
	return &Checker{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger:        logger.With().Str("component", "healthcheck").Logger(),
		state:         StateUnknown,
		stateChangeCh: make(chan State, 10), // buffered to avoid blocking
		stopCh:        make(chan struct{}),
		stoppedCh:     make(chan struct{}),
	}
}

// StateChanges returns a channel that receives state changes
func (c *Checker) StateChanges() <-chan State {
	return c.stateChangeCh
}

// CurrentState returns the current health state
func (c *Checker) CurrentState() State {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// Start begins periodic health checking in a goroutine
func (c *Checker) Start() {
	go c.run()
}

// Stop signals the checker to stop and waits for it to finish
func (c *Checker) Stop() {
	close(c.stopCh)
	<-c.stoppedCh
}

func (c *Checker) run() {
	defer close(c.stoppedCh)
	defer close(c.stateChangeCh)

	// Perform initial check immediately
	c.check()

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			c.logger.Debug().Msg("Health checker stopping")
			return
		case <-ticker.C:
			c.check()
		}
	}
}

func (c *Checker) check() {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.URL, nil)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to create health check request")
		c.recordFailure("request_error", err.Error())
		return
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Warn().Err(err).Str("url", c.config.URL).Msg("Health check failed")
		c.recordFailure("connection_error", err.Error())
		return
	}
	defer resp.Body.Close()

	if c.config.StatusMatcher.Matches(resp.StatusCode) {
		c.logger.Debug().Int("status", resp.StatusCode).Msg("Health check passed")
		c.recordSuccess()
	} else {
		c.logger.Warn().Int("status", resp.StatusCode).Str("url", c.config.URL).Msg("Health check failed: unexpected status")
		c.recordFailure("bad_status", fmt.Sprintf("status=%d", resp.StatusCode))
	}
}

func (c *Checker) recordSuccess() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	c.consecutiveFail = 0
	c.consecutiveOK++

	if c.consecutiveOK >= c.config.SuccessThreshold && c.state != StateHealthy {
		oldState := c.state
		c.state = StateHealthy
		c.logger.Info().
			Str("oldState", string(oldState)).
			Str("newState", string(c.state)).
			Int("consecutiveOK", c.consecutiveOK).
			Msg("Backend health state changed")

		// Non-blocking send
		select {
		case c.stateChangeCh <- c.state:
		default:
			c.logger.Warn().Msg("State change channel full, dropping notification")
		}
	}
}

func (c *Checker) recordFailure(reason, detail string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	c.consecutiveOK = 0
	c.consecutiveFail++

	if c.consecutiveFail >= c.config.FailureThreshold && c.state != StateUnhealthy {
		oldState := c.state
		c.state = StateUnhealthy
		c.logger.Warn().
			Str("oldState", string(oldState)).
			Str("newState", string(c.state)).
			Str("reason", reason).
			Str("detail", detail).
			Int("consecutiveFail", c.consecutiveFail).
			Msg("Backend health state changed")

		// Non-blocking send
		select {
		case c.stateChangeCh <- c.state:
		default:
			c.logger.Warn().Msg("State change channel full, dropping notification")
		}
	}
}
