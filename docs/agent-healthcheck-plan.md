# Agent Backend Health Check Plan

## Problem

Currently, the agent sends a "ready" signal immediately after WebSocket connection to the server succeeds, without verifying the backend is actually reachable. This means:

1. Requests can be routed to agents with unavailable backends (resulting in 502s)
2. There's no mechanism to mark an agent as not-ready if its backend becomes unavailable
3. Recovery requires agent restart or waiting for per-request failures

## Design

### New State: `not_ready`

Add a third state alongside `ready` and `draining`:

| State | Meaning | Server behavior |
|-------|---------|-----------------|
| `ready` | Backend healthy, accepting requests | Routes requests to agent |
| `not_ready` | Backend unhealthy, temporarily unavailable | Skips agent for routing |
| `draining` | Shutting down, finishing in-flight | Skips agent, allows existing requests to complete |

### Health Check Mechanism

HTTP GET request to a configurable health endpoint on the backend.

**Why HTTP (not just TCP dial)?**

TCP dial only tells you "something is listening on the port". It doesn't tell you:
- Whether the application has finished initializing
- Whether the application can actually serve requests
- Whether dependencies (database, cache, etc.) are healthy
- Whether the process crashed but something else holds the port

HTTP health checks are industry standard (Kubernetes probes, ALB health checks, etc.) because they let the backend report actual readiness.

**Configuration:**
- **Path**: Health endpoint path (default: `/health`)
- **Expected status**: What counts as healthy (default: any 2xx)
- **Interval**: How often to check (default: 5s)
- **Timeout**: Max time for request to complete (default: 3s)
- **Failure threshold**: Consecutive failures before marking not_ready (default: 2)
- **Success threshold**: Consecutive successes before marking ready (default: 1)

**Behavior:**
- GET request to `{target_url}{health_path}` (e.g., `http://backend:8000/health`)
- Success = 2xx response (we don't care about body)
- Failure = connection error, timeout, or non-2xx response
- Thresholds prevent flapping on transient failures

### State Transitions

```
                    ┌──────────────┐
    startup ───────►│  not_ready   │◄────── health check fails
                    └──────┬───────┘           (threshold met)
                           │
                    first health check passes
                    (success threshold met)
                           │
                           ▼
                    ┌──────────────┐
                    │    ready     │◄────── health check passes
                    └──────┬───────┘           (threshold met)
                           │
                    health check fails (threshold met)
                           │
                           ▼
                    ┌──────────────┐
    SIGTERM ───────►│   draining   │
                    └──────────────┘
```

Note: `draining` is terminal (only from shutdown signal). Health check failures go to `not_ready`, which can recover to `ready`.

### Configuration

New config options:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--health-check-path` | `GIMLET_AGENT_HEALTH_CHECK_PATH` | `/health` | HTTP path for health checks |
| `--health-check-interval` | `GIMLET_AGENT_HEALTH_CHECK_INTERVAL` | `5s` | Health check frequency |
| `--health-check-timeout` | `GIMLET_AGENT_HEALTH_CHECK_TIMEOUT` | `3s` | HTTP request timeout |
| `--health-check-codes` | `GIMLET_AGENT_HEALTH_CHECK_CODES` | `200-299` | Accepted HTTP status codes (e.g., `200`, `200-299`, `200,204,301-399`) |
| `--health-check-failure-threshold` | `GIMLET_AGENT_HEALTH_CHECK_FAILURE_THRESHOLD` | `2` | Consecutive failures to mark not_ready |
| `--health-check-success-threshold` | `GIMLET_AGENT_HEALTH_CHECK_SUCCESS_THRESHOLD` | `1` | Consecutive successes to mark ready |

**Examples:**

```bash
# Default: check /health every 5s
gimlet-agent --target-url http://myapp:8080

# Custom health path
gimlet-agent --target-url http://myapp:8080 --health-check-path /healthz

# Faster detection (1s interval, 1 failure = not_ready)
gimlet-agent --target-url http://myapp:8080 \
  --health-check-interval 1s \
  --health-check-failure-threshold 1

# Slower, more tolerant (10s interval, 3 failures needed)
gimlet-agent --target-url http://myapp:8080 \
  --health-check-interval 10s \
  --health-check-failure-threshold 3
```

## Implementation Plan

### Commit 1: Add health check config options

- Add new fields to `Config` struct
- Add flag definitions and env var resolution
- Add config logging on startup

### Commit 2: Add `not_ready` state to message types

- Update `StateChangeMessage` comment to include "not_ready"
- Add `sendNotReady()` function in agent main.go
- Update server to handle "not_ready" message type

### Commit 3: Implement health checker

- Create `src/agent/health/checker.go` with:
  - `Checker` struct holding config, HTTP client, state
  - `Run()` method that performs periodic checks in a goroutine
  - Threshold-based state transitions
  - Channel-based state change notifications
  - `Stop()` method for graceful shutdown

### Commit 4: Integrate health checker into agent lifecycle

- Start health checker before connection monitoring
- Wait for initial health state before connecting to servers
- Subscribe to state changes and broadcast to all connected servers
- Health checker stops when agent receives shutdown signal

### Commit 5: Add unit tests for health checker

- Test threshold logic (consecutive failures/successes)
- Test state transitions (not_ready → ready → not_ready)
- Test HTTP client behavior (success, timeout, non-2xx)
- Use httptest for deterministic HTTP responses

### Commit 6: Update E2E tests

- Test that agent doesn't become ready with unreachable backend
- Test ready → not_ready transition when backend stops
- Test not_ready → ready recovery when backend returns

## Files to Modify

| File | Changes |
|------|---------|
| `src/agent/config/config.go` | Add health check config fields |
| `src/agent/main.go` | Integrate health checker, manage state |
| `src/agent/messages/messages.go` | Update comment for not_ready |
| `src/agent/health/checker.go` | New file: health check logic |
| `src/server/main.go` | Handle "not_ready" message type |
| `src/server/agentmgr/agent_test.go` | Test not_ready state |
| `tests/test_e2e.py` | Add health check E2E tests |

## Edge Cases

**Backend has no /health endpoint:**
- User configures `--health-check-path /` or another existing endpoint
- Any 2xx response counts as healthy

**Backend returns 200 but with error body:**
- We don't inspect body, only status code
- If backend wants to signal unhealthy, it should return non-2xx

**Health check slower than interval:**
- Each check runs independently on the interval
- Slow checks don't stack (ticker resets after each check completes)

**Agent connects to server before health check completes:**
- Agent connects immediately but sends `not_ready` state
- Server won't route requests until `ready` received
- When health check passes, agent sends `ready` to all connected servers

## Non-Goals (for now)

- TCP-only health check mode (could add later if needed)
- Response body validation
- Health check metrics/observability (could add later)
- Circuit breaker pattern (health check serves this purpose)
