# Gimlet Development Guide

HTTP tunnel exposing services on egress-only networks. See README.md for usage, deployment, and configuration reference.

## Code Style & Philosophy

**Priorities (in order):**
1. **Correctness** - No silent data loss, no silent failures
2. **Multi-tenant safety** - Resource limits, rate limiting
3. **Observability** - Structured logging, metrics
4. **Ephemeral resilience** - Handle agent/backend churn gracefully
5. **Simplicity** - Avoid over-engineering

**Do:**
- Fail fast and loud - errors should propagate, not be swallowed
- Be explicit with types
- Use structured logging with context (requestID, agentID, service)

**Don't:**
- Add defensive nil checks that hide bugs (if `a.b` should exist, let it crash with a clear error rather than silently setting `c = nil`)
- Over-engineer for hypothetical futures
- Add features/refactoring beyond what's requested
- Create abstractions for one-time operations

## Critical Bugs to Watch

- **Buffered channels dropping data** - Response channels (`Agent.requests[].dataCh`) and request channels (`Handler.requestHandlers[].dataCh`) must never silently drop frames
- **Fixed timeouts killing requests** - Agent supports multi-minute responses; don't add `conn.SetDeadline` that breaks this
- **Unbounded resource usage** - Always have limits on goroutines, connections, memory
- **Race conditions** - All tests run with `-race`; concurrent WebSocket writes need mutex protection (see `RealWebSocketConn` in agent)

## Architecture Quick Reference

**Binary frame protocol:** 4 frame types (`start`, `data`, `end`, `cancel`) with requestID prefix. START frames contain HTTP headers only; body is streamed in DATA frames. Agent parses HTTP responses from backends using `http.ReadResponse()`.

**Full-mesh topology:** Each agent connects to ALL servers via probe-based discovery (5s interval through load balancer). Server rejects duplicates.

**Load balancing:** Local-only, round-robin agent selection per server. No cross-server coordination.

**Ephemeral by design:** Agent/backend death is normal operation. 30s max for detection/cleanup via WebSocket ping/pong.

## Code Structure

```
src/server/          # Go server
├── config/          # CLI flags, env vars, config struct
├── handlers/        # HTTP handlers, service routing
├── agentmgr/        # Agent connections, binary frames
├── auth/            # JWT validation
└── main.go          # Orchestration

src/agent/           # Go agent
├── config/          # CLI flags, env vars, config struct
├── connection/      # WebSocket handling, request routing
└── main.go          # Connection monitor, state management

src/gimlet/          # Python CLI for JWT generation

tests/
├── resources/       # docker-compose.yml, nginx config, credentials
├── test_e2e.py      # Parallel E2E tests
├── test_auth.py     # JWT authentication tests
└── test_disruption.py  # Failure/recovery tests (sequential)
```

**Ground truth for configuration:** `src/server/config/config.go` and `src/agent/config/config.go`

## Key Code Paths

**Server request handling** (`src/server/handlers/http.go:ServeHTTP`):
1. Extract service from URL path (`/services/<service>/...`)
2. Rewrite path (strip `/services/<service>` prefix)
3. Validate client JWT
4. Select agent via round-robin from ready agents for service
5. Stream request body as binary frames to agent
6. Stream response frames back to client via `http.ResponseWriter`

**Agent connection** (`src/agent/main.go:tryConnect`):
1. Connect via WebSocket with JWT auth
2. Receive hello message with serverID
3. Store wrapped connection (mutex-protected for concurrent writes)
4. Send ready signal, start handler goroutine

## Testing

```bash
make test-go         # Go unit tests with race detector
make test-e2e        # E2E + auth tests (parallel)
make test-disruption # Failure recovery (sequential, restarts containers)
```

Race detection is enabled everywhere - unit tests use `-race` flag, E2E tests use race-enabled binaries with `GORACE=halt_on_error=1`.

## Local Dev

```bash
make build  # Race-enabled binaries
make up     # Start test infrastructure
make down   # Stop
```

Test infrastructure lives in `tests/resources/docker-compose.yml`.
