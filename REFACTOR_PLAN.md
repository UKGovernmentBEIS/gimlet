# HTTP Handler Refactor Plan

## Goal

Simplify the architecture by:
1. Agent parses HTTP responses (no longer "dumb pipe" for responses)
2. Server uses `net/http` handler (not raw TCP)
3. Remove response completion detection complexity
4. Maintain streaming in both directions (no body buffering)

## New Architecture

```
Request flow:
Client → nginx → Server (net/http) → Agent → Backend
                 r.Body.Read()        raw TCP write
                 (streaming)          (streaming)

Response flow:
Backend → Agent → Server → Client
          http.ReadResponse()   w.Write() + Flush()
          resp.Body.Read()      (streaming)
          (streaming)
```

## Frame Protocol Changes

**Current START frame**: Raw HTTP bytes (headers + possibly body)
**New START frame**: Headers only (HTTP format, no body)

```
Current:  START [HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello...]
New:      START [HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n]
          DATA  [Hello...]
```

This is a **breaking protocol change** - not backwards compatible. Deploy new agent and server binaries together. (Runtime lifecycles remain fully independent.)

---

## Phase 1: Agent - Parse HTTP Responses

**File**: `src/agent/connection/handler.go`

### Current code (simplified):
```go
func (h *Handler) handleHTTPRequest(requestID string, frameCh <-chan []byte) {
    conn, _ := h.dialer.DialTimeout("tcp", h.backendAddr, 5*time.Second)

    // Stream request frames → backend (stays the same)
    go func() {
        for frame := range frameCh {
            // Write payload to conn
        }
    }()

    // Stream backend → response frames (CHANGES)
    buffer := make([]byte, 64*1024)
    firstChunk := true
    for {
        n, _ := conn.Read(buffer)  // Raw TCP read
        if firstChunk {
            h.writeFrame(START, requestID, buffer[:n])
            firstChunk = false
        } else {
            h.writeFrame(DATA, requestID, buffer[:n])
        }
    }
    h.writeFrame(END, requestID, nil)
}
```

### New code:
```go
func (h *Handler) handleHTTPRequest(requestID string, frameCh <-chan []byte) {
    conn, _ := h.dialer.DialTimeout("tcp", h.backendAddr, 5*time.Second)

    // Stream request frames → backend (unchanged)
    go func() {
        for frame := range frameCh {
            // Write payload to conn
        }
    }()

    // Parse HTTP response
    resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
    if err != nil {
        h.sendErrorResponse(requestID, 502, "Bad Gateway")
        return
    }
    defer resp.Body.Close()

    // Send headers as START frame
    headers := serializeResponseHeaders(resp)
    h.writeFrame(START, requestID, headers)

    // Stream decoded body as DATA frames
    buffer := make([]byte, 64*1024)
    for {
        n, err := resp.Body.Read(buffer)  // Streaming, handles chunked decoding
        if n > 0 {
            h.writeFrame(DATA, requestID, buffer[:n])
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            // Handle error
            break
        }
    }

    // Response complete - we know because resp.Body returned EOF
    h.writeFrame(END, requestID, nil)
}

func serializeResponseHeaders(resp *http.Response) []byte {
    var buf bytes.Buffer
    fmt.Fprintf(&buf, "HTTP/%d.%d %d %s\r\n",
        resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)
    resp.Header.Write(&buf)
    buf.WriteString("\r\n")
    return buf.Bytes()
}
```

### Key changes:
- Use `http.ReadResponse()` to parse response
- `resp.Body.Read()` returns decoded bytes (chunked decoding handled by Go)
- START frame contains only headers
- We know response is complete when `resp.Body.Read()` returns EOF
- No more guessing about response completion!

### CANCEL handling (stays mostly the same):
```go
case protocol.FrameTypeCancel:
    reqLogger.Debug().Msg("Released by server")
    conn.Close()  // Close backend connection, unblocks resp.Body.Read()
    return
```

---

## Phase 2: Server - Use net/http Handler

**File**: `src/server/handlers/http.go`

### New ServeHTTP implementation:
```go
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Track for graceful shutdown
    h.activeRequests.Add(1)
    defer h.activeRequests.Done()

    ctx := r.Context()

    // Extract service from path
    service, rewrittenPath := extractServiceFromPath(r.URL.Path)
    if service == "" {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    // Validate JWT (same as current)
    clientID, services, err := h.validateClientJWT(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Select agent (same as current)
    agent, err := h.selectAgent(service)
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }

    requestID := uuid.New().String()
    respCh := agent.RegisterResponseChannel(requestID, h.responseChannelBufferSize)
    defer agent.CleanupRequest(requestID)
    defer agent.SendHTTPRequestCancel(requestID)  // Always send CANCEL when handler returns

    // Stream request to agent
    if err := h.streamRequestToAgent(ctx, agent, requestID, r, rewrittenPath); err != nil {
        http.Error(w, "Failed to forward request", http.StatusBadGateway)
        return
    }

    // Stream response from agent
    h.streamResponseToClient(ctx, w, respCh, requestID)
}

func (h *HTTPHandler) streamRequestToAgent(ctx context.Context, agent *agentmgr.Agent, requestID string, r *http.Request, rewrittenPath string) error {
    // Send headers as START frame
    headers := serializeRequestHeaders(r, rewrittenPath)
    if err := agent.SendHTTPRequestStart(requestID, headers); err != nil {
        return err
    }

    // Stream body as DATA frames
    if r.Body != nil {
        buf := make([]byte, 64*1024)
        for {
            select {
            case <-ctx.Done():
                return ctx.Err()
            default:
            }

            n, err := r.Body.Read(buf)
            if n > 0 {
                if err := agent.SendHTTPRequestData(requestID, buf[:n]); err != nil {
                    return err
                }
            }
            if err == io.EOF {
                break
            }
            if err != nil {
                return err
            }
        }
    }

    // Send END frame
    return agent.SendHTTPRequestEnd(requestID, "")
}

func (h *HTTPHandler) streamResponseToClient(ctx context.Context, w http.ResponseWriter, respCh <-chan []byte, requestID string) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming not supported", http.StatusInternalServerError)
        return
    }

    headersSent := false

    for {
        select {
        case <-ctx.Done():
            // Client disconnected
            return

        case frame, ok := <-respCh:
            if !ok {
                // Channel closed (agent disconnected)
                if !headersSent {
                    http.Error(w, "Agent disconnected", http.StatusBadGateway)
                }
                return
            }

            frameType, _, payload, _ := protocol.DecodeFrame(frame)

            switch frameType {
            case protocol.FrameTypeStart:
                // Parse response headers
                resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
                if err != nil {
                    http.Error(w, "Invalid response", http.StatusBadGateway)
                    return
                }

                // Copy headers to ResponseWriter
                for key, values := range resp.Header {
                    for _, v := range values {
                        w.Header().Add(key, v)
                    }
                }
                w.WriteHeader(resp.StatusCode)
                headersSent = true

            case protocol.FrameTypeData:
                if !headersSent {
                    continue  // Ignore data before headers
                }
                w.Write(payload)
                flusher.Flush()

            case protocol.FrameTypeEnd:
                // Response complete, handler returns
                // CANCEL sent via defer
                return
            }
        }
    }
}
```

---

## Phase 3: Server main.go - Simplify Routing

**File**: `src/server/main.go`

### Current (complex):
```go
// Raw TCP listener with manual path routing
tcpListener, _ := net.Listen("tcp", ":"+cfg.HTTPPort)
go func() {
    for {
        conn, _ := tcpListener.Accept()
        go cs.routeConnection(conn, httpServer)  // Peeks at path
    }
}()

func (cs *Server) routeConnection(conn net.Conn, httpServer *http.Server) {
    // Read request line, check if /services/*, route accordingly
    // Uses prefixConn, singleConnListener hacks
}
```

### New (simple):
```go
// Just use http.Server with mux
mux := http.NewServeMux()
mux.Handle("/services/", cs.httpHandler)  // New ServeHTTP handler
mux.HandleFunc("/agent", cs.handleAgentWebSocket)
mux.HandleFunc("/health", metrics.HealthHandler(cs))
mux.Handle("/metrics", metrics.MetricsHandler())

httpServer := &http.Server{
    Addr:    ":" + cfg.HTTPPort,
    Handler: mux,
}

go httpServer.ListenAndServe()

// Graceful shutdown
<-sigChan
httpServer.Shutdown(ctx)  // Stops accepting, waits for handlers
cs.activeRequests.Wait()  // Extra wait for hijacked connections if any
```

### Remove:
- `routeConnection()`
- `prefixConn` struct
- `singleConnListener` struct

---

## Phase 4: Clean Up

### Remove from `http.go`:
- `HandleTCPConnection()` - replaced by `ServeHTTP()`
- `streamResponseToTCP()` - replaced by `streamResponseToClient()`
- Response completion detection code:
  - `containsChunkedTerminator()`
  - `chunkedTerminator` variable
  - Content-Length tracking
  - Client close monitoring goroutine

### Update tests:
- `http_integration_test.go` - update to use new frame format (headers-only START)
- Remove completion detection tests (no longer needed)
- Add new tests for streaming behavior

---

## Implementation Order

1. **Agent changes first** (Phase 1)
   - Modify agent to parse HTTP and send headers-only START
   - This is a breaking change - tests will fail until server is updated

2. **Server handler** (Phase 2)
   - Implement new `ServeHTTP` method
   - Keep old `HandleTCPConnection` temporarily

3. **Server routing** (Phase 3)
   - Switch mux to use new handler
   - Remove `routeConnection`

4. **Clean up** (Phase 4)
   - Remove old code
   - Update tests

5. **Test everything**
   - Unit tests
   - E2E tests
   - Graceful shutdown test (the one that's currently failing)
   - SSE streaming
   - Large file transfers

---

## Risk Mitigation

- **Breaking protocol change**: New START frame format isn't backwards compatible. Deploy updated agent and server binaries in same release. (This is fine for greenfield - no gradual rollout needed.)
- **Rollback plan**: Keep old code on a branch
- **Testing**: Run full test suite after each phase

---

## Success Criteria

1. `test_server_graceful_shutdown_drains_requests` passes
2. All E2E tests pass
3. No response completion detection code
4. No `routeConnection` / `prefixConn` / `singleConnListener`
5. Streaming works (verify with large files, SSE)
6. Code is simpler and easier to understand

---

## Additional Considerations

### Hop-by-hop Headers
When copying response headers to `ResponseWriter`, filter out:
- `Connection`
- `Keep-Alive`
- `Transfer-Encoding` (Go handles this)
- `Proxy-Authenticate`, `Proxy-Authorization`
- `TE`, `Trailer`, `Upgrade`

### Idle Timeout
Current code has idle timeout for responses. With net/http:
- Use `http.Server.ReadTimeout` and `WriteTimeout` for overall limits
- For per-request idle timeout, use `context.WithTimeout` in handler
- Or use `http.ResponseController` (Go 1.20+) for deadline control

### Metrics to Preserve
- `ActiveRequests` gauge (per service)
- `RequestDuration` histogram
- `RequestsTotal` counter (with labels: service, agentID, clientID, statusCode)
- `WebsocketMessages` counter
- `ResponseChannelBuffer` gauge
- `RateLimitRejections` counter

### Rate Limiting
Preserve the semaphore-based rate limiting:
```go
if h.requestSemaphore != nil {
    select {
    case h.requestSemaphore <- struct{}{}:
        defer func() { <-h.requestSemaphore }()
    default:
        http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
        return
    }
}
```

### Agent Selection
Preserve round-robin logic with sorted agent list for deterministic ordering.

### Error Response Format
Keep consistent error format using `errors.Format()` from `server/errors` package.

### Context Cancellation Flow
```
Client disconnects
    → r.Context().Done() fires
    → Handler detects in select
    → Send CANCEL to agent (via defer or explicit)
    → Agent receives CANCEL
    → Agent closes backend connection
    → resp.Body.Read() returns error
    → Agent sends END frame
    → Handler returns
```

### Request Timeout in Agent
When CANCEL arrives during `resp.Body.Read()`:
```go
// In the goroutine listening for frames
case protocol.FrameTypeCancel:
    conn.Close()  // This will cause resp.Body.Read() to return error
```

### Testing Checklist
- [ ] Basic request/response
- [ ] Streaming response (SSE)
- [ ] Large file upload
- [ ] Large file download
- [ ] Client disconnect mid-request
- [ ] Client disconnect mid-response
- [ ] Agent disconnect mid-request
- [ ] Backend timeout
- [ ] Graceful shutdown with in-flight requests
- [ ] Rate limiting (server-level)
- [ ] Rate limiting (agent-level)
- [ ] JWT validation (client)
- [ ] Service routing
- [ ] Multiple agents for same service (round-robin)
