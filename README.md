# Gimlet

**A reverse HTTP tunnel for exposing services from private networks.** Gimlet creates a **one-way bridge** that lets external clients reach services running behind NAT or firewalls—without opening any inbound ports. Your services stay hidden from the public internet while remaining accessible to authenticated clients through the tunnel.

New backend services can be exposed on-demand. Client credentials can be scoped to specific services, or created with wildcards which allow access by matching against service name.

## How Does It Work?

Gimlet uses **outbound-initiated connections** to avoid firewall/NAT issues:

1. **Agents establish outbound WebSocket connections** from your private network to the Gimlet server
2. **Clients send HTTP requests** to the Gimlet server
3. **Servers broker requests through existing agent connections** to your backend
4. **Responses flow back** through the same tunnel

```
                       TLS termination
┌────────┐   HTTPS   ┌──────────────┐  HTTP   ┌────────┐  WebSocket  ┌───────┐   HTTP   ┌─────────┐
│ Client │──────────▶│ Load Balancer│────────▶│ Server │◀────────────│ Agent │─────────▶│ Backend │
└────────┘           └──────────────┘         └────────┘             └───────┘          └─────────┘
  (you)                                      (public net)            (private)           (private)
```

This is the opposite of a traditional VPN where you connect TO a network—here, specific services are **pulled out** to be reachable while everything else stays private.

> [!IMPORTANT]
> **The Gimlet server listens on plain HTTP only.** You must deploy a TLS-terminating load balancer (AWS ALB, nginx, etc.) in front of it to provide HTTPS for clients.
>
> Gimlet forwards HTTP requests and responses. The server and agent handle HTTP protocol details (headers, chunked encoding, etc.) automatically. Your backends must speak HTTP—HTTPS backends are not currently supported.

---

## Deployment

See `examples/fly-io/` for instructions on deploying to fly.io.

### Load Balancer Configuration

> [!IMPORTANT]
> **The load balancer MUST use round-robin routing. Do NOT enable sticky sessions.**
>
> Agents discover servers by repeatedly connecting through the load balancer. With sticky sessions, an agent would only ever see one server, breaking the full-mesh topology.
>
> **Compatible:** AWS ALB (default), nginx (default), Kubernetes Service (default)
>
> **Incompatible:** AWS ALB with stickiness, nginx with `ip_hash`, any consistent hashing

All traffic goes to port 8080. The server handles path-based routing internally.

### Token Setup

Generate a keypair:
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Generate tokens using the CLI:
```bash
# Agent token (for registering a service)
uv run gimlet jwt agent --subject my-agent-1 --service my-model --duration 24h --private-key-file private.pem

# Client token (for accessing services)
uv run gimlet jwt client --subject my-user --services "my-*" --duration 8h --private-key-file private.pem
```

For AWS KMS signing (recommended for production):
```bash
# Agent token signed with KMS
uv run gimlet jwt agent --subject my-agent-1 --service my-model --duration 24h --kms-key-arn arn:aws:kms:us-east-1:123456789:key/abc-123

# Export public key from KMS for server configuration
uv run gimlet jwt export-public-key --kms-key-arn arn:aws:kms:us-east-1:123456789:key/abc-123 -o public.pem
```

The server needs only the public key. Keep the private key (or KMS key) secure for token generation.

### Making Requests

Client requests use path-based routing: `/services/<service-name>/<path>`

```bash
curl https://gimlet.example.com/services/my-model/predict \
  -H "Authorization: Bearer $(cat client.token)" \
  -d '{"input": "data"}'
```

The `/services/my-model` prefix is stripped before the request reaches your backend, so your backend sees `/predict`.


---

## Configuration Reference

Configuration can be set via CLI flags or environment variables (CLI flags take precedence).

### Server

| CLI Flag | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--http-port` | `GIMLET_SERVER_HTTP_PORT` | `8080` | Server port |
| `--metrics-port` | `GIMLET_SERVER_METRICS_PORT` | `9090` | Separate port for `/metrics` endpoint |
| `--health-port` | `GIMLET_SERVER_HEALTH_PORT` | - | Separate port for `/health` (if unset, served on main port) |
| `--server-id` | `GIMLET_SERVER_SERVER_ID` | random UUID | Server identifier |
| `--token-public-key-file` | `GIMLET_SERVER_TOKEN_PUBLIC_KEY_FILE` | - | Path to RSA public key for token validation |
| `--token-public-key-dir` | `GIMLET_SERVER_TOKEN_PUBLIC_KEY_DIR` | - | Directory of public keys (supports rotation) |
| `--token-public-key` | `GIMLET_SERVER_TOKEN_PUBLIC_KEY` | - | RSA public key PEM data (alternative to file) |
| `--token-issuer` | `GIMLET_SERVER_TOKEN_ISSUER` | `gimlet` | Expected token issuer |
| `--idle-timeout` | `GIMLET_SERVER_IDLE_TIMEOUT` | `10m` | Max idle time before request cancelled |
| `--shutdown-timeout` | `GIMLET_SERVER_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown timeout for draining requests |
| `--response-buffer-size` | `GIMLET_SERVER_RESPONSE_BUFFER_SIZE` | `100` | Response channel buffer size |
| `--max-concurrent-requests` | `GIMLET_SERVER_MAX_CONCURRENT_REQUESTS` | `1000` | Max concurrent requests (0 = unlimited) |
| `--log-level` | `GIMLET_SERVER_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARN, ERROR |
| `--log-format` | `GIMLET_SERVER_LOG_FORMAT` | `json` | Log format: json, console |

### Agent

| CLI Flag | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--server-url` | `GIMLET_AGENT_SERVER_URL` | `ws://server:8080/agent` | WebSocket URL to gimlet server |
| `--target-url` | `GIMLET_AGENT_TARGET_URL` | `http://backend:8000` | Local backend URL |
| `--token-file` | `GIMLET_AGENT_TOKEN_FILE` | - | Path to agent token |
| `--token` | `GIMLET_AGENT_TOKEN` | - | Token string (alternative to file) |
| `--connection-check-interval` | `GIMLET_AGENT_CONNECTION_CHECK_INTERVAL` | `5s` | How often to probe for new servers |
| `--shutdown-timeout` | `GIMLET_AGENT_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown timeout for draining requests |
| `--max-concurrent-requests` | `GIMLET_AGENT_MAX_CONCURRENT_REQUESTS` | `50` | Max concurrent requests (0 = unlimited) |
| `--request-buffer-size` | `GIMLET_AGENT_REQUEST_BUFFER_SIZE` | `100` | Request channel buffer size |
| `--log-level` | `GIMLET_AGENT_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARN, ERROR |
| `--log-format` | `GIMLET_AGENT_LOG_FORMAT` | `json` | Log format: json, console |

### Python CLI

The CLI provides JWT management via `uv run gimlet jwt <command>`.

**Subcommands:**

| Command | Description |
|---------|-------------|
| `agent` | Generate agent registration JWT (aud: gimlet-agent) |
| `client` | Generate client request JWT (aud: gimlet-client) |
| `inspect` | Decode and optionally verify a JWT |
| `export-public-key` | Export public key from AWS KMS in PEM format |

**Common options for `agent` and `client`:**

| CLI Flag | Env Var | Description |
|----------|---------|-------------|
| `--private-key-file` | `GIMLET_JWT_PRIVATE_KEY_FILE` | Private key file for signing |
| `--kms-key-arn` | `GIMLET_JWT_KMS_KEY_ARN` | AWS KMS key ARN for signing |
| `--issuer` | `GIMLET_JWT_ISSUER` | Token issuer claim (default: `gimlet`) |
| `--duration` | - | Token lifetime, e.g. `24h`, `7d` (default: `24h`) |
| `--json` | - | Output as JSON with metadata |

> Note: Exactly one of `--private-key-file` or `--kms-key-arn` must be provided.

---

## Metrics

> [!WARNING]
> **The `/metrics` endpoint is unauthenticated.** It exposes service names, agent IDs, and request counts which could reveal your infrastructure topology.
>
> By default, metrics are served on port 9090 (separate from the main port). Ensure this port is not exposed publicly, or place authentication in front of it.

Servers expose Prometheus metrics at `/metrics`:

- `gimlet_requests_total` - Total requests by service and status code
- `gimlet_request_duration_seconds` - Request latency histogram
- `gimlet_active_requests` - In-flight requests per service
- `gimlet_agent_connections` - Connected agents per service
- `gimlet_rate_limit_rejections_total` - Rate limit rejections

Agents push their metrics to servers, which then expose them:

- `gimlet_agent_concurrent_requests` - Per-agent concurrent requests
- `gimlet_agent_backend_failures_total` - Backend connection failures
- `gimlet_agent_draining` - Whether agent is draining (shutting down gracefully)

---

## Local Development

### Quick Start

```bash
make build     # Build race-enabled Go binaries
make up        # Start all services (generates keys/tokens if needed)
make test-e2e  # Run tests
```

### Test a Request

```bash
curl http://localhost:8080/services/model-v1/headers \
  -H "Authorization: Bearer $(cat tests/resources/credentials/client.jwt)"
```

### Architecture

The test infrastructure in `tests/resources/docker-compose.yml` runs:

- **2 servers** (`server-1`, `server-2`) - demonstrates full-mesh topology
- **3 agents** - 2 for `model-v1` (load balancing), 1 for `model-v2`
- **nginx** - load balancer on port 8080, round-robins to servers
- **backend-v1** - [httpbun](https://github.com/sharat87/httpbun) for realistic HTTP testing (`/delay`, `/headers`, `/post`, `/sse`)
- **backend-v2** - nginx serving static files
- **prometheus** - scrapes server metrics (port 9090)
- **grafana** - dashboards (port 3000, no login required)

### Running Tests

```bash
make test-go          # Go unit tests with race detector
make test-e2e         # E2E + auth tests (parallel)
make test-disruption  # Failure/recovery tests (sequential, restarts containers)
make test-all         # Everything
```

**Race detection:** Both unit tests and E2E tests use race-enabled binaries to catch data races.

### Build Targets

```bash
make build      # Race-enabled binaries for local dev (default)
make build-go   # Production binaries (static, cross-compiled for amd64 + arm64)
```

### Logs

```bash
docker compose -f tests/resources/docker-compose.yml logs -f server
docker compose -f tests/resources/docker-compose.yml logs -f agent-v1-1 agent-v1-2
```

---

## Contributing

This project uses [Claude Code](https://docs.anthropic.com/en/docs/claude-code) for development. See `CLAUDE.md` for architecture details and development guidelines.