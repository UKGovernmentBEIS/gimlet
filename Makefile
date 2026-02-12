.PHONY: test-go test-e2e test-disruption test-load test-all clean build build-go build-test up down down-v ps logs gen-keys gen-jwts gen-test-data

# Go build cache (persists between builds)
GO_CACHE := -v gimlet-go-cache:/go/pkg

# Docker compose file location
COMPOSE := docker compose -f tests/resources/docker-compose.yml

# Credentials directory
CREDS_DIR := tests/resources/credentials

# Build Go binaries for production (static, no race detection)
build-go:
	@echo "Building production Go binaries for amd64 and arm64..."
	@mkdir -p bin
	@docker volume create gimlet-go-cache > /dev/null 2>&1 || true
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 golang:1.25 go build -buildvcs=false -o ../../bin/gimlet-server-amd64 .
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=arm64 golang:1.25 go build -buildvcs=false -o ../../bin/gimlet-server-arm64 .
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 golang:1.25 go build -buildvcs=false -o ../../bin/gimlet-agent-amd64 .
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=arm64 golang:1.25 go build -buildvcs=false -o ../../bin/gimlet-agent-arm64 .
	@echo "✓ Production binaries built in bin/"
	@ls -lh bin/ | grep gimlet

# Build Go binaries for testing (with race detection, requires glibc)
build-test:
	@echo "Building test Go binaries with race detection..."
	@mkdir -p bin
	@docker volume create gimlet-go-cache > /dev/null 2>&1 || true
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server -e GOOS=linux -e GOARCH=amd64 golang:1.25 go build -race -buildvcs=false -o ../../bin/gimlet-server-amd64 .
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent -e GOOS=linux -e GOARCH=amd64 golang:1.25 go build -race -buildvcs=false -o ../../bin/gimlet-agent-amd64 .
	@echo "✓ Test binaries (with race detection) built in bin/"
	@ls -lh bin/ | grep gimlet

# Run Go unit tests (with race detector by default)
test-go:
	@echo "Running Go unit tests with race detector..."
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent golang:1.25 go mod download
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/server golang:1.25 go test -race ./...
	docker run --rm $(GO_CACHE) -v $(PWD):/workspace -w /workspace/src/agent golang:1.25 go test -race ./...
	@echo "✓ All Go tests passed"

# Run Python E2E tests (parallel safe)
test-e2e:
	@echo "Running Python E2E tests..."
	uv run pytest tests/test_e2e.py tests/test_auth.py -v -n auto

# Run Python disruption tests (sequential, restarts containers)
test-disruption:
	@echo "Running Python disruption tests..."
	uv run pytest tests/test_disruption.py -v

# Run Python load tests (intensive, may take several minutes)
# NOTE: These are for manual testing only, NOT run in CI (too slow)
test-load:
	@echo "Running Python load tests (may take 3-15 minutes)..."
	uv run pytest tests/test_load.py -v

# Run all tests for CI (Go + Python E2E + disruption)
# Load tests excluded - run manually with 'make test-load'
test-all: test-go test-e2e test-disruption
	@echo "✓ All tests passed!"

# Clean build artifacts and containers
clean:
	$(COMPOSE) down -v 2>/dev/null || true
	rm -rf bin/
	rm -rf tests/resources/temp/
	rm -rf $(CREDS_DIR)/

# Build for local testing (race detection enabled)
build: build-test

# Generate test data files (for buffer saturation and load tests)
gen-test-data:
	@echo "Generating test data files..."
	@mkdir -p tests/resources/temp
	@if [ ! -f tests/resources/temp/1mb.bin ]; then \
		dd if=/dev/urandom of=tests/resources/temp/1mb.bin bs=1M count=1 2>/dev/null; \
		echo "✓ Generated tests/resources/temp/1mb.bin (1MB)"; \
	else \
		echo "✓ tests/resources/temp/1mb.bin already exists"; \
	fi
	@if [ ! -f tests/resources/temp/10mb.bin ]; then \
		dd if=/dev/urandom of=tests/resources/temp/10mb.bin bs=1M count=10 2>/dev/null; \
		echo "✓ Generated tests/resources/temp/10mb.bin (10MB)"; \
	else \
		echo "✓ tests/resources/temp/10mb.bin already exists"; \
	fi
	@if [ ! -f tests/resources/temp/50mb.bin ]; then \
		dd if=/dev/zero of=tests/resources/temp/50mb.bin bs=1M count=50 2>/dev/null; \
		echo "✓ Generated tests/resources/temp/50mb.bin (50MB)"; \
	else \
		echo "✓ tests/resources/temp/50mb.bin already exists"; \
	fi

# Start services (generate JWTs and test data first if they don't exist)
up: gen-jwts gen-test-data
	$(COMPOSE) up -d
	@echo "Services starting... (pytest will wait for readiness)"
	@sleep 3

# Stop services
down:
	$(COMPOSE) down

# Stop services and remove volumes
down-v:
	$(COMPOSE) down -v

# Show container status
ps:
	$(COMPOSE) ps

# Show container logs
logs:
	$(COMPOSE) logs

# Generate JWT keys (if they don't exist)
gen-keys:
	@if [ ! -f $(CREDS_DIR)/jwt-signing-key.pem ]; then \
		echo "Generating RSA keypair..."; \
		mkdir -p $(CREDS_DIR); \
		openssl genrsa -out $(CREDS_DIR)/jwt-signing-key.pem 2048 2>/dev/null; \
		openssl rsa -in $(CREDS_DIR)/jwt-signing-key.pem -pubout -out $(CREDS_DIR)/jwt-signing-key.pub 2>/dev/null; \
		chmod 600 $(CREDS_DIR)/jwt-signing-key.pem; \
		echo "✓ Keys generated in $(CREDS_DIR)/"; \
	else \
		echo "✓ Keys already exist in $(CREDS_DIR)/"; \
	fi

# Generate JWTs for docker-compose
gen-jwts: gen-keys
	@echo "Generating JWTs..."
	@mkdir -p $(CREDS_DIR)
	@uv run gimlet jwt agent --subject agent-v1-1 --service model-v1 --duration 24h --private-key-file $(CREDS_DIR)/jwt-signing-key.pem > $(CREDS_DIR)/agent-v1-1.jwt
	@uv run gimlet jwt agent --subject agent-v1-2 --service model-v1 --duration 24h --private-key-file $(CREDS_DIR)/jwt-signing-key.pem > $(CREDS_DIR)/agent-v1-2.jwt
	@uv run gimlet jwt agent --subject agent-v2-1 --service model-v2 --duration 24h --private-key-file $(CREDS_DIR)/jwt-signing-key.pem > $(CREDS_DIR)/agent-v2-1.jwt
	@uv run gimlet jwt client --subject test-client --services "*" --duration 24h --private-key-file $(CREDS_DIR)/jwt-signing-key.pem > $(CREDS_DIR)/client.jwt
	@uv run gimlet jwt client --subject status-client --services "*" --scope status --duration 24h --private-key-file $(CREDS_DIR)/jwt-signing-key.pem > $(CREDS_DIR)/status-client.jwt
	@echo "✓ JWTs generated in $(CREDS_DIR)/"
