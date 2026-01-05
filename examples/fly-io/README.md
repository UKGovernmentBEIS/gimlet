# Deploying Gimlet on Fly.io

This example deploys a Gimlet server on Fly.io.

## Prerequisites

- [Fly CLI](https://fly.io/docs/hands-on/install-flyctl/) installed and authenticated
- AWS CLI configured (for KMS key creation)

## Setup

### 1. Create a KMS signing key

```bash
KMS_KEY_ARN=$(aws kms create-key \
  --key-spec RSA_2048 \
  --key-usage SIGN_VERIFY \
  --description "Gimlet token signing key" \
  --query 'KeyMetadata.Arn' \
  --output text)
```

Export the public key for the server:

```bash
uv run gimlet jwt export-public-key \
  --kms-key-arn $KMS_KEY_ARN \
  -o examples/fly-io/server/keys/primary.pub
```

### 2. Build and prepare binaries

**TODO:** Download from release in multistage docker once app is OSS

```bash
# Build static binaries (from repo root)
make build-go

# Copy binaries to example directory
cp bin/gimlet-server-amd64 examples/fly-io/server/bin/gimlet-server
chmod +x examples/fly-io/server/bin/gimlet-server
cp bin/gimlet-agent-amd64 examples/fly-io/server/bin/gimlet-agent
chmod +x examples/fly-io/server/bin/gimlet-agent
```

### 3. Deploy to Fly.io

```bash
cd examples/fly-io/server
fly apps create gimlet-server  # Choose a unique name if taken
fly deploy
```

## Quick Demo

Start a local web server:

```bash
docker run -d --name demo-server -p 8000:80 nginx:alpine
```

Generate tokens and run the agent:

```bash
cd examples/fly-io/server

AGENT_TOKEN=$(uv run gimlet jwt agent \
  --subject demo-agent \
  --service demo \
  --duration 1h \
  --kms-key-arn $KMS_KEY_ARN)

./bin/gimlet-agent \
  --server-url wss://gimlet-server.fly.dev/agent \
  --target-url http://localhost:8000 \
  --token "$AGENT_TOKEN"
```

In another terminal, make a request:

```bash
CLIENT_TOKEN=$(uv run gimlet jwt client \
  --subject demo-user \
  --services "demo" \
  --duration 1h \
  --kms-key-arn $KMS_KEY_ARN)

curl https://gimlet-server.fly.dev/services/demo/ \
  -H "Authorization: Bearer $CLIENT_TOKEN"
```

Cleanup:

```bash
docker rm -f demo-server
```
