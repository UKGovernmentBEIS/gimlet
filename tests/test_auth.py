"""
JWT authentication tests for Gimlet.

Tests JWT validation for both agent registration and client requests.
"""

import pytest
import requests
import websocket
from pathlib import Path


BASE_URL = "http://localhost:8080"
CONTROL_WS_URL = "ws://localhost:8080/agent"
CREDENTIALS_DIR = Path(__file__).parent / "resources" / "credentials"
JWT_KEY_PATH = CREDENTIALS_DIR / "jwt-signing-key.pem"


def _make_request(method, path, service, headers, **kwargs):
    """Helper to make requests with path-based service routing."""
    return requests.request(
        method, f"{BASE_URL}/services/{service}{path}", headers=headers, **kwargs
    )


def test_missing_auth_header():
    """Test that requests without Authorization header are rejected."""
    resp = _make_request("GET", "/headers", "model-v1", {})
    assert resp.status_code == 401
    assert "Missing Authorization header" in resp.text


def test_invalid_auth_format():
    """Test that requests with invalid Authorization format are rejected."""
    headers = {"Authorization": "InvalidFormat token123"}
    resp = _make_request("GET", "/headers", "model-v1", headers)
    assert resp.status_code == 401
    assert "Invalid Authorization header format" in resp.text


def test_invalid_jwt_signature(client_jwt):
    """Test that JWT with invalid signature is rejected."""
    # Tamper with the JWT by changing the last character
    tampered_jwt = client_jwt[:-5] + "XXXXX"
    headers = {"Authorization": f"Bearer {tampered_jwt}"}
    resp = _make_request("GET", "/headers", "model-v1", headers)
    assert resp.status_code == 401
    assert "Invalid signature" in resp.text


def test_valid_client_jwt_wildcard(auth_headers):
    """Test that client JWT with wildcard service access works."""
    # Client JWT has "*" so should access both services
    resp_v1 = _make_request("GET", "/headers", "model-v1", auth_headers)
    resp_v2 = _make_request("GET", "/", "model-v2", auth_headers)  # nginx autoindex

    assert resp_v1.status_code == 200
    assert resp_v2.status_code == 200


def test_client_jwt_service_restriction():
    """Test that client JWT respects service restrictions."""
    # Generate a JWT that only allows access to model-v1
    import subprocess

    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "test-restricted",
            "--services",
            "model-v1",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    restricted_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {restricted_jwt}"}

    # Should be able to access model-v1
    resp_v1 = _make_request("GET", "/headers", "model-v1", headers)
    assert resp_v1.status_code == 200

    # Should NOT be able to access model-v2
    resp_v2 = _make_request("GET", "/", "model-v2", headers)  # nginx autoindex
    assert resp_v2.status_code == 403
    assert "Forbidden" in resp_v2.text


def test_client_jwt_wildcard_pattern():
    """Test that client JWT wildcard patterns work correctly."""
    import subprocess

    # Generate JWT with pattern "model-*" (should match model-v1 and model-v2)
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "test-pattern",
            "--services",
            "model-*",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    pattern_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {pattern_jwt}"}

    # Should match both model-v1 and model-v2
    resp_v1 = _make_request("GET", "/headers", "model-v1", headers)
    resp_v2 = _make_request("GET", "/", "model-v2", headers)  # nginx autoindex

    assert resp_v1.status_code == 200
    assert resp_v2.status_code == 200


def test_expired_jwt():
    """Test that expired JWT is rejected."""
    import subprocess

    # Generate JWT with very short expiry (1 second)
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "test-expired",
            "--services",
            "*",
            "--duration",
            "1s",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    expired_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {expired_jwt}"}

    # Wait for JWT to expire
    import time

    time.sleep(2)

    # Should be rejected
    resp = _make_request("GET", "/headers", "model-v1", headers)
    assert resp.status_code == 401
    assert "Token expired" in resp.text


def test_wrong_audience_jwt():
    """Test that JWT with wrong audience is rejected."""
    import subprocess

    # Generate an agent JWT (aud: gimlet-agent) and try to use it for client requests
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "agent",
            "--subject",
            "fake-agent",
            "--service",
            "model-v1",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    agent_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {agent_jwt}"}

    # Should be rejected (wrong audience)
    resp = _make_request("GET", "/headers", "model-v1", headers)
    assert resp.status_code == 401
    assert "Unauthorized" in resp.text


def test_agent_registration_missing_jwt():
    """Test that agent registration without JWT is rejected."""
    try:
        ws = websocket.create_connection(
            CONTROL_WS_URL, host="control.local", timeout=2
        )
        ws.close()
        # If we got here, the connection was accepted without auth
        pytest.fail("Agent connection without JWT should be rejected")
    except Exception as e:
        # Should fail with 401 or connection error
        assert (
            "401" in str(e) or "Unauthorized" in str(e) or "handshake" in str(e).lower()
        )


def test_agent_registration_invalid_jwt():
    """Test that agent registration with invalid JWT is rejected."""
    # Try to connect with invalid JWT
    try:
        ws = websocket.create_connection(
            CONTROL_WS_URL,
            host="control.local",
            header=["Authorization: Bearer invalid.jwt.token"],
            timeout=2,
        )
        ws.close()
        pytest.fail("Agent connection with invalid JWT should be rejected")
    except Exception as e:
        # Should fail with 401
        assert "401" in str(e) or "Unauthorized" in str(e)


def test_agent_registration_client_jwt():
    """Test that agent cannot register using a client JWT (wrong audience)."""
    import subprocess

    # Generate a client JWT and try to use it for agent registration
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "fake-agent",
            "--services",
            "*",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    client_jwt = result.stdout.strip()

    try:
        ws = websocket.create_connection(
            CONTROL_WS_URL,
            host="control.local",
            header=[f"Authorization: Bearer {client_jwt}"],
            timeout=2,
        )
        ws.close()
        pytest.fail("Agent connection with client JWT should be rejected")
    except Exception as e:
        # Should fail with 401 (wrong audience)
        assert "401" in str(e) or "Unauthorized" in str(e)


def test_agent_registration_expired_jwt():
    """Test that agent registration with expired JWT is rejected."""
    import subprocess
    import time

    # Generate JWT with 1 second expiry
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "agent",
            "--subject",
            "test-agent",
            "--service",
            "model-v1",
            "--duration",
            "1s",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    expired_jwt = result.stdout.strip()

    # Wait for expiry
    time.sleep(2)

    try:
        ws = websocket.create_connection(
            CONTROL_WS_URL,
            host="control.local",
            header=[f"Authorization: Bearer {expired_jwt}"],
            timeout=2,
        )
        ws.close()
        pytest.fail("Agent connection with expired JWT should be rejected")
    except Exception as e:
        # Should fail with 401
        assert "401" in str(e) or "Unauthorized" in str(e)


def test_multiple_services_in_client_jwt():
    """Test that client can access multiple services with single JWT."""
    import subprocess

    # Generate JWT with multiple specific services
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "multi-service-client",
            "--services",
            "model-v1,model-v2",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    multi_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {multi_jwt}"}

    # Should be able to access both services
    resp_v1 = _make_request("GET", "/headers", "model-v1", headers)
    resp_v2 = _make_request("GET", "/", "model-v2", headers)  # nginx autoindex

    assert resp_v1.status_code == 200
    assert resp_v2.status_code == 200


def test_client_jwt_no_wildcard_denied():
    """Test that client without wildcard cannot access arbitrary services."""
    import subprocess

    # Generate JWT for only model-v1
    result = subprocess.run(
        [
            "uv",
            "run",
            "gimlet",
            "jwt",
            "client",
            "--subject",
            "restricted-client",
            "--services",
            "model-v1",
            "--duration",
            "1h",
            "--private-key-file",
            str(JWT_KEY_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    restricted_jwt = result.stdout.strip()
    headers = {"Authorization": f"Bearer {restricted_jwt}"}

    # Should access model-v1
    resp_v1 = _make_request("GET", "/headers", "model-v1", headers)
    assert resp_v1.status_code == 200

    # Should NOT access model-v2
    resp_v2 = _make_request("GET", "/", "model-v2", headers)  # nginx autoindex
    assert resp_v2.status_code == 403


def test_agent_duplicate_connection_rejected():
    """Test that duplicate agent connection to same control server is rejected."""
    import json

    # Use an existing agent's JWT
    jwt_path = Path(__file__).parent / "resources" / "credentials" / "agent-v1-1.jwt"
    agent_jwt = jwt_path.read_text().strip()

    # With 2 servers behind a load balancer, we need to create enough connections
    # to guarantee at least one hits a server that already has this agent connected.
    # By pigeonhole principle: 3 connections to 2 servers = at least one duplicate.
    connections = []
    responses = []

    for i in range(3):
        ws = websocket.create_connection(
            CONTROL_WS_URL,
            host="control.local",
            header=[f"Authorization: Bearer {agent_jwt}"],
            timeout=5,
        )
        msg = ws.recv()
        data = json.loads(msg)
        connections.append(ws)
        responses.append(data)

    # Clean up connections
    for ws in connections:
        ws.close()

    # At least one response should be a duplicate rejection error
    duplicate_errors = [r for r in responses if "error" in r]
    assert len(duplicate_errors) >= 1, f"Expected at least one duplicate rejection, got responses: {responses}"

    # Verify the error message is correct
    for error_response in duplicate_errors:
        assert (
            "create multiple connections to a server with the same jwt"
            in error_response["error"].lower()
        ), f"Wrong error message: {error_response['error']}"


def test_status_requires_auth():
    """Test that /status without auth header returns 401."""
    resp = requests.get(f"{BASE_URL}/status")
    assert resp.status_code == 401
    assert "Missing Authorization header" in resp.text


def test_status_rejects_unscoped_token(auth_headers):
    """Test that /status rejects a standard client JWT without status scope."""
    resp = requests.get(f"{BASE_URL}/status", headers=auth_headers)
    assert resp.status_code == 401


def test_status_accepts_scoped_token(status_auth_headers):
    """Test that /status accepts a JWT with the status scope."""
    resp = requests.get(f"{BASE_URL}/status", headers=status_auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "server_id" in data
    assert "services" in data


def test_health_still_unauthenticated():
    """Regression guard: /health should remain unauthenticated."""
    resp = requests.get(f"{BASE_URL}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
