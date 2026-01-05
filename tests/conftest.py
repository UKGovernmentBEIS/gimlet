"""Pytest configuration and fixtures."""

import time
import pytest
import requests
from pathlib import Path


BASE_URL = "http://localhost:8080"


@pytest.fixture(scope="session")
def client_jwt():
    """Load client JWT from file."""
    jwt_path = Path(__file__).parent / "resources" / "credentials" / "client.jwt"
    if not jwt_path.exists():
        pytest.fail(f"Client JWT not found at {jwt_path}. Run 'make gen-jwts' first.")
    return jwt_path.read_text().strip()


@pytest.fixture(scope="session")
def auth_headers(client_jwt):
    """Return headers with JWT authorization."""
    return {"Authorization": f"Bearer {client_jwt}"}


@pytest.fixture(scope="session", autouse=True)
def wait_for_services(auth_headers):
    """
    Wait for all services to be healthy and stable before running tests.

    This ensures full-mesh topology is established and both model-v1
    and model-v2 services have connected agents. Requires multiple
    consecutive successes to confirm stability.
    """
    services = ["model-v1", "model-v2"]
    timeout = 60  # Max seconds to wait
    required_successes = 3  # Consecutive successes needed per service
    start = time.time()

    for service in services:
        url = f"{BASE_URL}/services/{service}/headers" if service == "model-v1" else f"{BASE_URL}/services/{service}/"
        consecutive_successes = 0

        while time.time() - start < timeout:
            try:
                resp = requests.get(url, headers=auth_headers, timeout=2)
                if resp.status_code == 200:
                    consecutive_successes += 1
                    if consecutive_successes >= required_successes:
                        break
                else:
                    consecutive_successes = 0  # Reset on non-200
            except requests.RequestException:
                consecutive_successes = 0  # Reset on error
            time.sleep(0.5)
        else:
            pytest.fail(f"Service {service} not stable after {timeout}s. Is infrastructure running? (make up)")
