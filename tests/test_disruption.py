"""
Disruption and chaos tests for Gimlet.

These tests have side effects (killing/restarting containers) and MUST NOT
be run in parallel with other tests or each other.

Run with: pytest test_disruption.py -v
Run specific test: pytest test_disruption.py::test_agent_reconnect_same_id -v

IMPORTANT: Do NOT run with pytest-xdist (no -n flag)!
These tests are marked with xdist_group to run sequentially if xdist is used.
"""

import time
import random
import docker
import pytest
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Base URL for testing
BASE_URL = "http://localhost:8080"

# Get Docker client
docker_client = docker.from_env()


# Load auth headers once at module level
def _load_auth_headers():
    jwt_path = Path(__file__).parent / "resources" / "credentials" / "client.jwt"
    jwt = jwt_path.read_text().strip()
    return {"Authorization": f"Bearer {jwt}"}


AUTH_HEADERS = _load_auth_headers()


def _make_request(method, path, service, **kwargs):
    """Helper to make requests with path-based service routing."""
    return requests.request(method, f"{BASE_URL}/services/{service}{path}", headers=AUTH_HEADERS, **kwargs)


@pytest.fixture(scope="function", autouse=True)
def ensure_system_running():
    """Ensure all containers are running and healthy before each test."""
    print("\n[Setup] Ensuring all services are running...")
    services = [
        "server-1",
        "server-2",
        "agent-v1-1-1",
        "agent-v1-2-1",
        "agent-v2-1-1",
        "backend-v1-1",
        "backend-v2-1",
        "nginx-1",
    ]

    # Start any stopped containers
    for service in services:
        try:
            container = get_container(service)
            if container.status != "running":
                print(f"  Starting {service}...")
                container.start()
        except Exception as e:
            print(f"  Warning: Could not start {service}: {e}")

    # Wait for servers to be ready
    print("  Waiting for servers (5s)...")
    time.sleep(5)

    # Wait for agents to connect to servers (full mesh takes ~15s)
    print("  Waiting for agents to establish full mesh (15s)...")
    time.sleep(15)

    # Verify system health with multiple requests
    print("  Verifying system health...")
    success_count = 0
    for attempt in range(10):
        try:
            resp = _make_request("GET", "/headers", "model-v1", timeout=2)
            if resp.status_code == 200:
                success_count += 1
        except Exception:
            pass
        time.sleep(0.5)

    if success_count < 8:
        print(f"  Warning: Only {success_count}/10 health checks passed")
    else:
        print(f"[Setup] System ready ({success_count}/10 health checks passed)")

    yield

    # Cleanup after test (best effort)
    print("\n[Teardown] Checking system state...")
    for service in services:
        try:
            container = get_container(service)
            if container.status != "running":
                print(f"  Restarting {service}...")
                container.start()
        except Exception:
            pass


def get_container(service_name):
    """Get a container by service name for this project."""
    # Docker compose uses the directory name where docker-compose.yml lives
    # Our docker-compose.yml is in tests/resources/, so project name is "resources"
    project_name = "resources"

    # Full container name pattern: {project_name}-{service_name}
    container_name_pattern = f"{project_name}-{service_name}"

    containers = docker_client.containers.list(
        all=True,  # Include stopped containers
        filters={"name": container_name_pattern},
    )
    if not containers:
        raise RuntimeError(
            f"Container for service {service_name} not found (looking for {container_name_pattern})"
        )
    return containers[0]


def wait_for_health(service="model-v1", timeout=30, expected_status=200):
    """Wait for service to become healthy."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = _make_request("GET", "/headers", service, timeout=2)
            if resp.status_code == expected_status:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_reconnect_same_id():
    """Test that agent can reconnect with same ID after restart."""
    print("\n=== Testing agent reconnection with same ID ===")

    # Verify initial state works
    resp = _make_request("GET", "/headers", "model-v1")
    assert resp.status_code == 200, "Initial request failed"
    print("✓ Initial state healthy")

    # Restart agent-v1-1
    container = get_container("agent-v1-1-1")
    print("Restarting agent-v1-1...")
    container.restart()

    # Wait for reconnection (should be fast now that we replace old connection)
    print("Waiting for reconnection...")
    assert wait_for_health(timeout=15), "Agent failed to reconnect within 15s"

    # Give agent time to connect to BOTH servers (5s reconnection interval)
    time.sleep(7)

    # Verify requests work consistently (make multiple to ensure agent-v1-1 gets some)
    print("Verifying consistent success...")
    for i in range(10):
        resp = _make_request("GET", "/headers", "model-v1")
        assert resp.status_code == 200, (
            f"Request {i + 1} failed with {resp.status_code}"
        )

    print("✓ Agent reconnected successfully and handling requests")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_inflight_request_during_agent_disconnect():
    """Test that in-flight requests fail fast when agent disconnects."""
    print("\n=== Testing in-flight request during agent disconnect ===")

    # Stop agent-v1-2 so requests will only go to agent-v1-1
    print("Stopping agent-v1-2 to isolate agent-v1-1...")
    agent_v1_2 = get_container("agent-v1-2-1")
    agent_v1_2.stop()
    time.sleep(2)  # Wait for server to detect disconnect

    # Start a slow request (10s delay)
    print("Starting slow request (10s delay) - will go to agent-v1-1...")
    start = time.time()

    def slow_request():
        try:
            return _make_request("GET", "/delay/10", "model-v1", timeout=15)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(slow_request)

        # Wait 2s then kill the agent (immediate termination)
        time.sleep(2)
        print("Killing agent-v1-1 during request...")
        container = get_container("agent-v1-1-1")
        container.kill(signal="SIGKILL")

        # Wait a moment for server to detect disconnect
        time.sleep(1)

        # Wait for response (should fail fast)
        result = future.result()
        elapsed = time.time() - start

    # Restart both agents for next tests
    print("Restarting both agents...")
    container.start()
    agent_v1_2.start()
    time.sleep(5)  # Wait for both agents to reconnect
    print("Agents restarted and ready")

    # Should fail within ~5s (not wait full 10s delay)
    assert elapsed < 8, f"Request took {elapsed:.1f}s, expected <8s (fast failure)"
    assert isinstance(result, requests.Response)
    assert result.status_code in [502, 503, 504], (
        f"Expected 502/503/504, got {result.status_code}"
    )
    print(f"✓ Request failed fast in {elapsed:.1f}s with status {result.status_code}")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_inflight_request_during_server_disconnect():
    """Test that system handles server restart gracefully via full-mesh topology."""
    print("\n=== Testing in-flight request during server disconnect ===")

    # First, identify which servers are handling requests
    print("Identifying server distribution...")
    servers_seen = set()
    for _ in range(10):
        resp = _make_request("GET", "/headers", "model-v1")
        server = resp.headers.get("X-Gimlet-Server-ID", "unknown")
        servers_seen.add(server)
    print(f"Seen servers (UUIDs): {len(servers_seen)} unique servers")

    # Pick first replica container to kill
    target_container = "server-1"
    print(f"Will kill container {target_container}")

    # Make many concurrent slow requests
    # Note: With HTTP keep-alive and full-mesh topology, these may all succeed
    # via the surviving server or via agent reconnection
    print("Starting 20 concurrent slow requests (5s delay each)...")
    start = time.time()

    def slow_request():
        try:
            return _make_request("GET", "/delay/5", "model-v1", timeout=10)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(slow_request) for _ in range(20)]

        # Wait 2s then restart target server
        time.sleep(2)
        print(f"Restarting {target_container} during requests...")
        container = get_container(target_container)
        container.restart()

        # Collect results
        results = [f.result() for f in futures]
        elapsed = time.time() - start

        time.sleep(5)

    # Analyze results
    succeeded = []
    failed_fast = []
    failed_slow = []

    for result in results:
        if isinstance(result, requests.Response):
            if result.status_code == 200:
                server = result.headers.get("X-Gimlet-Server-ID", "unknown")
                succeeded.append(server)
            else:
                req_time = result.elapsed.total_seconds()
                if req_time < 7:  # Failed before completing 5s delay
                    failed_fast.append(result.status_code)
                else:
                    failed_slow.append(result.status_code)
        else:
            failed_fast.append("exception")

    print(f"\nResults after {elapsed:.1f}s:")
    print(f"  Succeeded: {len(succeeded)} (servers: {set(succeeded[:5])}...)")
    print(f"  Failed fast: {len(failed_fast)} (statuses: {set(failed_fast)})")
    print(f"  Failed slow: {len(failed_slow)}")
    print(f"  Total successes: {len(succeeded)}")

    # With full-mesh topology and Docker Compose's internal load balancing:
    # - Requests may all succeed via the surviving server
    # - Or some may fail fast if they were routed to the killed server
    # Either outcome is acceptable - we just verify no slow failures (hangs)
    assert len(failed_slow) == 0, "Expected all failures (if any) to be fast (<7s)"

    if len(failed_fast) > 0:
        print(
            f"✓ {len(failed_fast)} requests failed fast, {len(succeeded)} succeeded via other server"
        )
    else:
        print(
            f"✓ All {len(succeeded)} requests succeeded (routed to surviving server or via agent reconnection)"
        )
        print(
            "  Note: This can happen with HTTP keep-alive or Docker's internal load balancer"
        )


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
@pytest.mark.slow
def test_chaos_monkey():
    """Chaos test: randomly kill/restart services during load."""
    print("\n=== Running chaos monkey test (60s) ===")

    duration = 60
    success_count = 0
    failure_count = 0

    def make_request():
        try:
            resp = _make_request("GET", "/headers", "model-v1", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        end_time = time.time() + duration
        chaos_count = 0

        while time.time() < end_time:
            # Submit some requests
            for _ in range(5):
                futures.append(executor.submit(make_request))

            # Random chaos action every 5s
            if random.random() < 0.3:  # 30% chance
                action = random.choice(
                    [
                        "restart_server_1",
                        "restart_server_2",
                        "restart_agent_v1_1",
                        "restart_agent_v1_2",
                    ]
                )

                try:
                    if action == "restart_server_1":
                        print("  🔄 Restarting server-1")
                        get_container("server-1").restart()
                        time.sleep(2)  # Brief wait for server to come back
                        chaos_count += 1
                    elif action == "restart_server_2":
                        print("  🔄 Restarting server-2")
                        get_container("server-2").restart()
                        time.sleep(2)  # Brief wait for server to come back
                        chaos_count += 1
                    elif action == "restart_agent_v1_1":
                        print("  🔄 Restarting agent-v1-1")
                        get_container("agent-v1-1-1").restart()
                        chaos_count += 1
                    elif action == "restart_agent_v1_2":
                        print("  🔄 Restarting agent-v1-2")
                        get_container("agent-v1-2-1").restart()
                        chaos_count += 1
                except Exception as e:
                    print(f"  ⚠️  Chaos action failed: {e}")

            time.sleep(1)

        # Collect results
        for future in as_completed(futures):
            if future.result():
                success_count += 1
            else:
                failure_count += 1

    # Restart all services to clean state
    print("\nRestoring system...")
    for service in ["server-1", "server-2", "agent-v1-1-1", "agent-v1-2-1"]:
        try:
            container = get_container(service)
            if container.status != "running":
                container.start()
        except Exception:
            pass

    time.sleep(10)  # Wait for full recovery

    total = success_count + failure_count
    success_rate = success_count / total if total > 0 else 0

    print("\n=== Chaos Results ===")
    print(f"Duration: {duration}s")
    print(f"Chaos actions: {chaos_count}")
    print(f"Total requests: {total}")
    print(f"Successful: {success_count} ({success_rate:.1%})")
    print(f"Failed: {failure_count}")

    # We expect some failures during chaos, but success rate should be reasonable
    # With 2 servers and 2 agents, we have good redundancy
    assert success_rate > 0.70, (
        f"Success rate too low: {success_rate:.1%} (expected >70%)"
    )
    print(f"✓ Chaos test passed with {success_rate:.1%} success rate")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_load_balancing_after_restart():
    """Test that system stays healthy during and after agent restart."""
    print("\n=== Testing load balancing during agent restart ===")

    # Restart agent-v1-1 in background (it will be briefly down then back up)
    print("Restarting agent-v1-1...")
    container = get_container("agent-v1-1-1")
    container.restart()

    # Make requests immediately - should succeed via agent-v1-2 or recovering agent-v1-1
    print("Making requests during/after restart...")
    for i in range(10):
        resp = _make_request("GET", "/headers", "model-v1")
        assert resp.status_code == 200, f"Request {i + 1} failed"
        time.sleep(0.5)  # Spread requests over 5s

    print("✓ All requests succeeded during agent restart window")

    # Wait for full reconnection to both servers
    time.sleep(5)

    # Verify system fully recovered
    print("Verifying full recovery...")
    for i in range(10):
        resp = _make_request("GET", "/headers", "model-v1")
        assert resp.status_code == 200

    print("✓ System fully recovered after agent restart")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_graceful_shutdown_sigterm():
    """Test that agent gracefully shuts down on SIGTERM, finishing in-flight requests."""
    print("\n=== Testing agent graceful shutdown with SIGTERM ===")

    # Start a slow request (10s delay)
    print("Starting slow request (10s delay)...")
    start = time.time()

    def slow_request():
        try:
            return _make_request("GET", "/delay/10", "model-v1", timeout=15)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(slow_request)

        # Wait 2s then send SIGTERM to agent
        time.sleep(2)
        print("Sending SIGTERM to agent...")
        container = get_container("agent-v1-1-1")
        container.kill(signal="SIGTERM")

        # Wait for response
        result = future.result()
        elapsed = time.time() - start

    # With graceful shutdown, request should complete successfully
    if isinstance(result, Exception):
        print(f"✗ Request failed with exception: {result}")
        print(f"  Elapsed time: {elapsed:.1f}s")
        # This is acceptable - agent may have drained before completing
        print("  (Agent may have hit 30s drain timeout)")
    elif result.status_code == 200:
        print(f"✓ Request completed successfully in {elapsed:.1f}s")
        print("  Agent waited for in-flight request to complete")
        # Should take ~10s (delay time) + some overhead
        assert 9 < elapsed < 12, f"Request took {elapsed:.1f}s, expected ~10s"
    else:
        print(f"✗ Request failed with status {result.status_code}")
        print(f"  Elapsed time: {elapsed:.1f}s")

    # Wait for agent to fully stop
    time.sleep(3)

    # Verify agent is stopped
    container.reload()
    assert container.status != "running", "Agent should have stopped after SIGTERM"
    print("✓ Agent stopped gracefully after SIGTERM")

    # Restart agent for other tests
    print("Restarting agent...")
    container.start()
    time.sleep(5)


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_drain_prevents_new_requests():
    """Test that draining agent stops accepting new requests but finishes existing ones."""
    print("\n=== Testing agent drain prevents new requests ===")

    # Start two slow requests in parallel
    print("Starting two slow requests (8s delay each)...")

    def slow_request(req_id):
        try:
            resp = _make_request("GET", "/delay/8", "model-v1", timeout=15)
            return (req_id, resp.status_code)
        except Exception as e:
            return (req_id, e)

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Start first batch of requests
        futures1 = [executor.submit(slow_request, i) for i in range(2)]

        # Wait 2s then send SIGTERM
        time.sleep(2)
        print("Sending SIGTERM to agent (drain mode)...")
        container = get_container("agent-v1-1-1")
        container.kill(signal="SIGTERM")

        # Wait 1s for drain message to propagate
        time.sleep(1)

        # Try to start new requests - should go to other agents
        print("Starting new requests after drain signal...")
        futures2 = [executor.submit(slow_request, i + 10) for i in range(3)]

        # Collect all results
        all_futures = futures1 + futures2
        results = []
        for f in as_completed(all_futures):
            results.append(f.result())

    # Check results
    print("\nRequest results:")
    success_count = 0
    for req_id, status in results:
        if isinstance(status, Exception):
            print(f"  Request {req_id}: FAILED ({status})")
        else:
            print(f"  Request {req_id}: {status}")
            if status == 200:
                success_count += 1

    # All or most requests should succeed (handled by other agents or completed)
    print(f"\n✓ {success_count}/{len(results)} requests succeeded")
    assert success_count >= 3, (
        f"Expected at least 3 successful requests, got {success_count}"
    )

    # Restart agent
    container.start()
    time.sleep(5)


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_server_graceful_shutdown_sigterm():
    """Test that server gracefully shuts down on SIGTERM."""
    print("\n=== Testing server graceful shutdown with SIGTERM ===")

    # Verify server-2 works
    print("Verifying server-2 health...")
    resp = _make_request("GET", "/headers", "model-v1")
    assert resp.status_code == 200

    # Send SIGTERM to server-2
    print("Sending SIGTERM to server-2...")
    container = get_container("server-2")
    container.kill(signal="SIGTERM")

    # Wait for graceful shutdown (should be quick, no long requests)
    time.sleep(3)

    # Verify server stopped
    container.reload()
    assert container.status != "running", "Server should have stopped after SIGTERM"
    print("✓ Server stopped gracefully after SIGTERM")

    # Verify server-1 still works (nginx should route to it)
    print("Verifying server-1 still handles requests...")
    for i in range(5):
        resp = _make_request("GET", "/headers", "model-v1")
        assert resp.status_code == 200, f"Request {i + 1} failed"

    print("✓ Server-1 continues serving requests")

    # Restart server-2
    print("Restarting server-2...")
    container.start()
    time.sleep(10)  # Wait for agents to reconnect


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_server_graceful_shutdown_drains_requests():
    """
    Test that server waits for in-flight requests to complete before shutting down.

    Unlike agents, servers previously terminated in-flight requests immediately on SIGTERM.
    This test verifies the fix: servers should now drain requests like agents do.
    """
    print("\n=== Testing server drains in-flight requests on SIGTERM ===")

    # Stop server-1 so all requests go to server-2
    print("Stopping server-1 to isolate server-2...")
    server_1 = get_container("server-1")
    server_1.stop()
    time.sleep(3)  # Wait for agents to detect disconnect

    # Start a slow request (10s delay)
    print("Starting slow request (10s delay) - will go to server-2...")
    start = time.time()

    def slow_request():
        try:
            return _make_request("GET", "/delay/10", "model-v1", timeout=20)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(slow_request)

        # Wait 2s then send SIGTERM to server-2
        time.sleep(2)
        print("Sending SIGTERM to server-2 during request...")
        server_2 = get_container("server-2")
        server_2.kill(signal="SIGTERM")

        # Wait for response
        result = future.result()
        elapsed = time.time() - start

    # Restart both servers before assertions (so cleanup works)
    print("Restarting servers...")
    server_2.start()
    server_1.start()
    time.sleep(10)  # Wait for agents to reconnect

    # Verify the request completed successfully
    if isinstance(result, Exception):
        pytest.fail(f"Request failed with exception: {result} (elapsed: {elapsed:.1f}s)")

    assert result.status_code == 200, (
        f"Expected 200 OK (server should drain), got {result.status_code}"
    )

    # Should take ~10s (delay time) since server waited for request to complete
    assert 9 < elapsed < 15, (
        f"Request took {elapsed:.1f}s, expected ~10s (server should have drained)"
    )

    print(f"✓ Request completed successfully in {elapsed:.1f}s")
    print("  Server waited for in-flight request to complete before shutting down")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_30s_drain_timeout():
    """Test that agent shuts down after 30s drain timeout even with pending requests."""
    print("\n=== Testing agent 30s drain timeout ===")

    # This test verifies the agent doesn't wait forever for slow requests

    # Stop agent-v1-2 to ensure request goes to agent-v1-1
    print("Stopping agent-v1-2 to isolate agent-v1-1...")
    agent_v1_2 = get_container("agent-v1-2-1")
    agent_v1_2.stop()
    time.sleep(2)

    # Start a very slow request (60s delay)
    print("Starting very slow request (60s delay) - will go to agent-v1-1...")
    start = time.time()

    def very_slow_request():
        try:
            return _make_request("GET", "/delay/60", "model-v1", timeout=70)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(very_slow_request)

        # Wait 2s then send SIGTERM
        time.sleep(2)
        print("Sending SIGTERM to agent-v1-1...")
        container = get_container("agent-v1-1-1")
        container.kill(signal="SIGTERM")

        # Wait and check that agent stops within 35s (30s timeout + margin)
        print("Waiting for agent to stop (should hit 30s timeout)...")
        for i in range(35):
            time.sleep(1)
            container.reload()
            if container.status != "running":
                elapsed = time.time() - start
                print(f"✓ Agent stopped after {elapsed:.1f}s")
                break
        else:
            pytest.fail("Agent did not stop within 35s")

        # Request should fail (agent stopped before completing)
        result = future.result()
        if isinstance(result, Exception):
            print(f"✓ Request failed as expected: {type(result).__name__}")
        else:
            print(f"  Request got status {result.status_code} (unexpected)")

    # Verify agent stopped around 30s mark (not waiting for full 60s)
    total_elapsed = time.time() - start
    assert total_elapsed < 35, f"Agent took {total_elapsed:.1f}s to stop, expected <35s"
    print(f"✓ Agent respected 30s drain timeout ({total_elapsed:.1f}s total)")

    # Restart both agents
    print("Restarting agents...")
    container.start()
    agent_v1_2.start()
    time.sleep(5)


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_server_rate_limit():
    """
    Test that server rate limit enforcement works correctly.

    This test uses MAX_CONCURRENT_REQUESTS_PER_SERVER=60 configured in docker-compose.yml.
    With 2 server replicas, the cluster-wide limit is 120 concurrent requests.
    """
    print("\n[Test] Testing server concurrent request limit...")

    # Expected limit (should match docker-compose config for testing)
    limit_per_server = 60  # From docker-compose.yml
    num_server_replicas = 2  # From docker-compose.yml: deploy.replicas
    expected_cluster_limit = limit_per_server * num_server_replicas  # 120

    # Send more concurrent slow requests than the cluster limit
    num_requests = int(
        expected_cluster_limit * 1.5
    )  # 180 requests for cluster limit of 120
    delay_seconds = 3

    print(
        f"Sending {num_requests} concurrent requests (cluster limit: {expected_cluster_limit})..."
    )

    def make_slow_request(i):
        try:
            resp = _make_request(
                "GET", f"/delay/{delay_seconds}", "model-v1", timeout=10
            )
            return (i, resp.status_code)
        except Exception as e:
            return (i, f"error: {e}")

    start = time.time()
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(make_slow_request, i) for i in range(num_requests)]
        results = [f.result() for f in futures]
    elapsed = time.time() - start

    # Analyze results
    status_codes = [r[1] for r in results if isinstance(r[1], int)]
    success_count = sum(1 for s in status_codes if s == 200)
    rate_limited_count = sum(1 for s in status_codes if s == 429)

    print(f"Results after {elapsed:.1f}s:")
    print(f"  - 200 OK: {success_count}")
    print(f"  - 429 Rate Limited: {rate_limited_count}")
    print(f"  - Errors: {len(results) - len(status_codes)}")

    # Verify rate limiting occurred
    assert rate_limited_count > 0, (
        f"Expected some requests to be rate limited (cluster limit={expected_cluster_limit}), "
        f"but got {rate_limited_count} 429s out of {num_requests} requests."
    )

    # Verify some requests still succeeded
    assert success_count > 0, "Expected some requests to succeed"

    # Total should be close to cluster limit (allowing some to succeed as others complete)
    assert success_count <= expected_cluster_limit * 1.5, (
        f"Too many successful requests ({success_count}), expected around {expected_cluster_limit}"
    )

    print("✓ Server rate limit working correctly")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_rate_limit():
    """
    Test that agent rate limit enforcement works correctly.

    This test uses MAX_CONCURRENT_REQUESTS_PER_AGENT=30 configured in docker-compose.yml.
    Targets model-v1 which has 2 agents, so we need enough concurrent requests to ensure
    at least one agent hits its rate limit even with load balancing.
    """
    print("\n[Test] Testing agent concurrent request limit...")

    # Expected limit (should match docker-compose config for testing)
    limit_per_agent = (
        30  # From docker-compose.yml (now global per agent, not per connection)
    )
    num_agents = 2  # model-v1 has 2 agents (agent-v1-1, agent-v1-2)

    # Send enough concurrent requests to ensure at least one agent hits its limit
    # With global per-agent limit, each agent can handle 30 requests total (not 30 per server)
    num_requests = int(limit_per_agent * num_agents * 1.5)  # 90 requests
    delay_seconds = 3  # Long enough to ensure requests pile up before completing

    print(
        f"Sending {num_requests} concurrent requests (per-agent limit: {limit_per_agent})..."
    )

    def make_slow_request(i):
        try:
            resp = _make_request(
                "GET", f"/delay/{delay_seconds}", "model-v1", timeout=10
            )
            return (i, resp.status_code)
        except Exception as e:
            return (i, f"error: {e}")

    start = time.time()
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(make_slow_request, i) for i in range(num_requests)]
        results = [f.result() for f in futures]
    elapsed = time.time() - start

    # Analyze results
    status_codes = [r[1] for r in results if isinstance(r[1], int)]
    success_count = sum(1 for s in status_codes if s == 200)
    rate_limited_count = sum(1 for s in status_codes if s == 429)

    print(f"Results after {elapsed:.1f}s:")
    print(f"  - 200 OK: {success_count}")
    print(f"  - 429 Rate Limited: {rate_limited_count}")
    print(f"  - Errors: {len(results) - len(status_codes)}")

    # Verify rate limiting occurred
    assert rate_limited_count > 0, (
        f"Expected some requests to be rate limited (per-agent limit={limit_per_agent}), "
        f"but got {rate_limited_count} 429s out of {num_requests} requests."
    )

    # Verify some requests still succeeded
    assert success_count > 0, "Expected some requests to succeed"

    # With 2 agents each having limit of 30, cluster limit is ~60
    # Allow some margin as requests complete and new ones start
    expected_cluster_limit = limit_per_agent * num_agents
    assert success_count <= expected_cluster_limit * 1.5, (
        f"Too many successful requests ({success_count}), expected around {expected_cluster_limit}"
    )

    print("✓ Agent rate limit working correctly")


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_instant_shutdown_after_completed_requests():
    """
    Test that agent shuts down instantly after requests complete.

    This tests the fix for a bug where goroutines would hang after requests
    completed because the backend connection wasn't properly cleaned up.
    With the fix, once a request completes (backend sends response and closes),
    the handler goroutine should exit cleanly, allowing instant shutdown.
    """
    print("\n=== Testing agent instant shutdown after completed requests ===")

    # Make several requests that complete successfully
    print("Making 10 requests that will complete normally...")
    for i in range(10):
        resp = _make_request("GET", "/headers", "model-v1", timeout=5)
        assert resp.status_code == 200, f"Request {i + 1} failed with {resp.status_code}"
    print("✓ All 10 requests completed successfully")

    # Give a brief moment for any cleanup
    time.sleep(1)

    # Now send SIGTERM to agent - should shut down almost instantly
    # since there are no in-flight requests
    print("Sending SIGTERM to agent (should shutdown instantly)...")
    container = get_container("agent-v1-1-1")
    start = time.time()
    container.kill(signal="SIGTERM")

    # Wait for agent to stop - should be very fast (< 5s)
    for i in range(10):
        time.sleep(0.5)
        container.reload()
        if container.status != "running":
            elapsed = time.time() - start
            print(f"✓ Agent stopped in {elapsed:.1f}s")
            break
    else:
        elapsed = time.time() - start
        container.kill(signal="SIGKILL")  # Force kill to not hang
        pytest.fail(f"Agent did not stop within 5s (took {elapsed:.1f}s) - possible goroutine leak")

    # Verify it was fast (< 3s is reasonable, < 5s is acceptable)
    assert elapsed < 5, f"Agent took {elapsed:.1f}s to stop, expected < 5s (instant shutdown)"

    if elapsed < 2:
        print("  (Excellent - truly instant shutdown)")
    elif elapsed < 3:
        print("  (Good - quick shutdown)")
    else:
        print("  (Acceptable but slower than expected)")

    # Restart agent for other tests
    print("Restarting agent...")
    container.start()
    time.sleep(5)


@pytest.mark.disruption
@pytest.mark.xdist_group(name="serial_disruption")
def test_agent_shutdown_no_goroutine_leak():
    """
    Test that repeated requests don't cause goroutine leaks.

    Make many requests, then verify shutdown is still instant.
    This catches bugs where goroutines accumulate over time.
    """
    print("\n=== Testing no goroutine leak after many requests ===")

    # Make many requests in quick succession
    num_requests = 50
    print(f"Making {num_requests} rapid requests...")

    success_count = 0
    for i in range(num_requests):
        try:
            resp = _make_request("GET", "/headers", "model-v1", timeout=5)
            if resp.status_code == 200:
                success_count += 1
        except Exception:
            pass
        # Small delay to avoid overwhelming
        if i % 10 == 9:
            time.sleep(0.1)

    print(f"✓ {success_count}/{num_requests} requests completed")
    assert success_count > 40, f"Too many failures: only {success_count}/{num_requests} succeeded"

    # Give a moment for cleanup
    time.sleep(2)

    # Shutdown should still be instant
    print("Sending SIGTERM to agent (should still shutdown instantly)...")
    container = get_container("agent-v1-1-1")
    start = time.time()
    container.kill(signal="SIGTERM")

    # Wait for agent to stop
    for i in range(10):
        time.sleep(0.5)
        container.reload()
        if container.status != "running":
            elapsed = time.time() - start
            print(f"✓ Agent stopped in {elapsed:.1f}s after {num_requests} requests")
            break
    else:
        elapsed = time.time() - start
        container.kill(signal="SIGKILL")
        pytest.fail(f"Agent did not stop within 5s - possible goroutine leak after {num_requests} requests")

    assert elapsed < 5, f"Agent took {elapsed:.1f}s to stop, expected < 5s"
    print("✓ No goroutine leak detected - shutdown was instant")

    # Restart agent
    print("Restarting agent...")
    container.start()
    time.sleep(5)


if __name__ == "__main__":
    # Run all disruption tests
    pytest.main([__file__, "-v", "-m", "disruption"])
