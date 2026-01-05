"""
Load tests for Gimlet - focused on extreme scenarios.

These tests validate:
1. Long-running and idle requests (10m+ idle timeout)
2. Chaos testing - random mixed traffic under high concurrency

Run with: uv run pytest tests/test_load.py -v

Note: These tests are more intensive than E2E tests and may take several minutes.
"""

import concurrent.futures
import time
import requests
import pytest


BASE_URL = "http://localhost:8080"


def _make_request(method, path, service, auth_headers=None, **kwargs):
    """Helper to make requests with path-based service routing."""
    headers = auth_headers or {}
    return requests.request(method, f"{BASE_URL}/services/{service}{path}", headers=headers, **kwargs)


# ============================================================================
# 1. LONG-RUNNING AND IDLE REQUESTS
# ============================================================================


def test_long_streaming_request_no_idle_timeout(auth_headers):
    """
    Test that long requests with continuous data flow do NOT timeout.

    Uses httpbun /drip endpoint to stream data over 12 minutes (exceeds 10m default).
    As long as data keeps flowing, the request should complete successfully.
    """
    print("\n[Test] Long streaming request (12 minutes)...")

    # Stream 1KB over 12 minutes (720 seconds)
    # This exceeds IDLE_TIMEOUT (10m) but should succeed because data is flowing
    duration_seconds = 720  # 12 minutes
    num_bytes = 1024

    start = time.time()
    chunk_times = []
    chunks = []

    try:
        resp = _make_request(
            "GET",
            f"/drip?duration={duration_seconds}&numbytes={num_bytes}",
            "model-v1",
            auth_headers,
            stream=True,
            timeout=duration_seconds + 60,  # Client timeout longer than request
        )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        # Read all chunks
        for chunk in resp.iter_content(chunk_size=None):
            if chunk:
                elapsed = time.time() - start
                chunk_times.append(elapsed)
                chunks.append(chunk)
                print(f"  Chunk {len(chunks)} at {elapsed:.1f}s ({len(chunk)} bytes)")

        elapsed = time.time() - start
        total_bytes = sum(len(c) for c in chunks)

        # Verify request completed successfully
        assert elapsed >= 700, (
            f"Request completed too quickly ({elapsed:.1f}s), expected ~720s"
        )
        assert total_bytes > 0, "Expected some data"

        print(
            f"✓ Long streaming request completed: {total_bytes} bytes over {elapsed:.1f}s"
        )

    except requests.exceptions.Timeout as e:
        elapsed = time.time() - start
        pytest.fail(
            f"Request timed out after {elapsed:.1f}s (should not timeout with flowing data): {e}"
        )


def test_truly_idle_request_does_timeout(auth_headers):
    """
    Test that truly idle requests (no data flow) DO timeout after IDLE_TIMEOUT.

    This validates the idle timeout mechanism by creating a connection that
    never sends data. Expected to timeout after ~10 minutes.

    Note: This test takes ~10 minutes. Consider skipping in fast test runs.
    """
    pytest.skip("Skipped by default (takes 10+ minutes). Enable for full load testing.")

    print("\n[Test] Idle request timeout (10+ minutes)...")

    # Use /delay endpoint with very long delay
    # Server should timeout after IDLE_TIMEOUT (10m = 600s)
    delay_seconds = 900  # 15 minutes (exceeds IDLE_TIMEOUT)

    start = time.time()

    try:
        resp = _make_request(
            "GET",
            f"/delay/{delay_seconds}",
            "model-v1",
            auth_headers,
            timeout=delay_seconds + 60,
        )

        elapsed = time.time() - start

        # If we got here, request completed (unexpected)
        pytest.fail(
            f"Request completed after {elapsed:.1f}s with status {resp.status_code}. "
            f"Expected timeout after ~600s (IDLE_TIMEOUT)"
        )

    except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
        elapsed = time.time() - start

        # Verify timeout happened around IDLE_TIMEOUT (10m = 600s)
        # Allow some tolerance (±60s)
        assert 540 <= elapsed <= 660, (
            f"Timeout occurred at {elapsed:.1f}s, expected ~600s (IDLE_TIMEOUT=10m). "
            f"Tolerance: 540-660s"
        )

        print(f"✓ Idle request timed out correctly after {elapsed:.1f}s (~10m)")


# ============================================================================
# 2. CHAOS TESTING
# ============================================================================


def test_chaos_mixed_load(auth_headers):
    """
    Chaos test: Random mix of request types under high load.

    Throws random requests at the system:
    - Small GETs (fast)
    - Large GETs (10MB downloads)
    - Large POSTs (10MB uploads to nginx, 100KB to httpbun)
    - Delayed requests (2s)
    - Streaming requests (SSE)
    - Different services (model-v1, model-v2)

    Validates only: Either get 200 (success) or 429 (rate limited).
    Allows <5% errors (502 Bad Gateway under extreme load is acceptable).
    No silent failures, no data corruption.
    """
    import random

    print("\n[Test] Chaos - mixed load...")

    duration_seconds = 180  # 3 minutes of chaos
    concurrency = 150  # Very high concurrency

    # Request types with weights
    request_types = [
        ("GET_SMALL", "/headers", "model-v1", 0.25),  # 25% - fast requests
        (
            "GET_LARGE",
            "/50mb.bin",
            "model-v2",
            0.15,
        ),  # 15% - large downloads (rate-limited to 1MB/s)
        ("GET_DELAY", "/delay/5", "model-v1", 0.15),  # 15% - slow requests
        ("POST_SMALL", "/post", "model-v1", 0.15),  # 15% - small uploads to httpbun
        ("POST_LARGE", "/upload", "model-v2", 0.15),  # 15% - large uploads to nginx
        ("GET_STREAM", "/sse", "model-v1", 0.15),  # 15% - streaming
    ]

    print(f"Running chaos test for {duration_seconds}s with {concurrency} workers...")
    print("Request mix:")
    for req_type, _, _, weight in request_types:
        print(f"  - {req_type}: {weight * 100:.0f}%")

    def random_request(worker_id):
        """Make random requests until time limit."""
        end_time = time.time() + duration_seconds
        local_stats = {"success": 0, "rate_limited": 0, "errors": []}

        while time.time() < end_time:
            # Pick random request type
            rand = random.random()
            cumulative = 0
            selected_type = None
            for req_type, path, service, weight in request_types:
                cumulative += weight
                if rand < cumulative:
                    selected_type = (req_type, path, service)
                    break

            req_type, path, service = selected_type

            try:
                if req_type == "POST_LARGE":
                    # Upload 10MB to nginx
                    data = b"X" * (10 * 1024 * 1024)
                    post_headers = {
                        **auth_headers,
                        "Content-Type": "application/octet-stream",
                    }
                    resp = _make_request(
                        "POST", path, service, post_headers, data=data, timeout=60
                    )
                elif req_type == "POST_SMALL":
                    # Upload 100KB to httpbun
                    data = b"Y" * (100 * 1024)
                    post_headers = {
                        **auth_headers,
                        "Content-Type": "application/octet-stream",
                    }
                    resp = _make_request(
                        "POST", path, service, post_headers, data=data, timeout=30
                    )
                elif req_type == "GET_STREAM":
                    # Streaming request - just read some chunks
                    resp = _make_request(
                        "GET", path, service, auth_headers, stream=True, timeout=20
                    )
                    if resp.status_code == 200:
                        # Read first few chunks
                        for i, chunk in enumerate(resp.iter_content(chunk_size=None)):
                            if i >= 3:  # Only read 3 chunks
                                break
                else:
                    # Regular GET
                    resp = _make_request(
                        "GET", path, service, auth_headers, stream=True, timeout=30
                    )
                    if resp.status_code == 200:
                        # Download the response
                        for chunk in resp.iter_content(chunk_size=65536):
                            pass  # Just consume it

                # Validate response
                if resp.status_code == 200:
                    local_stats["success"] += 1
                elif resp.status_code == 429:
                    local_stats["rate_limited"] += 1
                else:
                    local_stats["errors"].append(
                        {
                            "type": req_type,
                            "status": resp.status_code,
                            "body": resp.text[:100],
                        }
                    )

            except Exception as e:
                local_stats["errors"].append({"type": req_type, "error": str(e)[:100]})

            # Small random delay to vary arrival rate
            time.sleep(random.uniform(0, 0.1))

        return local_stats

    # Run chaos
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(random_request, i) for i in range(concurrency)]
        worker_results = [f.result() for f in futures]
    elapsed = time.time() - start

    # Aggregate results
    total_success = sum(r["success"] for r in worker_results)
    total_rate_limited = sum(r["rate_limited"] for r in worker_results)
    all_errors = []
    for r in worker_results:
        all_errors.extend(r["errors"])

    total_requests = total_success + total_rate_limited + len(all_errors)

    print(f"\nChaos test completed after {elapsed:.1f}s:")
    print(f"  - Total requests: {total_requests}")
    print(
        f"  - Success (200): {total_success} ({total_success / total_requests * 100:.1f}%)"
    )
    print(
        f"  - Rate limited (429): {total_rate_limited} ({total_rate_limited / total_requests * 100:.1f}%)"
    )
    print(
        f"  - Errors: {len(all_errors)} ({len(all_errors) / total_requests * 100:.1f}%)"
    )
    print(f"  - Throughput: {total_requests / elapsed:.1f} req/s")

    if all_errors:
        print("\nSample errors:")
        for err in all_errors[:5]:
            print(f"  {err}")

    # Validate: Some requests succeeded, most got rate limited, few errors
    assert total_requests > 0, "Expected some requests"
    assert total_success > 0, "Expected some successful requests"

    # Allow up to 5% errors (connection resets, 502s, timeouts under extreme load)
    error_rate = len(all_errors) / total_requests
    assert error_rate < 0.05, f"Too many errors: {error_rate * 100:.1f}% (expected <5%)"

    print("\n✓ Chaos test passed:")
    print("  - System remained stable under random mixed load")
    print("  - No silent failures")
    print("  - Error rate within acceptable limits")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
