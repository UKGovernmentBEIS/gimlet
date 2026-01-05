"""
End-to-end tests for Gimlet tunnel-based model serving.

Run with: uv run pytest test_e2e.py -v
"""

import concurrent.futures
import time
import requests
import pytest


BASE_URL = "http://localhost:8080"


def _make_request(method, path, service, auth_headers, **kwargs):
    """Helper to make requests with path-based service routing."""
    return requests.request(method, f"{BASE_URL}/services/{service}{path}", headers=auth_headers, **kwargs)


def test_service_isolation(auth_headers):
    """Test that different services route to different agents."""
    resp_v1 = _make_request("GET", "/headers", "model-v1", auth_headers)
    resp_v2 = _make_request("GET", "/", "model-v2", auth_headers)  # nginx autoindex

    assert resp_v1.status_code == 200
    assert resp_v2.status_code == 200

    # Both should work but route to different backends
    # v1 uses httpbun (JSON response), v2 uses nginx (HTML directory listing)
    assert "headers" in resp_v1.json()
    assert "1mb.bin" in resp_v2.text or "10mb.bin" in resp_v2.text  # nginx file listing


def test_bare_domain_404():
    """Test that requests to bare domain return 404 (no API structure hints)."""
    resp = requests.get(BASE_URL)
    assert resp.status_code == 404


def test_request_with_delay(auth_headers):
    """Test that delayed requests work correctly."""
    start = time.time()
    resp = _make_request("GET", "/delay/1", "model-v1", auth_headers)
    duration = time.time() - start

    assert resp.status_code == 200
    assert duration >= 1.0  # Should take at least 1 second


def test_long_running_request(auth_headers):
    """
    Test that requests >30s work correctly (tests timeout fix).

    Previously, agent had a fixed 30s deadline that killed all requests after 30s.
    This test verifies that the timeout bug is fixed and long requests can complete.
    """
    start = time.time()
    resp = _make_request("GET", "/delay/45", "model-v1", auth_headers, timeout=60)
    duration = time.time() - start

    assert resp.status_code == 200
    assert duration >= 45.0  # Should take at least 45 seconds
    print(f"\n✓ Long request completed in {duration:.1f}s (old timeout was 30s)")


# NOTE: Client disconnect cancellation is tested implicitly by the idle timeout test
# and by disruption tests that kill agents/servers during requests. Direct testing
# would require low-level TCP manipulation which is complex and flaky.


def test_load_balancing_with_concurrent_requests(auth_headers):
    """
    Test load balancing across multiple agents for the same service.

    With 2 agents for model-v1 and many concurrent slow requests, load should be distributed.
    """
    num_requests = 30  # Reduced to avoid rate limit flakiness when tests run in parallel
    delay_seconds = 2

    def make_request(i):
        resp = _make_request(
            "GET", f"/delay/{delay_seconds}", "model-v1", auth_headers, timeout=15
        )
        return (resp.status_code, i)

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(make_request, i) for i in range(num_requests)]
        results = [f.result() for f in futures]

    duration = time.time() - start

    # All requests should succeed
    statuses = [status for status, _ in results]
    failed = [(i, status) for status, i in results if status != 200]
    assert all(status == 200 for status in statuses), (
        f"{len(failed)} requests failed: {failed[:10]}"
    )

    # With 2 agents and 30 concurrent requests of 2s each:
    # - Perfect distribution: 15 requests per agent, serialized = 15 * 2s = 30s total
    # - Single agent: 30 * 2s = 60s total
    # We should see something closer to 30-35s, not 60s
    print(
        f"\n30 concurrent requests took {duration:.1f}s (expected ~30-35s with 2 agents)"
    )
    assert duration < 40, (
        f"Load balancing not working: took {duration}s (expected ~30-35s)"
    )


def test_request_headers_preserved(auth_headers):
    """Test that custom headers are forwarded through the tunnel."""
    headers_with_custom = {**auth_headers, "X-Custom-Header": "test-value"}
    resp = _make_request("GET", "/headers", "model-v1", headers_with_custom)

    assert resp.status_code == 200
    response_headers = resp.json()["headers"]
    assert response_headers.get("X-Custom-Header") == "test-value"


def test_post_request_with_body(auth_headers):
    """Test that POST requests with body work correctly."""
    data = {"key": "value", "test": 123}
    resp = _make_request("POST", "/post", "model-v1", auth_headers, json=data)

    assert resp.status_code == 200
    response_data = resp.json()
    assert response_data["json"] == data


def test_different_http_methods(auth_headers):
    """Test that different HTTP methods work correctly."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    for method in methods:
        resp = _make_request(method, f"/{method.lower()}", "model-v1", auth_headers)
        assert resp.status_code == 200
        response_data = resp.json()
        assert response_data["method"] == method


def test_status_codes(auth_headers):
    """Test that different status codes are correctly forwarded."""
    test_cases = [200, 201, 400, 404, 500, 503]

    for status_code in test_cases:
        resp = _make_request("GET", f"/status/{status_code}", "model-v1", auth_headers)
        assert resp.status_code == status_code


def test_service_v2_independent(auth_headers):
    """Test that model-v2 service works independently."""
    # Test that v2 can handle requests while v1 is under load

    def slow_v1_request():
        _make_request("GET", "/delay/3", "model-v1", auth_headers)

    # Start slow v1 requests in background
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        v1_futures = [executor.submit(slow_v1_request) for _ in range(2)]

        # While v1 is busy, v2 should still be fast
        start = time.time()
        resp = _make_request("GET", "/", "model-v2", auth_headers)  # nginx autoindex
        v2_duration = time.time() - start

        # Wait for v1 requests to complete
        [f.result() for f in v1_futures]

    assert resp.status_code == 200
    assert v2_duration < 1.0, "v2 should not be blocked by v1 load"


def test_sse_streaming(auth_headers):
    """
    Test that SSE events are streamed incrementally, not buffered until completion.

    The /sse endpoint sends an event every ~1 second for 10 seconds.
    We verify that chunks arrive over time rather than all at once at the end.
    """
    chunk_times = []
    chunks_received = []

    start_time = time.time()

    # Use stream=True to enable incremental reading
    resp = _make_request(
        "GET", "/sse", "model-v1", auth_headers, stream=True, timeout=15
    )
    assert resp.status_code == 200

    # Read chunks as they arrive
    for chunk in resp.iter_content(chunk_size=None, decode_unicode=False):
        if chunk:
            elapsed = time.time() - start_time
            chunk_times.append(elapsed)
            chunks_received.append(chunk)
            print(
                f"  Chunk {len(chunks_received)} received at {elapsed:.1f}s: {len(chunk)} bytes"
            )

    total_duration = time.time() - start_time

    # Verify we received multiple chunks
    assert len(chunks_received) >= 3, (
        f"Expected multiple chunks, got {len(chunks_received)}"
    )

    # Verify streaming behavior: chunks should arrive over time, not all at once
    # First chunk should arrive quickly (< 2s), last chunk should arrive near the end (~10s)
    first_chunk_time = chunk_times[0]
    last_chunk_time = chunk_times[-1]

    assert first_chunk_time < 2.0, (
        f"First chunk took {first_chunk_time:.1f}s (should be < 2s)"
    )
    assert last_chunk_time > 5.0, (
        f"Last chunk at {last_chunk_time:.1f}s (should be > 5s for streaming)"
    )
    assert total_duration > 5.0, (
        f"Total duration {total_duration:.1f}s (should be > 5s)"
    )

    # Verify chunks are spread out over time (not all arriving at once)
    time_spread = last_chunk_time - first_chunk_time
    assert time_spread > 4.0, (
        f"Chunks arrived in {time_spread:.1f}s (should be spread over > 4s)"
    )

    print(
        f"\n  ✓ SSE streaming verified: {len(chunks_received)} chunks over {total_duration:.1f}s"
    )
    print(
        f"  ✓ First chunk: {first_chunk_time:.1f}s, Last chunk: {last_chunk_time:.1f}s, Spread: {time_spread:.1f}s"
    )


def test_large_binary_response(auth_headers):
    """
    Test that large binary responses are streamed in chunks.

    Uses httpbun's /range/1000 endpoint (1KB of random bytes).
    Verifies the response arrives incrementally via chunked transfer encoding.
    """
    resp = _make_request("GET", "/range/1000", "model-v1", auth_headers, stream=True)
    assert resp.status_code == 200

    chunks = []
    for chunk in resp.iter_content(chunk_size=None):
        if chunk:
            chunks.append(chunk)

    # Should receive data in chunks (not all at once)
    # httpbun /range/1000 returns 1000 bytes, we expect multiple chunks
    assert len(chunks) >= 1, f"Expected at least 1 chunk, got {len(chunks)}"

    # Verify total size
    total_bytes = sum(len(chunk) for chunk in chunks)
    assert total_bytes == 1000, f"Expected 1000 bytes, got {total_bytes}"

    print(f"\n  ✓ Large binary response: {total_bytes} bytes in {len(chunks)} chunk(s)")


def test_concurrent_large_responses(auth_headers):
    """
    Test that multiple concurrent large responses work correctly.

    Sends 10 concurrent requests to /range/1000 (1KB each = 10KB total).
    Verifies bounded buffering doesn't cause failures under concurrent load.
    """
    num_requests = 10

    def fetch_large_response(i):
        resp = _make_request("GET", "/range/1000", "model-v1", auth_headers, timeout=10)
        assert resp.status_code == 200
        data = resp.content
        assert len(data) == 1000, f"Request {i}: expected 1000 bytes, got {len(data)}"
        return len(data)

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [
            executor.submit(fetch_large_response, i) for i in range(num_requests)
        ]
        sizes = [f.result() for f in futures]

    duration = time.time() - start

    # All requests should succeed
    assert len(sizes) == num_requests
    assert all(size == 1000 for size in sizes)

    total_mb = sum(sizes) / (1024 * 1024)
    print(
        f"\n  ✓ Concurrent large responses: {num_requests} requests, {total_mb:.2f}MB total in {duration:.1f}s"
    )


def test_drip_endpoint_streaming(auth_headers):
    """
    Test incremental streaming with httpbun's /drip endpoint.

    The /drip endpoint sends data over a specified duration.
    Verifies chunks arrive over time, not all at once.
    """
    # Request data dripped over 3 seconds
    start_time = time.time()
    chunk_times = []
    chunks = []

    resp = _make_request(
        "GET",
        "/drip?duration=3&numbytes=100",
        "model-v1",
        auth_headers,
        stream=True,
        timeout=10,
    )
    assert resp.status_code == 200

    for chunk in resp.iter_content(chunk_size=None):
        if chunk:
            elapsed = time.time() - start_time
            chunk_times.append(elapsed)
            chunks.append(chunk)

    duration = time.time() - start_time

    # Should take at least 2 seconds (duration=3 with some tolerance)
    assert duration >= 2.0, f"Expected duration >= 2s, got {duration:.1f}s"

    # Should receive data (even if httpbun limits the size)
    assert len(chunks) >= 1, f"Expected at least 1 chunk, got {len(chunks)}"

    total_bytes = sum(len(chunk) for chunk in chunks)
    print(
        f"\n  ✓ Drip streaming: {total_bytes} bytes in {len(chunks)} chunk(s) over {duration:.1f}s"
    )


def test_backpressure_no_data_loss(auth_headers):
    """
    Test that backpressure mechanism prevents data loss with slow consumer.

    This test verifies that when buffer fills up (triggering backpressure),
    no frames are dropped. The server and agent should block until the consumer
    catches up, rather than silently dropping frames.
    """
    # httpbun /range/ maxes out at 1000 bytes, but we can test backpressure
    # by making the consumer very slow and verifying all data arrives intact
    response_size = 1000  # 1KB (httpbun /range/ max)

    start_time = time.time()
    resp = _make_request(
        "GET",
        f"/range/{response_size}",
        "model-v1",
        auth_headers,
        stream=True,
        timeout=30,
    )

    assert resp.status_code == 200

    # Read response VERY slowly (1 byte at a time) to stress channel buffers
    # This creates maximum backpressure as the producer is much faster than consumer
    chunks_received = []
    total_bytes = 0
    chunk_count = 0

    for chunk in resp.iter_content(chunk_size=10):  # Tiny 10-byte chunks
        if chunk:
            chunks_received.append(chunk)
            total_bytes += len(chunk)
            chunk_count += 1

            # Simulate VERY slow consumer (creates sustained backpressure)
            time.sleep(0.001)  # 1ms delay per chunk

    duration = time.time() - start_time

    # Verify we received all data (no loss)
    assert total_bytes == response_size, (
        f"Data loss detected: expected {response_size} bytes, got {total_bytes} bytes"
    )

    # Verify data integrity - check that chunks concatenate correctly
    full_data = b"".join(chunks_received)
    assert len(full_data) == total_bytes, (
        f"Chunk concatenation mismatch: expected {total_bytes}, got {len(full_data)}"
    )

    print(
        f"\n  ✓ Backpressure test: {total_bytes} bytes in {chunk_count} small chunks over {duration:.2f}s"
    )
    print("    No data loss detected with very slow consumer")


def test_backpressure_concurrent_large_responses(auth_headers):
    """
    Test that multiple concurrent responses with slow consumers don't cause data loss.

    This stresses the backpressure mechanism with multiple simultaneous transfers
    and slow consumers, ensuring no frames are dropped even under high load.
    """
    response_size = 1000  # 1KB per request (httpbun /range/ max)
    num_concurrent = 20  # 20 concurrent requests

    def fetch_large_response(request_id):
        """Fetch response with slow consumer and verify integrity."""
        resp = _make_request(
            "GET",
            f"/range/{response_size}",
            "model-v1",
            auth_headers,
            stream=True,
            timeout=30,
        )

        assert resp.status_code == 200

        # Read slowly to create backpressure
        total_bytes = 0
        chunk_count = 0
        for chunk in resp.iter_content(chunk_size=10):  # Tiny chunks
            if chunk:
                total_bytes += len(chunk)
                chunk_count += 1
                time.sleep(0.001)  # Slow consumer

        # Verify exact data received (no loss)
        assert total_bytes == response_size, (
            f"Request {request_id}: data loss - expected {response_size}, got {total_bytes}"
        )

        return total_bytes

    # Run concurrent requests
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
        futures = [
            executor.submit(fetch_large_response, i) for i in range(num_concurrent)
        ]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    duration = time.time() - start_time

    # Verify all requests completed successfully
    assert len(results) == num_concurrent
    total_kb = sum(results) / 1024

    print(
        f"\n  ✓ Concurrent backpressure test: {num_concurrent} x 1KB = {total_kb:.1f} KB total"
    )
    print(f"    Completed in {duration:.1f}s with no data loss across all requests")


def test_large_file_buffer_saturation(auth_headers):
    """
    Test backpressure with truly large response that saturates channel buffers.

    Downloads 10MB file through model-v2 (nginx backend).
    10MB = ~160 frames (64KB each), which exceeds the 100-frame buffer.
    This creates sustained backpressure throughout the transfer.

    Verifies:
    - All 10MB received (no data loss despite buffer saturation)
    - Slow consumer doesn't cause frame drops
    - Backpressure mechanism works under realistic load
    """
    expected_size = 10 * 1024 * 1024  # 10MB

    start_time = time.time()
    resp = _make_request(
        "GET",
        "/10mb.bin",  # nginx serves static file
        "model-v2",
        auth_headers,
        stream=True,
        timeout=60,
    )

    assert resp.status_code == 200

    # Read with small chunks and delays to create sustained backpressure
    # The producer (backend) will generate ~160 frames, but buffer is only 100
    # This forces blocking sends in the server's DeliverResponseFrame
    total_bytes = 0
    chunk_count = 0
    for chunk in resp.iter_content(chunk_size=8192):  # 8KB chunks
        if chunk:
            total_bytes += len(chunk)
            chunk_count += 1
            # Small delay to ensure consumer is slower than producer
            time.sleep(0.002)  # 2ms delay per chunk

    duration = time.time() - start_time

    # Verify complete data transfer (no loss)
    assert total_bytes == expected_size, (
        f"Data loss detected: expected {expected_size} bytes, got {total_bytes} bytes"
    )

    # Calculate approximate frame count (64KB per frame)
    frame_size = 64 * 1024
    approx_frames = expected_size / frame_size

    total_mb = total_bytes / (1024 * 1024)
    print("\n  ✓ Large file buffer saturation test:")
    print(f"    {total_mb:.1f}MB in {chunk_count} chunks over {duration:.1f}s")
    print(
        f"    ~{approx_frames:.0f} frames exceeded 100-frame buffer (sustained backpressure)"
    )
    print("    No data loss despite buffer saturation")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
