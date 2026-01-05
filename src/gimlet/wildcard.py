"""Service wildcard matching for JWT authorization."""

import fnmatch


def matches_any(service: str, patterns: list[str]) -> bool:
    """Check if service matches any of the wildcard patterns."""
    return any(fnmatch.fnmatch(service, pattern) for pattern in patterns)
