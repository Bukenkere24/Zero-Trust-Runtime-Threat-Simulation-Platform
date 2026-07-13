"""Hardcoded allowlist — every outbound request must pass this check."""

from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "target-app",
    "0.0.0.0",
})

ALLOWED_HOST_SUFFIXES = (".local",)


class SafetyViolationError(Exception):
    """Raised when a request target is not on the allowlist."""


def validate_target_url(url: str) -> str:
    """Validate URL against allowlist. Returns normalized host or raises."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SafetyViolationError(f"Blocked scheme: {parsed.scheme!r}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise SafetyViolationError("Missing hostname in URL")

    if host in ALLOWED_HOSTS:
        return host

    if any(host.endswith(suffix) for suffix in ALLOWED_HOST_SUFFIXES):
        return host

    raise SafetyViolationError(
        f"Target host {host!r} is not on the allowlist. "
        f"Only localhost and internal Docker network targets are permitted."
    )


def get_default_target_url() -> str:
    import os
    return os.environ.get("TARGET_URL", "http://target-app:5000")
